#!/usr/bin/env python3
"""
traffic_sniffer.py - асинхронный захват трафика и отправка в ML-сервисы Orchid.
Работает в связке с ML Isolation Forest и Random Forest.
Использует asyncio, aiohttp, aiosqlite + синхронный pyshark в отдельном потоке.
"""
import asyncio
import aiohttp
import aiosqlite
import pyshark
import netifaces
import os
import re
import math
import json
import logging
import signal
import threading
import queue
from datetime import datetime
from collections import defaultdict
from typing import Dict, Any, Optional

# Конфигурация
DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'attacks.db')
ML_ISOLATION_URL = "http://localhost:8001/predict"
ML_RANDOM_URL = "http://localhost:8002/predict"
INTERFACE = os.getenv('INTERFACE', 'any')
CAPTURE_FILTER = "tcp port 80 or tcp port 443"  # только HTTP/HTTPS
REQUEST_TIMEOUT = 2  # таймаут для запросов к ML

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('traffic_sniffer')

# Очередь для передачи пакетов из потока захвата в асинхронный обработчик
packet_queue = queue.Queue(maxsize=1000)

# Флаг остановки
stop_flag = threading.Event()

# ---------- Инициализация БД ----------
async def init_db(db_path):
    """Создаёт таблицу attacks, если её нет."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    async with aiosqlite.connect(db_path) as db:
        await db.execute('''
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                payload TEXT,
                isolation_result TEXT,
                random_result TEXT,
                detected BOOLEAN DEFAULT 1,
                ml_service TEXT DEFAULT 'both',
                http_method TEXT,
                headers TEXT,
                full_url TEXT,
                user_agent TEXT,
                response_status INTEGER,
                request_body TEXT
            )
        ''')
        await db.commit()
    logger.info(f"Database initialized at {db_path}")

# ---------- Извлечение признаков (аналогично monitor_juice_improved.py) ----------
def extract_features_from_http(packet):
    """
    Извлекает признаки из HTTP-пакета.
    Возвращает словарь фич и метаданные.
    """
    try:
        # Базовые поля
        method = packet.http.request_method if hasattr(packet.http, 'request_method') else 'GET'
        uri = packet.http.request_uri if hasattr(packet.http, 'request_uri') else '/'
        host = packet.http.host if hasattr(packet.http, 'host') else 'unknown'
        user_agent = packet.http.user_agent if hasattr(packet.http, 'user_agent') else ''
        content_length = int(packet.http.content_length) if hasattr(packet.http, 'content_length') else 0
        status_code = int(packet.http.response_code) if hasattr(packet.http, 'response_code') else 200

        # Полный URL
        full_url = f"http://{host}{uri}"

        # Payload (тело запроса) – доступно только при наличии data
        payload = ''
        if hasattr(packet.http, 'file_data'):
            payload = packet.http.file_data
        elif hasattr(packet.http, 'request_body'):
            payload = packet.http.request_body

        endpoint = uri
        request_length = len(full_url) + len(payload)
        param_count = payload.count('&') + (1 if '?' in uri else 0) + (1 if method == 'POST' else 0)

        special_chars = sum(1 for c in payload if c in "'\"<>();%&|`$")
        special_char_ratio = special_chars / (len(payload) + 1)

        url_depth = uri.count('/')
        user_agent_length = len(user_agent)
        request_time_seconds = 0.0  # pyshark не даёт тайминги легко, можно пропустить

        # Признаки для детектирования атак
        sql_keywords = ['select', 'union', 'insert', 'delete', 'update', 'drop', 'alter',
                        'where', 'from', 'order by', 'group by', 'having', 'join', 'on',
                        'and', 'or', 'not', 'null', '--', '#', '/*']
        sql_keywords_count = 0
        payload_lower = payload.lower()
        for kw in sql_keywords:
            sql_keywords_count += payload_lower.count(kw)

        html_tags = re.findall(r'<[^>]+>', payload)
        html_tag_count = len(html_tags)

        path_traversal_count = payload.count('../') + payload.count('..\\') + payload.count('..%2f')

        # Энтропия
        if payload:
            prob = [float(payload.count(c)) / len(payload) for c in set(payload)]
            entropy = -sum([p * math.log2(p) for p in prob])
        else:
            entropy = 0

        tokens = re.split(r'[^a-zA-Z0-9]', payload)
        max_token_length = max((len(t) for t in tokens), default=0)

        has_equals = 1 if '=' in payload else 0
        has_quotes = 1 if ("'" in payload or '"' in payload) else 0

        digit_count = sum(c.isdigit() for c in payload)
        letter_count = sum(c.isalpha() for c in payload)
        letter_digit_ratio = letter_count / (digit_count + 1)

        features = {
            'request_length': request_length,
            'param_count': param_count,
            'special_char_ratio': round(special_char_ratio, 4),
            'url_depth': url_depth,
            'user_agent_length': user_agent_length,
            'content_length': content_length,
            'request_time_seconds': round(request_time_seconds, 2),
            'status_code': status_code,
            'sql_keywords_count': sql_keywords_count,
            'html_tag_count': html_tag_count,
            'path_traversal_count': path_traversal_count,
            'entropy': round(entropy, 4),
            'max_token_length': max_token_length,
            'has_equals': has_equals,
            'has_quotes': has_quotes,
            'digit_count': digit_count,
            'letter_count': letter_count,
            'letter_digit_ratio': round(letter_digit_ratio, 4)
        }

        metadata = {
            'source_ip': packet.ip.src if hasattr(packet, 'ip') else '0.0.0.0',
            'timestamp': datetime.now().isoformat(),
            'full_url': full_url,
            'endpoint': endpoint,
            'payload': payload[:500],   # ограничим длину
            'method': method,
            'user_agent': user_agent,
            'headers': {},  # можно расширить
        }
        return features, metadata
    except Exception as e:
        logger.error(f"Error extracting HTTP features: {e}")
        return None, None


def extract_features_from_tls(packet):
    """
    Извлекает признаки из TLS-рукопожатия (для HTTPS без расшифровки).
    Возвращает словарь фич (метаданные).
    """
    try:
        sni = packet.tls.handshake_extensions_server_name if hasattr(packet.tls, 'handshake_extensions_server_name') else ''
        # Размеры пакетов можно получить из IP-слоя
        ip_len = int(packet.ip.len) if hasattr(packet, 'ip') else 0
        tcp_len = int(packet.tcp.len) if hasattr(packet, 'tcp') else 0

        features = {
            'request_length': ip_len + tcp_len,
            'param_count': 0,
            'special_char_ratio': 0.0,
            'url_depth': 0,
            'user_agent_length': 0,
            'content_length': 0,
            'request_time_seconds': 0.0,
            'status_code': 0,
            'sql_keywords_count': 0,
            'html_tag_count': 0,
            'path_traversal_count': 0,
            'entropy': 0.0,
            'max_token_length': 0,
            'has_equals': 0,
            'has_quotes': 0,
            'digit_count': 0,
            'letter_count': 0,
            'letter_digit_ratio': 0.0,
            # дополнительные метаданные TLS
            'tls_sni_length': len(sni),
            'tls_cipher': hash(packet.tls.handshake_ciphersuite) % 1000 if hasattr(packet.tls, 'handshake_ciphersuite') else 0,
            'tls_version': hash(packet.tls.handshake_version) % 10 if hasattr(packet.tls, 'handshake_version') else 0,
        }
        metadata = {
            'source_ip': packet.ip.src if hasattr(packet, 'ip') else '0.0.0.0',
            'timestamp': datetime.now().isoformat(),
            'tls_sni': sni,
            'payload': '',
        }
        return features, metadata
    except Exception as e:
        logger.error(f"Error extracting TLS features: {e}")
        return None, None


# ---------- Асинхронная отправка в ML и запись в БД ----------
async def send_to_ml(session, features, metadata):
    """Отправляет признаки в оба ML-сервиса асинхронно."""
    payload = {
        "features": features,
        "metadata": metadata
    }
    iso_result = {"error": "No response"}
    rf_result = {"error": "No response"}

    try:
        async with session.post(ML_ISOLATION_URL, json=payload, timeout=REQUEST_TIMEOUT) as resp:
            if resp.status == 200:
                iso_result = await resp.json()
            else:
                iso_result = {"error": f"HTTP {resp.status}"}
    except asyncio.TimeoutError:
        iso_result = {"error": "Timeout"}
    except Exception as e:
        iso_result = {"error": str(e)}

    try:
        async with session.post(ML_RANDOM_URL, json=payload, timeout=REQUEST_TIMEOUT) as resp:
            if resp.status == 200:
                rf_result = await resp.json()
            else:
                rf_result = {"error": f"HTTP {resp.status}"}
    except asyncio.TimeoutError:
        rf_result = {"error": "Timeout"}
    except Exception as e:
        rf_result = {"error": str(e)}

    return iso_result, rf_result


async def log_attack(features, metadata, iso_result, rf_result, db_path):
    """Асинхронно сохраняет результат в SQLite."""
    try:
        # Определяем, обнаружена ли атака
        iso_detected = iso_result.get('is_anomaly', False) if not iso_result.get('error') else False
        rf_detected = rf_result.get('is_attack', False) if not rf_result.get('error') else False
        detected = iso_detected or rf_detected

        # Тип атаки (берём из Random Forest, если есть)
        attack_type = rf_result.get('prediction', 'unknown') if not rf_result.get('error') else 'unknown'
        if attack_type == 'unknown' and iso_result.get('is_anomaly'):
            attack_type = 'unknown_anomaly'

        # Формируем строковые представления результатов
        iso_str = json.dumps(iso_result, ensure_ascii=False)
        rf_str = json.dumps(rf_result, ensure_ascii=False)

        source_ip = metadata.get('source_ip', '0.0.0.0')
        endpoint = metadata.get('endpoint', '')
        payload = metadata.get('payload', '')[:200]  # ограничим длину
        http_method = metadata.get('method', 'GET')
        full_url = metadata.get('full_url', '')
        user_agent = metadata.get('user_agent', '')

        async with aiosqlite.connect(db_path) as db:
            await db.execute('''
                INSERT INTO attacks
                (timestamp, attack_type, source_ip, endpoint, payload,
                 isolation_result, random_result, detected, ml_service,
                 http_method, headers, full_url, user_agent, response_status, request_body)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                attack_type,
                source_ip,
                endpoint,
                payload,
                iso_str,
                rf_str,
                1 if detected else 0,
                'both',
                http_method,
                '{}',  # headers пока оставляем пустыми
                full_url,
                user_agent,
                0,    # response_status пока не заполняем
                payload
            ))
            await db.commit()

        logger.info(f"Logged attack: {attack_type} from {source_ip}")
    except Exception as e:
        logger.error(f"Error logging to DB: {e}")


# ---------- Обработка пакета (вызывается из асинхронной задачи) ----------
async def process_packet(packet_data, session, db_path):
    """
    Обрабатывает данные пакета (фичи и метаданные), отправляет в ML и логирует.
    """
    features, metadata = packet_data
    iso_result, rf_result = await send_to_ml(session, features, metadata)
    await log_attack(features, metadata, iso_result, rf_result, db_path)


# ---------- Поток захвата пакетов ----------
def capture_thread_func(interface, bpf_filter, loop):
    """
    Функция, выполняемая в отдельном потоке.
    Захватывает пакеты, извлекает признаки и кладёт в очередь.
    """
    logger.info(f"Capture thread started on interface {interface}")
    capture = pyshark.LiveCapture(interface=interface, bpf_filter=bpf_filter)

    try:
        for packet in capture.sniff_continuously():
            if stop_flag.is_set():
                break

            # Извлекаем признаки
            features = None
            metadata = None
            if hasattr(packet, 'http') and packet.http:
                features, metadata = extract_features_from_http(packet)
            elif hasattr(packet, 'tls') and packet.tls:
                features, metadata = extract_features_from_tls(packet)

            if features is not None and metadata is not None:
                # Кладём в очередь для асинхронной обработки
                try:
                    packet_queue.put_nowait((features, metadata))
                except queue.Full:
                    logger.warning("Packet queue full, dropping packet")
    except Exception as e:
        logger.error(f"Capture thread error: {e}")
    finally:
        logger.info("Capture thread stopped")


# ---------- Асинхронная задача обработки очереди ----------
async def processor_task(db_path):
    """
    Асинхронная задача, которая читает пакеты из очереди и обрабатывает их.
    """
    async with aiohttp.ClientSession() as session:
        while not stop_flag.is_set():
            try:
                # Неблокирующее получение из очереди
                features, metadata = packet_queue.get_nowait()
                # Запускаем обработку как задачу, не дожидаясь завершения
                asyncio.create_task(process_packet((features, metadata), session, db_path))
            except queue.Empty:
                # Если очередь пуста, немного подождём
                await asyncio.sleep(0.1)


# ---------- Основная функция ----------
async def main():
    # Инициализируем БД
    await init_db(DB_PATH)

    logger.info(f"Starting traffic sniffer on interface {INTERFACE} with filter '{CAPTURE_FILTER}'")

    # Получаем текущий event loop
    loop = asyncio.get_running_loop()

    # Запускаем поток захвата
    capture_thread = threading.Thread(target=capture_thread_func, args=(INTERFACE, CAPTURE_FILTER, loop))
    capture_thread.start()

    # Запускаем обработчик очереди
    processor = asyncio.create_task(processor_task(DB_PATH))

    # Обработка сигналов для graceful shutdown
    stop_event = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(shutdown(stop_event)))

    await stop_event.wait()

    # Остановка
    logger.info("Shutting down...")
    stop_flag.set()
    capture_thread.join(timeout=5)
    processor.cancel()
    try:
        await processor
    except asyncio.CancelledError:
        pass
    logger.info("Shutdown complete")


async def shutdown(stop_event):
    stop_event.set()


if __name__ == "__main__":
    asyncio.run(main())
