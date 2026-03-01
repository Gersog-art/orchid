#!/usr/bin/env python3
"""
Асинхронный генератор трафика для Orchid.
Реально ходит на Juice Shop (http://localhost:3001), получает ответы,
отправляет данные в ML-сервисы и логирует всё в БД.
Использует asyncio, aiohttp, aiosqlite.
"""

import asyncio
import aiohttp
import aiosqlite
import random
import json
import math
import re
import os
import signal
import time
from datetime import datetime

# ---------- Конфигурация ----------
DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'attacks.db')
ML_ISOLATION_URL = "http://localhost:8001/predict"
ML_RANDOM_URL = "http://localhost:8002/predict"
JUICE_SHOP_URL = "http://localhost:3001"
WORKERS = 20
REQUEST_TIMEOUT = 2
REAL_REQUEST_TIMEOUT = 3

# ---------- Извлечение признаков (ПОЛНОЕ) ----------
def extract_features(endpoint, attack_data):
    payload = attack_data.get('payload', '')
    attack_type = attack_data.get('type', 'normal')
    method = attack_data.get('method', 'GET')
    user_agent = attack_data.get('user_agent', 'Mozilla/5.0 (X11; Linux x86_64)')

    # Базовые признаки
    request_length = len(endpoint) + len(payload)
    param_count = payload.count('&') + (1 if '?' in payload else 0) + (1 if method == 'POST' else 0)
    special_chars = sum(1 for c in payload if c in "'\"<>();%&|`$")
    special_char_ratio = special_chars / (len(payload) + 1)
    url_depth = endpoint.count('/')
    user_agent_length = len(user_agent)
    content_length = len(payload) if method == 'POST' else 0
    request_time_seconds = random.uniform(0.1, 2.0)

    # HTTP статус (эмулируем, будет заменён реальным)
    status_code = 200 if attack_type == 'normal' else random.choice([400, 404, 500])

    # ---- Признаки, зависящие от payload ----
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
    letter_digit_ratio = letter_count / (digit_count + 1) if digit_count > 0 else float('inf')

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
        'letter_digit_ratio': round(letter_digit_ratio, 4) if letter_digit_ratio != float('inf') else 0.0
    }

    for k in features:
        features[k] = float(features[k])

    return features


# ---------- Генерация трафика ----------
def generate_simulated_traffic():
    endpoints = [
        "/rest/user/login",
        "/api/Products",
        "/profile",
        "/#/search",
        "/rest/basket",
        "/rest/admin/application-configuration",
        "/ftp",
        "/redirect"
    ]

    attacks = [
        {"type": "sqli", "payload": "' UNION SELECT username, password FROM Users--"},
        {"type": "sqli", "payload": "' OR '1'='1' --"},
        {"type": "xss", "payload": "<img src=x onerror=alert(1)>"},
        {"type": "xss", "payload": "<script>document.location='http://evil.com'</script>"},
        {"type": "lfi", "payload": "../../../../etc/passwd"},
        {"type": "rce", "payload": "; cat /etc/shadow"},
        {"type": "rce", "payload": "| ls -la /"},
        {"type": "xxe", "payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>"},
        {"type": "ssrf", "payload": "http://169.254.169.254/latest/meta-data/"},
        {"type": "cmd_inject", "payload": "& ping -c 10 127.0.0.1 &"},
        {"type": "path_traversal", "payload": "..\\..\\..\\windows\\win.ini"},
    ]

    normal = [
        {"type": "normal", "payload": "product=1"},
        {"type": "normal", "payload": "search=apple"},
        {"type": "normal", "payload": "email=user@test.com"},
        {"type": "normal", "payload": "page=1"},
        {"type": "normal", "payload": "category=juice"},
        {"type": "normal", "payload": "sort=price"},
    ]

    if random.random() < 0.4:
        endpoint = random.choice(endpoints)
        attack = random.choice(attacks)
    else:
        endpoint = random.choice(endpoints)
        attack = random.choice(normal)

    http_method = random.choice(['GET', 'POST'])
    headers = {
        'User-Agent': random.choice([
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
            'curl/7.68.0',
            'python-requests/2.31.0'
        ]),
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded' if http_method == 'POST' else 'text/plain'
    }
    full_url = f"{JUICE_SHOP_URL}{endpoint}"
    if http_method == 'GET' and attack['payload']:
        full_url += '?' + attack['payload']

    attack.update({
        'method': http_method,
        'headers': headers,
        'full_url': full_url,
        'user_agent': headers['User-Agent']
    })

    return endpoint, attack


# ---------- Асинхронный монитор ----------
class AsyncJuiceShopMonitor:
    def __init__(self, workers=WORKERS):
        self.workers = workers
        self.running = True
        self.db_path = DB_PATH
        self._tasks = []
        self._stop_event = asyncio.Event()

    async def send_to_ml(self, session, endpoint, attack_data):
        features = extract_features(endpoint, attack_data)
        payload = {"features": features, "metadata": attack_data}
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

    async def send_real_request(self, session, endpoint, attack_data):
        url = attack_data.get('full_url', f"{JUICE_SHOP_URL}{endpoint}")
        method = attack_data.get('method', 'GET')
        headers = attack_data.get('headers', {})
        payload = attack_data.get('payload', '')

        start = time.time()
        try:
            if method.upper() == 'GET':
                async with session.get(url, headers=headers, timeout=REAL_REQUEST_TIMEOUT) as resp:
                    status = resp.status
                    body = await resp.text()
            else:
                data = payload if 'application/x-www-form-urlencoded' in headers.get('Content-Type', '') else None
                json_data = payload if 'application/json' in headers.get('Content-Type', '') else None
                async with session.post(url, headers=headers, data=data, json=json_data, timeout=REAL_REQUEST_TIMEOUT) as resp:
                    status = resp.status
                    body = await resp.text()
            elapsed = time.time() - start
            return status, body[:500], elapsed
        except Exception as e:
            return 0, str(e), time.time() - start

    async def log_attack(self, endpoint, attack_data, iso_result, rf_result, real_response):
        try:
            iso_detected = iso_result.get('is_anomaly', False) if not iso_result.get('error') else False
            rf_detected = rf_result.get('is_attack', False) if not rf_result.get('error') else False
            detected = iso_detected or rf_detected

            attack_type = rf_result.get('prediction', 'unknown') if not rf_result.get('error') else 'unknown'
            if attack_type == 'unknown' and iso_result.get('is_anomaly'):
                attack_type = 'unknown_anomaly'

            iso_str = json.dumps(iso_result, ensure_ascii=False)
            rf_str = json.dumps(rf_result, ensure_ascii=False)

            source_ip = f"192.168.1.{random.randint(2, 254)}"
            http_method = attack_data.get('method', 'GET')
            headers = attack_data.get('headers', {})
            full_url = attack_data.get('full_url', f"{JUICE_SHOP_URL}{endpoint}")
            user_agent = attack_data.get('user_agent', headers.get('User-Agent', ''))
            payload = attack_data.get('payload', '')[:200]

            real_status, real_body, real_time = real_response

            async with aiosqlite.connect(self.db_path) as db:
                await db.execute('''
                    INSERT INTO attacks
                    (timestamp, attack_type, source_ip, endpoint, payload,
                     isolation_result, random_result, detected, ml_service,
                     http_method, headers, full_url, user_agent, response_status, request_body,
                     real_response_status, real_response_body, real_response_time)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    json.dumps(headers),
                    full_url,
                    user_agent,
                    0,
                    payload,
                    real_status,
                    real_body[:200],
                    round(real_time, 3)
                ))
                await db.commit()

            print(f"[{datetime.now().strftime('%H:%M:%S')}] {attack_type} from {source_ip} (conf: {rf_result.get('confidence', 0):.2f}, real status: {real_status})")

        except Exception as e:
            print(f"Log error: {e}")

    async def worker(self, worker_id):
        print(f"Worker {worker_id} started")
        async with aiohttp.ClientSession() as session:
            while not self._stop_event.is_set():
                endpoint, attack_data = generate_simulated_traffic()
                real_response = await self.send_real_request(session, endpoint, attack_data)
                iso_result, rf_result = await self.send_to_ml(session, endpoint, attack_data)
                asyncio.create_task(self.log_attack(endpoint, attack_data, iso_result, rf_result, real_response))
                await asyncio.sleep(random.uniform(0.01, 0.05))

    async def run(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        for i in range(self.workers):
            task = asyncio.create_task(self.worker(i))
            self._tasks.append(task)

        await self._stop_event.wait()

        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        print("All workers stopped")

    def stop(self):
        self._stop_event.set()


async def main():
    monitor = AsyncJuiceShopMonitor(workers=10)

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(shutdown(monitor)))

    print("Async monitor with real Juice Shop requests started. Press Ctrl+C to stop.")
    await monitor.run()


async def shutdown(monitor):
    print("\nShutting down...")
    monitor.stop()
    await asyncio.sleep(2)


if __name__ == "__main__":
    asyncio.run(main())
