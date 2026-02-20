#!/usr/bin/env python3
import requests
import json
import time
import random
import sqlite3
import threading
import os
import socket
import math
import re
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

# ---------- Функция извлечения признаков (18 признаков) ----------
def extract_features(endpoint, attack_data):
    """
    Преобразует данные запроса в 18 числовых признаков для ML-моделей.
    """
    payload = attack_data.get('payload', '')
    attack_type = attack_data.get('type', 'normal')
    method = attack_data.get('method', 'GET')

    # ---- Базовые признаки ----
    request_length = len(endpoint) + len(payload)
    param_count = payload.count('&') + (1 if '?' in payload else 0) + (1 if method == 'POST' else 0)
    special_chars = sum(1 for c in payload if c in "'\"<>();%&|`$")
    special_char_ratio = special_chars / (len(payload) + 1)
    url_depth = endpoint.count('/')
    user_agent_length = len(attack_data.get('user_agent', 'Mozilla/5.0 (X11; Linux x86_64)'))
    content_length = len(payload) if method == 'POST' else 0
    request_time_seconds = random.uniform(0.1, 2.0)

    # HTTP статус
    if attack_type == 'normal':
        status_code = 200
    elif attack_type in ('sqli', 'xss', 'lfi', 'rce', 'xxe'):
        status_code = random.choice([400, 404, 500])
    else:
        status_code = 200

    # ---- Признаки для детектирования атак ----
    sql_keywords = ['select', 'union', 'insert', 'delete', 'update', 'drop', 'alter', 'create',
                    'where', 'from', 'order by', 'group by', 'having', 'join', 'on', 'and', 'or',
                    'not', 'null', '--', '#', '/*']
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

    # Принудительно приводим все к float (для безопасности)
    for k in features:
        features[k] = float(features[k])

    return features


# ---------- HTTP сервер для стриминга ----------
class AttackStreamHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/stream':
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'keep-alive')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

            try:
                recent = self.server.monitor.get_recent_attacks(5)
                for attack in recent:
                    self.wfile.write(f"data: {json.dumps(attack)}\n\n".encode())
                    self.wfile.flush()
            except Exception as e:
                print(f"Stream initial data error: {e}")

            if hasattr(self.server, 'connections'):
                self.server.connections.append(self)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


def find_free_port(start_port=8082, max_attempts=10):
    for port in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('0.0.0.0', port))
                return port
            except OSError:
                continue
    return None


# ---------- Основной класс монитора ----------
class JuiceShopMonitor:
    def __init__(self):
        self.juice_shop_url = "http://localhost:3001"
        self.ml_isolation_url = "http://localhost:8001/predict"
        self.ml_random_url = "http://localhost:8002/predict"
        self.db_file = "data/attacks.db"
        self.running = True
        self.attack_log = []

        os.makedirs('data', exist_ok=True)
        self.init_db()
        self.start_stream_server()

    def init_db(self):
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('''
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
            conn.commit()
            conn.close()
            print(f"📁 База данных: {self.db_file}")
        except Exception as e:
            print(f"❌ Ошибка инициализации БД: {e}")

    def start_stream_server(self):
        port = find_free_port(8082)
        if port is None:
            print("⚠️  Не удалось найти свободный порт для стриминга. Продолжаем без стрима.")
            self.stream_server = None
            return

        try:
            server = HTTPServer(('0.0.0.0', port), AttackStreamHandler)
            server.monitor = self
            server.connections = []

            def run_server():
                print(f"📡 Attack stream server started on http://localhost:{port}/stream")
                server.serve_forever()

            thread = threading.Thread(target=run_server, daemon=True)
            thread.start()
            self.stream_server = server
            self.stream_port = port
        except Exception as e:
            print(f"⚠️  Не удалось запустить stream server: {e}. Продолжаем без стрима.")
            self.stream_server = None

    def broadcast_attack(self, attack_data):
        if not self.stream_server or not hasattr(self.stream_server, 'connections'):
            return
        for conn in self.stream_server.connections[:]:
            try:
                conn.wfile.write(f"data: {json.dumps(attack_data)}\n\n".encode())
                conn.wfile.flush()
            except:
                if conn in self.stream_server.connections:
                    self.stream_server.connections.remove(conn)

    def get_recent_attacks(self, limit=10):
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT timestamp, attack_type, source_ip, endpoint,
                       isolation_result, random_result, detected
                FROM attacks
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
            rows = cursor.fetchall()
            conn.close()

            attacks = []
            for row in rows:
                attacks.append({
                    'time': row[0],
                    'type': row[1],
                    'ip': row[2],
                    'endpoint': row[3],
                    'iso': row[4],
                    'rf': row[5],
                    'detected': bool(row[6])
                })
            return attacks
        except Exception as e:
            print(f"Ошибка чтения БД: {e}")
            return []

    def log_attack(self, attack_data, endpoint, iso_result, rf_result):
        try:
            iso_detected = iso_result.get('is_anomaly', False) if not iso_result.get('error') else False
            rf_detected = rf_result.get('is_attack', False) if not rf_result.get('error') else False
            detected = iso_detected or rf_detected

            if 'error' in iso_result:
                iso_pred = f"ERR: {iso_result['error']}"
            else:
                iso_pred = iso_result.get('prediction', iso_result.get('message', 'N/A'))

            if 'error' in rf_result:
                rf_pred = f"ERR: {rf_result['error']}"
            else:
                rf_pred = rf_result.get('prediction', rf_result.get('message', 'N/A'))

            source_ip = f"192.168.1.{random.randint(2, 254)}"

            # Дополнительные поля из attack_data
            http_method = attack_data.get('method', 'GET')
            headers = attack_data.get('headers', {})
            full_url = attack_data.get('full_url', f"http://localhost:3001{endpoint}")
            user_agent = attack_data.get('user_agent', headers.get('User-Agent', ''))
            response_status = None  # можно будет заполнять позже
            request_body = attack_data.get('payload', '')

            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'attack_type': attack_data['type'],
                'source_ip': source_ip,
                'endpoint': endpoint,
                'payload': attack_data['payload'][:100],
                'isolation_result': str(iso_pred),
                'random_result': str(rf_pred),
                'detected': 1 if detected else 0,
                'ml_service': 'both',
                'http_method': http_method,
                'headers': json.dumps(headers),
                'full_url': full_url,
                'user_agent': user_agent,
                'response_status': response_status,
                'request_body': request_body
            }

            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO attacks
                (timestamp, attack_type, source_ip, endpoint, payload,
                 isolation_result, random_result, detected, ml_service,
                 http_method, headers, full_url, user_agent, response_status, request_body)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                log_entry['timestamp'],
                log_entry['attack_type'],
                log_entry['source_ip'],
                log_entry['endpoint'],
                log_entry['payload'],
                log_entry['isolation_result'],
                log_entry['random_result'],
                log_entry['detected'],
                log_entry['ml_service'],
                log_entry['http_method'],
                log_entry['headers'],
                log_entry['full_url'],
                log_entry['user_agent'],
                log_entry['response_status'],
                log_entry['request_body']
            ))
            conn.commit()
            conn.close()

            self.attack_log.append(log_entry)

            self.broadcast_attack({
                'type': 'attack',
                'data': {
                    'time': datetime.now().strftime('%H:%M:%S'),
                    'ip': source_ip,
                    'attack_type': attack_data['type'],
                    'endpoint': endpoint,
                    'detected': detected,
                    'iso_result': str(iso_pred),
                    'rf_result': str(rf_pred)
                }
            })

            if detected:
                print(f"\033[91m[!] Атака обнаружена: {attack_data['type']}\033[0m")
            else:
                print(f"\033[93m[~] Атака не обнаружена: {attack_data['type']}\033[0m")

            print(f"    Endpoint: {endpoint}")
            print(f"    Payload: {attack_data['payload'][:50]}...")
            print(f"    Isolation Forest: {log_entry['isolation_result']}")
            print(f"    Random Forest: {log_entry['random_result']}")
            print(f"    Source IP: {source_ip}")
            print("-" * 50)

            return log_entry

        except Exception as e:
            print(f"\033[90m[DEBUG] Ошибка логирования: {e}\033[0m")
            return None

    def generate_simulated_traffic(self):
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
            {"type": "xxe", "payload": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/read=convert.base64-encode/resource=/etc/passwd\">]><foo>&xxe;</foo>"},
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

        # Дополнительная информация о запросе
        http_method = random.choice(['GET', 'POST'])
        headers = {
            'User-Agent': random.choice([
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
                'curl/7.68.0',
                'python-requests/2.31.0'
            ]),
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded' if http_method == 'POST' else 'text/plain'
        }
        full_url = f"http://localhost:3001{endpoint}"
        if http_method == 'GET' and attack['payload']:
            full_url += '?' + attack['payload']

        attack.update({
            'method': http_method,
            'headers': headers,
            'full_url': full_url,
            'user_agent': headers['User-Agent']
        })

        return endpoint, attack

    def send_to_ml(self, endpoint, attack_data):
        features = extract_features(endpoint, attack_data)

        ml_payload = {
            "features": features,
            "metadata": {
                "source_ip": f"192.168.1.{random.randint(1, 254)}",
                "timestamp": datetime.now().isoformat(),
                "attack_type": attack_data["type"],
                "payload": attack_data["payload"],
                "endpoint": endpoint
            }
        }

        iso_result = {"error": "Service unavailable"}
        rf_result = {"error": "Service unavailable"}

        try:
            resp = requests.post(self.ml_isolation_url, json=ml_payload, timeout=2)
            if resp.status_code == 200:
                iso_result = resp.json()
            else:
                iso_result = {"error": f"HTTP {resp.status_code}"}
        except Exception as e:
            iso_result = {"error": str(e)}

        try:
            resp = requests.post(self.ml_random_url, json=ml_payload, timeout=2)
            if resp.status_code == 200:
                rf_result = resp.json()
            else:
                rf_result = {"error": f"HTTP {resp.status_code}"}
        except Exception as e:
            rf_result = {"error": str(e)}

        self.log_attack(attack_data, endpoint, iso_result, rf_result)

    def print_stats(self, request_count, attack_count):
        try:
            db_attacks = len(self.get_recent_attacks(1000))
        except:
            db_attacks = 0

        print("\n" + "=" * 60)
        print("\033[94m" + " " * 20 + "ORCHID SECURITY MONITOR" + " " * 20 + "\033[0m")
        print("=" * 60)
        print(f"📊 Статистика:")
        print(f"   Всего запросов:    \033[96m{request_count}\033[0m")
        print(f"   Обнаружено атак:   \033[91m{attack_count}\033[0m")
        print(f"   В базе данных:     \033[93m{db_attacks}\033[0m записей")
        print(f"   Juice Shop:        \033[92mhttp://localhost:3001\033[0m")
        print(f"   Админ панель:      \033[92mhttp://localhost:3000\033[0m")
        if hasattr(self, 'stream_port'):
            print(f"   Attack Stream:     \033[92mhttp://localhost:{self.stream_port}/stream\033[0m")
        print("=" * 60)

    def run(self):
        print("\033[94m" + "=" * 60 + "\033[0m")
        print("\033[94m" + " " * 15 + "ORCHID SECURITY SYSTEM MONITOR" + " " * 15 + "\033[0m")
        print("\033[94m" + "=" * 60 + "\033[0m")
        print("\033[93mЗапуск мониторинга Juice Shop...\033[0m")
        print("\033[93mНажмите Ctrl+C для остановки\033[0m\n")

        try:
            r = requests.get("http://localhost:8001/health", timeout=2)
            print(f"Isolation Forest: {'✓' if r.status_code == 200 else '✗'}")
        except:
            print("Isolation Forest: ✗ (недоступен)")

        try:
            r = requests.get("http://localhost:8002/health", timeout=2)
            print(f"Random Forest:    {'✓' if r.status_code == 200 else '✗'}")
        except:
            print("Random Forest:    ✗ (недоступен)")

        print()

        request_count = 0
        attack_count = 0

        try:
            while self.running:
                request_count += 1
                endpoint, attack_data = self.generate_simulated_traffic()

                if attack_data["type"] != "normal":
                    attack_count += 1

                self.send_to_ml(endpoint, attack_data)

                if request_count % 5 == 0:
                    self.print_stats(request_count, attack_count)

                time.sleep(random.uniform(0.5, 2.0))

        except KeyboardInterrupt:
            print("\n\033[93mОстановка мониторинга...\033[0m")
        finally:
            self.running = False
            self.print_stats(request_count, attack_count)
            print(f"\n✅ Мониторинг завершён. Данные сохранены в {self.db_file}")


if __name__ == "__main__":
    monitor = JuiceShopMonitor()
    monitor.run()
