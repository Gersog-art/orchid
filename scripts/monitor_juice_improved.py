#!/usr/bin/env python3
import requests
import json
import time
import random
from datetime import datetime
import sqlite3
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

class AttackStreamHandler(BaseHTTPRequestHandler):
    """HTTP сервер для стриминга атак в админку"""

    def do_GET(self):
        if self.path == '/stream':
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'keep-alive')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

            # Отправляем последние атаки при подключении
            try:
                recent_attacks = self.server.monitor.get_recent_attacks(5)
                for attack in recent_attacks:
                    self.wfile.write(f"data: {json.dumps(attack)}\n\n".encode())
                    self.wfile.flush()
            except Exception as e:
                print(f"Error sending initial attacks: {e}")

            # Регистрируем соединение
            if hasattr(self.server, 'connections'):
                self.server.connections.append(self)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Отключаем логирование

class JuiceShopMonitor:
    def __init__(self):
        self.juice_shop_url = "http://localhost:3001"
        self.ml_isolation_url = "http://localhost:8001/predict"
        self.ml_random_url = "http://localhost:8002/predict"
        self.admin_stream_url = "http://localhost:8082/stream"
        self.running = True
        self.attack_log = []
        self.db_file = "data/attacks.db"

        # Инициализируем БД с правильной структурой
        self.init_db()

        # Запускаем сервер для стриминга
        self.start_stream_server()

    def start_stream_server(self):
        """Запускаем HTTP сервер для стриминга атак"""
        try:
            server = HTTPServer(('0.0.0.0', 8082), AttackStreamHandler)
            server.monitor = self
            server.connections = []

            def run_server():
                print(f"📡 Attack stream server started on http://localhost:8082/stream")
                server.serve_forever()

            thread = threading.Thread(target=run_server, daemon=True)
            thread.start()
            self.stream_server = server
        except Exception as e:
            print(f"❌ Failed to start stream server: {e}")
            self.stream_server = None

    def broadcast_attack(self, attack_data):
        """Отправляем атаку всем подключенным клиентам"""
        if not hasattr(self, 'stream_server') or not self.stream_server:
            return

        for connection in self.stream_server.connections:
            try:
                connection.wfile.write(f"data: {json.dumps(attack_data)}\n\n".encode())
                connection.wfile.flush()
            except Exception as e:
                # Удаляем мертвое соединение
                if connection in self.stream_server.connections:
                    self.stream_server.connections.remove(connection)

    def init_db(self):
        """Инициализация SQLite базы данных для логов с проверкой структуры"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()

            # Проверяем существование таблицы
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='attacks'")
            table_exists = cursor.fetchone()

            if table_exists:
                # Проверяем структуру таблицы
                cursor.execute("PRAGMA table_info(attacks)")
                columns = [column[1] for column in cursor.fetchall()]

                # Если нет колонки ml_service, пересоздаем таблицу
                if 'ml_service' not in columns:
                    print("🔄 Обнаружена старая структура БД, пересоздаем таблицу...")
                    cursor.execute("DROP TABLE attacks")
                    table_exists = False

            if not table_exists:
                cursor.execute('''
                    CREATE TABLE attacks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        attack_type TEXT NOT NULL,
                        source_ip TEXT NOT NULL,
                        endpoint TEXT NOT NULL,
                        payload TEXT,
                        isolation_result TEXT,
                        random_result TEXT,
                        detected BOOLEAN DEFAULT 1,
                        ml_service TEXT DEFAULT 'both'
                    )
                ''')
                print(f"✅ База данных создана: {self.db_file}")
            else:
                print(f"📁 База данных уже существует: {self.db_file}")

            conn.commit()
            conn.close()

        except Exception as e:
            print(f"❌ Ошибка инициализации БД: {e}")
            # Создаем заново при ошибке
            try:
                conn = sqlite3.connect(self.db_file)
                cursor = conn.cursor()
                cursor.execute('DROP TABLE IF EXISTS attacks')
                cursor.execute('''
                    CREATE TABLE attacks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        attack_type TEXT NOT NULL,
                        source_ip TEXT NOT NULL,
                        endpoint TEXT NOT NULL,
                        payload TEXT,
                        isolation_result TEXT,
                        random_result TEXT,
                        detected BOOLEAN DEFAULT 1,
                        ml_service TEXT DEFAULT 'both'
                    )
                ''')
                conn.commit()
                conn.close()
                print(f"✅ База данных пересоздана: {self.db_file}")
            except Exception as e2:
                print(f"❌ Критическая ошибка БД: {e2}")

    def get_recent_attacks(self, limit=10):
        """Получаем последние атаки из БД"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT timestamp, attack_type, source_ip, endpoint, payload,
                       isolation_result, random_result, detected, ml_service
                FROM attacks
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))

            attacks = []
            for row in cursor.fetchall():
                attacks.append({
                    'timestamp': row[0],
                    'attack_type': row[1],
                    'source_ip': row[2],
                    'endpoint': row[3],
                    'payload': row[4],
                    'iso_result': row[5],
                    'rf_result': row[6],
                    'detected': bool(row[7]),
                    'ml_service': row[8]
                })

            conn.close()
            return attacks

        except Exception as e:
            print(f"❌ Ошибка чтения БД: {e}")
            return []

    def log_attack(self, attack_data, endpoint, iso_result, rf_result):
        """Записываем атаку в БД и транслируем в админку"""
        try:
            attack_log_entry = {
                'timestamp': datetime.now().isoformat(),
                'attack_type': attack_data['type'],
                'source_ip': f"192.168.1.{random.randint(1, 255)}",
                'endpoint': endpoint,
                'payload': attack_data['payload'][:100] if attack_data['payload'] else '',
                'iso_result': str(iso_result.get('message', iso_result.get('prediction', 'N/A'))),
                'rf_result': str(rf_result.get('prediction', rf_result.get('message', 'N/A'))),
                'detected': bool(iso_result.get('is_anomaly', False) or rf_result.get('is_attack', False)),
                'ml_service': 'both'
            }

            self.attack_log.append(attack_log_entry)

            # Сохраняем в БД
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO attacks (timestamp, attack_type, source_ip, endpoint, payload,
                                   isolation_result, random_result, detected, ml_service)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                attack_log_entry['timestamp'],
                attack_log_entry['attack_type'],
                attack_log_entry['source_ip'],
                attack_log_entry['endpoint'],
                attack_log_entry['payload'],
                attack_log_entry['iso_result'],
                attack_log_entry['rf_result'],
                1 if attack_log_entry['detected'] else 0,
                attack_log_entry['ml_service']
            ))
            conn.commit()
            conn.close()

            # Транслируем в админку через SSE
            self.broadcast_attack({
                'type': 'attack',
                'data': {
                    'time': datetime.now().strftime('%H:%M:%S'),
                    'ip': attack_log_entry['source_ip'],
                    'attack_type': attack_log_entry['attack_type'],
                    'endpoint': attack_log_entry['endpoint'],
                    'detected': attack_log_entry['detected'],
                    'iso_result': attack_log_entry['iso_result'],
                    'rf_result': attack_log_entry['rf_result']
                }
            })

            # Выводим в консоль цветной лог
            if attack_log_entry['detected']:
                print(f"\033[91m[!] Атака обнаружена: {attack_data['type']}\033[0m")
            else:
                print(f"\033[93m[~] Атака не обнаружена: {attack_data['type']}\033[0m")

            print(f"    Endpoint: {endpoint}")
            print(f"    Payload: {attack_data['payload'][:50] if attack_data['payload'] else 'No payload'}...")
            print(f"    Isolation Forest: {attack_log_entry['iso_result']}")
            print(f"    Random Forest: {attack_log_entry['rf_result']}")
            print(f"    Source IP: {attack_log_entry['source_ip']}")
            print("-" * 50)

            return attack_log_entry

        except Exception as e:
            print(f"\033[90m[DEBUG] Ошибка логирования: {e}\033[0m")
            return None

    def generate_simulated_traffic(self):
        """Генерируем симулированный трафик атак"""
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
            {"type": "xxe", "payload": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"},
        ]

        normal_requests = [
            {"type": "normal", "payload": "product=1"},
            {"type": "normal", "payload": "search=apple"},
            {"type": "normal", "payload": "email=user@test.com"},
            {"type": "normal", "payload": "page=1"},
            {"type": "normal", "payload": "category=juice"},
            {"type": "normal", "payload": "sort=price"},
        ]

        # 40% chance of attack
        if random.random() < 0.4:
            return random.choice(endpoints), random.choice(attacks)
        else:
            return random.choice(endpoints), random.choice(normal_requests)

    def send_to_ml(self, endpoint, attack_data):
        """Отправляем данные в ML сервисы"""
        ml_data = {
            "request": {
                "url": f"{self.juice_shop_url}{endpoint}",
                "method": "POST" if "login" in endpoint else "GET",
                "body": attack_data["payload"],
                "headers": {
                    "User-Agent": f"Mozilla/5.0 ({attack_data['type']} Test)",
                    "Content-Type": "application/x-www-form-urlencoded"
                }
            },
            "metadata": {
                "source_ip": f"192.168.1.{random.randint(1, 255)}",
                "timestamp": datetime.now().isoformat(),
                "attack_type": attack_data["type"]
            }
        }

        iso_result = {"error": "Service unavailable"}
        rf_result = {"error": "Service unavailable"}

        try:
            # Отправляем в Isolation Forest
            iso_response = requests.post(
                self.ml_isolation_url,
                json=ml_data,
                timeout=2
            )

            if iso_response.status_code == 200:
                iso_result = iso_response.json()
            else:
                iso_result = {"error": f"HTTP {iso_response.status_code}"}

        except Exception as e:
            iso_result = {"error": str(e)}

        try:
            # Отправляем в Random Forest
            rf_response = requests.post(
                self.ml_random_url,
                json=ml_data,
                timeout=2
            )

            if rf_response.status_code == 200:
                rf_result = rf_response.json()
            else:
                rf_result = {"error": f"HTTP {rf_response.status_code}"}

        except Exception as e:
            rf_result = {"error": str(e)}

        # Логируем атаку
        attack_log = self.log_attack(attack_data, endpoint, iso_result, rf_result)

        return attack_log

    def show_statistics(self, request_count, attack_count):
        """Показываем статистику в красивом формате"""
        try:
            db_attacks = len(self.get_recent_attacks(1000))
        except:
            db_attacks = 0

        print("\n" + "=" * 60)
        print("\033[94m" + " "*20 + "ORCHID SECURITY MONITOR" + " "*20 + "\033[0m")
        print("=" * 60)
        print(f"📊 Статистика:")
        print(f"   Всего запросов:    \033[96m{request_count}\033[0m")
        print(f"   Обнаружено атак:   \033[91m{attack_count}\033[0m")
        print(f"   В базе данных:     \033[93m{db_attacks}\033[0m записей")
        print(f"   Juice Shop:        \033[92mhttp://localhost:3001\033[0m")
        print(f"   Админ панель:      \033[92mhttp://localhost:3000\033[0m")
        print(f"   Attack Stream:     \033[92mhttp://localhost:8082/stream\033[0m")
        print("=" * 60)

    def run_monitoring(self):
        """Запуск мониторинга"""
        print("\033[94m" + "="*60 + "\033[0m")
        print("\033[94m" + " "*15 + "ORCHID SECURITY SYSTEM MONITOR" + " "*15 + "\033[0m")
        print("\033[94m" + "="*60 + "\033[0m")
        print("\033[93mЗапуск мониторинга Juice Shop...\033[0m")
        print(f"\033[93mJuice Shop URL: {self.juice_shop_url}\033[0m")
        print("\033[93mНажмите Ctrl+C для остановки\033[0m\n")

        # Стартовый тест ML сервисов
        print("\033[95mТестируем ML сервисы...\033[0m")
        try:
            iso_health = requests.get("http://localhost:8001/health", timeout=2)
            print(f"Isolation Forest: {'✓' if iso_health.status_code == 200 else '✗'}")
        except:
            print("Isolation Forest: ✗")

        try:
            rf_health = requests.get("http://localhost:8002/health", timeout=2)
            print(f"Random Forest:    {'✓' if rf_health.status_code == 200 else '✗'}")
        except:
            print("Random Forest:    ✗")

        print(f"Attack Stream:    {'✓' if hasattr(self, 'stream_server') and self.stream_server else '✗'}")
        print("\n" + "="*60 + "\n")

        request_count = 0
        attack_count = 0

        while self.running:
            try:
                request_count += 1

                # Генерируем симулированный трафик
                endpoint, attack_data = self.generate_simulated_traffic()

                # Отправляем в ML
                if attack_data["type"] != "normal":
                    attack_count += 1

                self.send_to_ml(endpoint, attack_data)

                # Показываем статистику каждые 5 запросов
                if request_count % 5 == 0:
                    self.show_statistics(request_count, attack_count)

                # Случайная задержка между запросами
                time.sleep(random.uniform(0.5, 2.0))

            except KeyboardInterrupt:
                print("\n\033[93mОстановка мониторинга...\033[0m")
                self.running = False
                break
            except Exception as e:
                print(f"\033[90m[DEBUG] Ошибка: {e}\033[0m")
                time.sleep(1)

        # Финальная статистика
        print("\n" + "="*60)
        print("\033[92m" + " "*20 + "МОНИТОРИНГ ЗАВЕРШЕН" + " "*20 + "\033[0m")
        print("="*60)
        print(f"\033[96mФинальная статистика:\033[0m")
        print(f"   Всего запросов:    {request_count}")
        print(f"   Обнаружено атак:   {attack_count}")
        try:
            db_count = len(self.get_recent_attacks(1000))
            print(f"   Логов в БД:        {db_count}")
        except:
            print(f"   Логов в БД:        N/A")
        print("="*60)
        print(f"\033[92mБаза данных атак: {self.db_file}\033[0m")
        print(f"\033[92mStream URL: http://localhost:8082/stream\033[0m")
        print(f"\033[92mДля просмотра: sqlite3 {self.db_file} 'SELECT * FROM attacks LIMIT 10;'\033[0m")

def main():
    monitor = JuiceShopMonitor()
    monitor.run_monitoring()

if __name__ == "__main__":
    main()
