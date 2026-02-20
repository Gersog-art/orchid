from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
import sqlite3
from datetime import datetime, timedelta
import os
import csv
import io
import subprocess
import re
import threading
import time

# Создаем директорию data если ее нет
if not os.path.exists('data'):
    os.makedirs('data', exist_ok=True)

DB_PATH = 'data/attacks.db'

def init_database():
    try:
        conn = sqlite3.connect(DB_PATH)
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
                ml_service TEXT DEFAULT 'both'
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                reason TEXT,
                blocked_by TEXT DEFAULT 'manual'
            )
        ''')

        # Добавляем новые колонки в таблицу attacks, если их нет
        cursor.execute("PRAGMA table_info(attacks)")
        existing_columns = [row[1] for row in cursor.fetchall()]
        new_columns = {
            'http_method': 'TEXT',
            'headers': 'TEXT',
            'full_url': 'TEXT',
            'user_agent': 'TEXT',
            'response_status': 'INTEGER',
            'request_body': 'TEXT'
        }
        for col, col_type in new_columns.items():
            if col not in existing_columns:
                cursor.execute(f"ALTER TABLE attacks ADD COLUMN {col} {col_type}")

        conn.commit()
        conn.close()
        print(f"✅ База данных инициализирована/обновлена: {DB_PATH}")
    except Exception as e:
        print(f"❌ Ошибка инициализации БД: {e}")

init_database()

app = FastAPI(title="Orchid Admin Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Валидация и iptables ----------
def is_valid_ip(ip):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    parts = ip.split('.')
    for part in parts:
        if int(part) > 255:
            return False
    return True

def apply_iptables_block(ip, action='add'):
    if not is_valid_ip(ip):
        return False, "Неверный IP адрес"

    try:
        if action == 'add':
            check = subprocess.run(
                ['iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP'],
                capture_output=True
            )
            if check.returncode == 0:
                return True, "IP уже заблокирован"

            result = subprocess.run(
                ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                return True, f"IP {ip} заблокирован"
            else:
                return False, f"Ошибка iptables: {result.stderr}"

        elif action == 'remove':
            result = subprocess.run(
                ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                return True, f"IP {ip} разблокирован"
            else:
                return False, f"Ошибка iptables: {result.stderr}"

    except Exception as e:
        return False, str(e)

def restore_iptables_rules():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT ip FROM blocked_ips')
        rows = cursor.fetchall()
        conn.close()

        for row in rows:
            ip = row[0]
            check = subprocess.run(
                ['iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP'],
                capture_output=True
            )
            if check.returncode != 0:
                subprocess.run(
                    ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
                    capture_output=True
                )
                print(f"Восстановлена блокировка IP {ip}")
    except Exception as e:
        print(f"Ошибка восстановления правил iptables: {e}")

restore_iptables_rules()

# ---------- Авто-блокировка (фоновая задача) ----------
ATTACK_THRESHOLD = 5      # количество атак
TIME_WINDOW = 60          # за последние 60 секунд

def is_ip_blocked(ip):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT 1 FROM blocked_ips WHERE ip = ?', (ip,))
        result = cursor.fetchone() is not None
        conn.close()
        return result
    except:
        return False

def auto_block_worker():
    while True:
        time.sleep(30)  # проверка каждые 30 секунд
        now = datetime.now()
        cutoff = (now - timedelta(seconds=TIME_WINDOW)).isoformat()

        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT source_ip, COUNT(*) as cnt
                FROM attacks
                WHERE timestamp > ? AND attack_type != 'normal'
                GROUP BY source_ip
                HAVING cnt >= ?
            ''', (cutoff, ATTACK_THRESHOLD))
            rows = cursor.fetchall()
            conn.close()
        except Exception as e:
            print(f"Auto-block DB query error: {e}")
            continue

        for ip, cnt in rows:
            if is_ip_blocked(ip):
                continue
            success, message = apply_iptables_block(ip, 'add')
            if success:
                try:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT OR IGNORE INTO blocked_ips (ip, timestamp, reason, blocked_by)
                        VALUES (?, ?, ?, ?)
                    ''', (ip, now.isoformat(), f'auto-block after {cnt} attacks', 'auto'))
                    conn.commit()
                    conn.close()
                except Exception as e:
                    print(f"Auto-block DB error: {e}")
                print(f"🚫 Auto-blocked IP {ip} (attacks: {cnt})")

# Запускаем фоновый поток
threading.Thread(target=auto_block_worker, daemon=True).start()

# ---------- Эндпоинты ----------
@app.get("/api/health")
async def health():
    return {
        "status": "online",
        "service": "Admin Backend",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/services/status")
async def get_services_status():
    services = [
        {"name": "Isolation Forest", "port": 8001, "status": "online", "last_checked": datetime.now().isoformat()},
        {"name": "Random Forest", "port": 8002, "status": "online", "last_checked": datetime.now().isoformat()},
        {"name": "Juice Shop", "port": 3001, "status": "online", "last_checked": datetime.now().isoformat()},
        {"name": "Admin Backend", "port": 8003, "status": "online", "last_checked": datetime.now().isoformat()}
    ]
    return {
        "services": services,
        "timestamp": datetime.now().isoformat(),
        "total_services": 4,
        "online_services": 4
    }

@app.get("/api/stats")
async def get_stats():
    """Расширенная статистика с распределением по типам атак"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM attacks")
        total = cursor.fetchone()[0] or 0

        cursor.execute("SELECT COUNT(*) FROM attacks WHERE detected = 1")
        detected = cursor.fetchone()[0] or 0

        cursor.execute("SELECT COUNT(DISTINCT source_ip) FROM attacks WHERE detected = 1")
        unique_ips = cursor.fetchone()[0] or 0

        cursor.execute("SELECT COUNT(*) FROM blocked_ips")
        blocked_count = cursor.fetchone()[0] or 0

        # Распределение по типам атак (исключая normal)
        cursor.execute("""
            SELECT attack_type, COUNT(*)
            FROM attacks
            WHERE attack_type != 'normal'
            GROUP BY attack_type
            ORDER BY COUNT(*) DESC
        """)
        type_counts = {row[0]: row[1] for row in cursor.fetchall()}

        conn.close()

        return {
            "total_attacks": total,
            "detected_attacks": detected,
            "unique_ips": unique_ips,
            "blocked_count": blocked_count,
            "attack_types": type_counts,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "total_attacks": 0,
            "detected_attacks": 0,
            "unique_ips": 0,
            "blocked_count": 0,
            "attack_types": {},
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }

@app.get("/api/attacks/recent")
async def get_recent_attacks(limit: int = 20):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM attacks
            WHERE attack_type != 'normal'
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))
        attacks = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return {
            "attacks": attacks,
            "count": len(attacks),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "attacks": [],
            "count": 0,
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }

@app.get("/api/attacks/today")
async def get_today_attacks():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM attacks
            WHERE DATE(timestamp) = DATE('now')
            AND attack_type != 'normal'
            ORDER BY timestamp DESC
        """)
        attacks = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return {
            "attacks": attacks,
            "count": len(attacks),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "attacks": [],
            "count": 0,
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }

@app.delete("/api/attacks")
async def clear_attacks():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM attacks")
        conn.commit()
        deleted = cursor.rowcount
        conn.close()
        return {
            "success": True,
            "message": f"Удалено {deleted} записей",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "success": False,
            "message": str(e),
            "timestamp": datetime.now().isoformat()
        }

@app.get("/api/attacks/export")
async def export_attacks(format: str = "csv"):
    """Экспорт всех атак в CSV или JSON"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM attacks ORDER BY timestamp DESC")
        rows = cursor.fetchall()
        conn.close()

        if format == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            if rows:
                writer.writerow(rows[0].keys())
                for row in rows:
                    writer.writerow(row)
            else:
                writer.writerow(["timestamp","attack_type","source_ip","endpoint","payload","isolation_result","random_result","detected","ml_service"])
            return Response(
                content=output.getvalue(),
                media_type="text/csv",
                headers={"Content-Disposition": "attachment; filename=attacks.csv"}
            )
        else:
            attacks = [dict(row) for row in rows]
            return {"attacks": attacks, "count": len(attacks)}
    except Exception as e:
        return {"error": str(e)}

# ----- Эндпоинты для блокировки IP -----
@app.post("/api/block/{ip}")
async def block_ip(ip: str, reason: str = "Blocked from admin panel"):
    if not is_valid_ip(ip):
        return {"success": False, "message": "Неверный формат IP"}

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR IGNORE INTO blocked_ips (ip, timestamp, reason, blocked_by)
            VALUES (?, ?, ?, ?)
        ''', (ip, datetime.now().isoformat(), reason, 'admin'))
        conn.commit()
        conn.close()
    except Exception as e:
        return {"success": False, "message": f"Ошибка БД: {e}"}

    success, message = apply_iptables_block(ip, 'add')
    return {"success": success, "message": message}

@app.delete("/api/block/{ip}")
async def unblock_ip(ip: str):
    if not is_valid_ip(ip):
        return {"success": False, "message": "Неверный формат IP"}

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM blocked_ips WHERE ip = ?', (ip,))
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
    except Exception as e:
        return {"success": False, "message": f"Ошибка БД: {e}"}

    success, message = apply_iptables_block(ip, 'remove')
    if deleted > 0:
        message += f" (удалено из БД)"
    return {"success": success, "message": message}

@app.get("/api/blocked")
async def get_blocked_ips():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT ip, timestamp, reason, blocked_by FROM blocked_ips ORDER BY timestamp DESC')
        rows = cursor.fetchall()
        conn.close()
        return {"success": True, "blocked": [dict(row) for row in rows]}
    except Exception as e:
        return {"success": False, "message": str(e), "blocked": []}

if __name__ == "__main__":
    import uvicorn
    print(f"🚀 Запуск Admin Backend на порту 8003")
    print(f"📊 База данных: {DB_PATH}")
    uvicorn.run(app, host="0.0.0.0", port=8003)
