from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import sqlite3
from datetime import datetime
import requests
import time
import os

# Создаем директорию data если ее нет
if not os.path.exists('data'):
    os.makedirs('data', exist_ok=True)

# Путь к базе данных
DB_PATH = 'data/attacks.db'

def init_database():
    """Инициализация базы данных при запуске"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Создаем таблицу если ее нет
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

        conn.commit()
        conn.close()
        print(f"✅ База данных инициализирована: {DB_PATH}")
    except Exception as e:
        print(f"❌ Ошибка инициализации БД: {e}")

# Инициализируем БД при импорте
init_database()

app = FastAPI(title="Orchid Admin Backend")

# Настройка CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
    """Статистика из базы данных"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM attacks")
        total = cursor.fetchone()[0] or 0

        cursor.execute("SELECT COUNT(*) FROM attacks WHERE detected = 1")
        detected = cursor.fetchone()[0] or 0

        cursor.execute("SELECT COUNT(DISTINCT source_ip) FROM attacks WHERE detected = 1")
        blocked = cursor.fetchone()[0] or 0

        conn.close()

        return {
            "total_attacks": total,
            "detected_attacks": detected,
            "blocked_ips": blocked,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "total_attacks": 0,
            "detected_attacks": 0,
            "blocked_ips": 0,
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }

@app.get("/api/attacks/recent")
async def get_recent_attacks(limit: int = 20):
    """Последние атаки"""
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
    """Атаки за сегодня"""
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
    """Удалить все записи об атаках"""
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

if __name__ == "__main__":
    import uvicorn
    print(f"🚀 Запуск Admin Backend на порту 8003")
    print(f"📊 База данных: {DB_PATH}")
    uvicorn.run(app, host="0.0.0.0", port=8003)
