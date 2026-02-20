#!/usr/bin/env python3
import requests
import time
import sqlite3
from datetime import datetime
import os

def print_status(name, status, details=""):
    if status:
        print(f"✅ {name}: {details}")
    else:
        print(f"❌ {name}: {details}")

def check_service(name, url):
    """Проверка сервиса"""
    try:
        start = time.time()
        response = requests.get(url, timeout=3)
        elapsed = (time.time() - start) * 1000
        
        if response.status_code == 200:
            try:
                data = response.json()
                return True, f"HTTP 200 ({elapsed:.0f}ms) - {data.get('status', 'online')}"
            except:
                return True, f"HTTP 200 ({elapsed:.0f}ms)"
        else:
            return False, f"HTTP {response.status_code}"
    except Exception as e:
        return False, str(e)

def main():
    print("=" * 60)
    print("🛡️  ORCHID SECURITY SYSTEM - DASHBOARD")
    print("=" * 60)
    print(f"Время: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Проверка сервисов
    print("🌐 СЕТЕВЫЕ СЕРВИСЫ:")
    print("-" * 40)
    
    services = [
        ("Isolation Forest", "http://localhost:8001/health"),
        ("Random Forest", "http://localhost:8002/health"),
        ("Admin Backend", "http://localhost:8003/api/health"),
        ("Juice Shop", "http://localhost:3001"),
        ("Admin Panel", "http://localhost:3000"),
    ]
    
    all_ok = True
    for name, url in services:
        ok, details = check_service(name, url)
        print_status(name, ok, details)
        if not ok:
            all_ok = False
        time.sleep(0.5)
    
    print()
    print("📊 ДАННЫЕ И МОДЕЛИ:")
    print("-" * 40)
    
    # Проверка базы данных
    db_path = "data/attacks.db"
    if os.path.exists(db_path):
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM attacks")
            count = cursor.fetchone()[0]
            conn.close()
            print(f"✅ База данных: {count} записей")
        except Exception as e:
            print(f"❌ База данных: ошибка - {e}")
    else:
        print(f"❌ База данных: файл не найден")
        all_ok = False
    
    # Проверка моделей
    models_path = "data/models"
    if os.path.exists(models_path):
        models = [f for f in os.listdir(models_path) if f.endswith('.joblib')]
        if models:
            print(f"✅ ML модели: {len(models)} файлов")
            for model in models[:3]:  # Показываем первые 3
                size = os.path.getsize(f"{models_path}/{model}")
                print(f"   - {model} ({size:,} байт)")
        else:
            print(f"❌ ML модели: файлы не найдены")
            all_ok = False
    else:
        print(f"❌ ML модели: папка не найдена")
        all_ok = False
    
    print()
    print("⚡ СИСТЕМНЫЕ РЕСУРСЫ:")
    print("-" * 40)
    
    # Проверка Docker
    try:
        import subprocess
        result = subprocess.run(["docker", "ps", "--format", "{{.Names}}"], 
                              capture_output=True, text=True)
        containers = result.stdout.strip().split('\n')
        running = len([c for c in containers if c])
        print(f"✅ Docker: {running} контейнеров запущено")
    except:
        print("❌ Docker: не доступен")
    
    print()
    print("=" * 60)
    
    if all_ok:
        print("🎉 СИСТЕМА ГОТОВА К РАБОТЕ!")
        print()
        print("Следующие шаги:")
        print("1. Запустите мониторинг: python scripts/monitor_juice_improved.py")
        print("2. Откройте админку: http://localhost:3000")
        print("3. Тестируйте атаки: открыть http://localhost:3001")
    else:
        print("⚠️  ЕСТЬ ПРОБЛЕМЫ! Проверьте конфигурацию.")
    
    print("=" * 60)

if __name__ == "__main__":
    main()
