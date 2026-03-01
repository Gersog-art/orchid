#!/usr/bin/env python3
import requests
import json
import time
import sys

def test_endpoint(method, url, name, data=None, headers=None):
    print(f"\n🔍 Тестируем {name}:")
    print(f"   URL: {url}")
    print(f"   Метод: {method}")
    
    try:
        start = time.time()
        
        if method == 'GET':
            response = requests.get(url, timeout=3, headers=headers)
        elif method == 'POST':
            response = requests.post(url, json=data, timeout=3, headers=headers)
        elif method == 'HEAD':
            response = requests.head(url, timeout=3, headers=headers)
        elif method == 'OPTIONS':
            response = requests.options(url, timeout=3, headers=headers)
        else:
            print(f"   ❌ Неподдерживаемый метод: {method}")
            return False
        
        elapsed = (time.time() - start) * 1000
        
        if response.status_code == 200:
            print(f"   ✅ Успех: HTTP {response.status_code} ({elapsed:.0f}ms)")
            
            # Проверяем CORS заголовки
            cors_headers = []
            for header in ['Access-Control-Allow-Origin', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Headers']:
                if header in response.headers:
                    cors_headers.append(f"{header}: {response.headers[header]}")
            
            if cors_headers:
                print(f"   📋 CORS заголовки:")
                for h in cors_headers:
                    print(f"      {h}")
            
            # Если есть тело ответа, показываем его
            if method != 'HEAD' and method != 'OPTIONS':
                try:
                    content = response.json()
                    print(f"   📊 Ответ: {json.dumps(content, indent=2)[:100]}...")
                except:
                    print(f"   📄 Ответ (текст): {response.text[:100]}...")
            
            return True
        else:
            print(f"   ❌ Ошибка: HTTP {response.status_code}")
            print(f"   📄 Ответ: {response.text[:100]}...")
            return False
            
    except requests.exceptions.Timeout:
        print(f"   ⏰ Таймаут: Сервис не ответил за 3 секунды")
        return False
    except requests.exceptions.ConnectionError:
        print(f"   🔌 Ошибка соединения: Не удалось подключиться")
        return False
    except Exception as e:
        print(f"   ❗ Исключение: {e}")
        return False

def main():
    print("=" * 60)
    print("FINAL VALIDATION - ORCHID SECURITY SYSTEM")
    print("=" * 60)
    
    # Тестируем ML сервисы разными методами
    services = [
        ("GET", "http://localhost:8001/health", "Isolation Forest (GET)"),
        ("HEAD", "http://localhost:8001/health", "Isolation Forest (HEAD)"),
        ("OPTIONS", "http://localhost:8001/health", "Isolation Forest (OPTIONS)"),
        ("GET", "http://localhost:8002/health", "Random Forest (GET)"),
        ("HEAD", "http://localhost:8002/health", "Random Forest (HEAD)"),
        ("OPTIONS", "http://localhost:8002/health", "Random Forest (OPTIONS)"),
    ]
    
    success_count = 0
    for method, url, name in services:
        if test_endpoint(method, url, name):
            success_count += 1
        time.sleep(0.5)
    
    # Тестируем обнаружение атаки
    test_payload = {
        "request": {
            "url": "http://test.com/login",
            "method": "POST",
            "body": "' OR '1'='1' --",
            "headers": {"User-Agent": "Test"}
        },
        "metadata": {
            "source_ip": "192.168.1.100",
            "timestamp": "2024-01-15T12:00:00Z"
        }
    }
    
    print("\n" + "=" * 60)
    print("ТЕСТ ОБНАРУЖЕНИЯ АТАК")
    print("=" * 60)
    
    attack_tests = [
        ("POST", "http://localhost:8001/predict", "Isolation Forest Predict", test_payload),
        ("POST", "http://localhost:8002/predict", "Random Forest Predict", test_payload),
    ]
    
    for method, url, name, data in attack_tests:
        if test_endpoint(method, url, name, data):
            success_count += 1
        time.sleep(0.5)
    
    # Проверяем веб-интерфейсы
    print("\n" + "=" * 60)
    print("ПРОВЕРКА ВЕБ-ИНТЕРФЕЙСОВ")
    print("=" * 60)
    
    web_services = [
        ("GET", "http://localhost:3000", "Admin Panel"),
        ("GET", "http://localhost:3001", "Juice Shop"),
    ]
    
    for method, url, name in web_services:
        if test_endpoint(method, url, name):
            success_count += 1
        time.sleep(0.5)
    
    print("\n" + "=" * 60)
    print("РЕЗУЛЬТАТЫ ВАЛИДАЦИИ")
    print("=" * 60)
    
    total_tests = len(services) + len(attack_tests) + len(web_services)
    print(f"Всего тестов: {total_tests}")
    print(f"Успешных: {success_count}")
    print(f"Проваленных: {total_tests - success_count}")
    
    if success_count == total_tests:
        print("\n🎉 ВСЕ ТЕСТЫ ПРОЙДЕНЫ!")
        print("Система Orchid полностью работоспособна.")
    elif success_count >= total_tests * 0.7:
        print("\n⚠️  БОЛЬШИНСТВО ТЕСТОВ ПРОЙДЕНО")
        print("Система в основном работоспособна, есть незначительные проблемы.")
    else:
        print("\n❌ КРИТИЧЕСКИЕ ПРОБЛЕМЫ")
        print("Система требует доработки.")
    
    print("\n" + "=" * 60)
    print("РЕКОМЕНДАЦИИ:")
    print("-" * 60)
    
    if success_count < total_tests:
        print("1. Проверьте логи контейнеров: docker-compose logs")
        print("2. Перезапустите систему: docker-compose restart")
        print("3. Убедитесь, что порты не заняты другими процессами")
    else:
        print("1. Откройте админку: http://localhost:3000")
        print("2. Запустите мониторинг: python3 monitor_juice_improved.py")
        print("3. Протестируйте атаки: ./manual_attack_test.sh")
    
    print("=" * 60)
    
    return 0 if success_count == total_tests else 1

if __name__ == "__main__":
    sys.exit(main())
