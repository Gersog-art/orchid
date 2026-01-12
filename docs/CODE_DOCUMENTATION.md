# 📚 Подробная документация кода Orchid Security System

## Структура документации:
1. [Скрипты управления](#скрипты-управления)
2. [ML сервисы](#ml-сервисы)
3. [Веб-интерфейс](#веб-интерфейс)
4. [База данных](#база-данных)
5. [Конфигурация](#конфигурация)

---

## 🛠️ Скрипты управления

### **1. run-orchid.sh**
**Назначение:** Основной скрипт запуска всей системы Orchid

```bash
#!/bin/bash
echo "Starting Orchid Security System..."

# Миграция базы данных в новую структуру
if [ -f "scripts/migrate_database.sh" ]; then
    echo "🔄 Миграция базы данных..."
    ./scripts/migrate_database.sh
fi

Разбор:

    #!/bin/bash - указание интерпретатора

    if [ -f "scripts/migrate_database.sh" ]; then - проверка существования файла

    ./scripts/migrate_database.sh - запуск миграции БД

bash

# Инициализация проекта
if [ -f "scripts/init_project.sh" ]; then
    echo "🔄 Инициализация проекта..."
    ./scripts/init_project.sh
else
    echo "⚠️  Скрипт init_project.sh не найден"
    echo "   Создаем базовую структуру..."
    mkdir -p data/{models,training,logs}
    mkdir -p configs
fi

Разбор:

    mkdir -p data/{models,training,logs} - создание структуры папок

    Флаг -p создает родительские директории если их нет

bash

# Проверка Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Error: Docker is not installed"
    echo "   Установите Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

Разбор:

    command -v docker - проверка наличия команды docker

    &> /dev/null - перенаправление stdout и stderr в /dev/null

    exit 1 - выход с кодом ошибки 1

bash

# Запуск сервисов
echo "🚀 Starting Docker containers..."
if command -v docker-compose &> /dev/null; then
    docker-compose up -d
else
    docker compose up -d
fi

Разбор:

    docker-compose up -d или docker compose up -d - запуск в фоновом режиме

    -d флаг для detached mode (в фоне)

2. stop-orchid.sh
bash

#!/bin/bash
echo "Stopping Orchid System..."
docker-compose down

echo "Cleaning up..."
docker system prune -f

echo "Orchid System stopped."

Разбор:

    docker-compose down - остановка и удаление контейнеров

    docker system prune -f - очистка неиспользуемых ресурсов Docker

    -f флаг для автоматического подтверждения

3. test_ml.py

Назначение: Тестирование ML сервисов
python

#!/usr/bin/env python3
import requests
import time

def test_service(port, name):
    url = f"http://localhost:{port}"
    print(f"\nТестируем {name} на порту {port}...")
    
    try:
        # Проверяем health
        health_url = f"{url}/health"
        response = requests.get(health_url, timeout=3)
        print(f"  Health check: {response.status_code}")
        if response.status_code == 200:
            print(f"  Ответ: {response.json()}")

Разбор:

    #!/usr/bin/env python3 - shebang для Python 3

    requests.get(health_url, timeout=3) - HTTP GET с таймаутом 3 сек

    response.json() - парсинг JSON ответа

python

        # Проверяем predict
        predict_url = f"{url}/predict"
        test_data = {
            "features": {
                "request_length": 300,
                "param_count": 2,
                "special_char_ratio": 0.02,
                "url_depth": 3,
                "user_agent_length": 120,
                "content_length": 500,
                "request_time_seconds": 0.5,
                "status_code": 200
            },
            "metadata": {
                "source": "test-script",
                "timestamp": "2024-01-15T12:00:00Z"
                }
            }
        response = requests.post(predict_url, json=test_data, timeout=3)

Разбор:

    requests.post(predict_url, json=test_data) - POST запрос с JSON телом

    Структура тестовых данных имитирует нормальный HTTP запрос

4. monitor_juice_improved.py

Назначение: Мониторинг и детектирование атак
python

class JuiceShopMonitor:
    def __init__(self):
        self.juice_shop_url = "http://localhost:3001"
        self.ml_isolation_url = "http://localhost:8001/predict"
        self.ml_random_url = "http://localhost:8002/predict"
        self.running = True
        self.attack_log = []
        self.db_file = "data/attacks.db"

Разбор:

    Инициализация URL для всех сервисов

    self.running = True - флаг для контроля цикла мониторинга

    self.db_file - путь к SQLite базе данных

python

    def init_db(self):
        """Инициализация SQLite базы данных для логов"""
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
                    ml_service TEXT DEFAULT 'both'
                )
            ''')
            conn.commit()
            conn.close()

Разбор:

    sqlite3.connect(self.db_file) - подключение к SQLite базе

    SQL запрос создает таблицу с полями:

        id - автоинкрементный первичный ключ

        timestamp - время атаки (текст в ISO формате)

        attack_type - тип атаки (sqli, xss, lfi, etc.)

        source_ip - IP источник (симулированный)

        endpoint - URL endpoint

        payload - полезная нагрузка атаки

        isolation_result - результат Isolation Forest

        random_result - результат Random Forest

        detected - флаг обнаружения

        ml_service - какой сервис обнаружил

python

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

Разбор:

    Список эндпоинтов имитирует реальные URL приложения

    Типы атак: SQL инъекции, XSS, LFI, RCE, XXE

    Полезные нагрузки соответствуют реальным атакам

python

    def send_to_ml(self, endpoint, attack_data):
        """Отправляем данные в ML сервисы"""
        ml_data = {
            "features": {
                "request_length": random.randint(200, 2000) if attack_data["type"] != "normal" else random.randint(200, 500),
                "param_count": random.randint(5, 30) if attack_data["type"] != "normal" else random.randint(1, 5),
                # ... остальные признаки
            },
            "metadata": {
                "source": "juice-shop",
                "timestamp": datetime.now().isoformat()
            }
        }

Разбор:

    Для атак генерируются более "подозрительные" значения:

        request_length: 200-2000 (атаки) vs 200-500 (норма)

        param_count: 5-30 (атаки) vs 1-5 (норма)

        special_char_ratio: 0.1-0.5 (атаки) vs 0.01-0.05 (норма)

5. test-agent.py

Назначение: Генератор тестового трафика
python

def generate_normal_request():
    return {
        "features": {
            "request_length": random.randint(200, 500),
            "param_count": random.randint(1, 5),
            "special_char_ratio": random.uniform(0.01, 0.05),
            "url_depth": random.randint(1, 4),
            "user_agent_length": random.randint(80, 150),
            "content_length": random.randint(100, 1000),
            "request_time_seconds": random.uniform(0.1, 1.0),
            "status_code": 200
        },
        "metadata": {
            "source": "juice-shop",
            "timestamp": datetime.now().isoformat()
        }
    }

Разбор:

    Нормальные запросы имеют характеристики:

        Короткая длина запроса (200-500)

        Мало параметров (1-5)

        Низкая доля спецсимволов (1-5%)

        Неглубокие URL (1-4 уровня)

        Нормальные User-Agent (80-150 символов)

        Успешные статус коды (200)

🤖 ML сервисы
1. service_isolation.py

Назначение: REST API для Isolation Forest модели
python

from fastapi import FastAPI
import joblib
import numpy as np
from pydantic import BaseModel
import time
import traceback
from typing import Dict, Any
import logging

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Orchid Isolation Forest - FULL")

Разбор:

    FastAPI - современный веб-фреймворк для Python

    joblib - для загрузки ML моделей

    pydantic - для валидации данных

    logging - для логирования работы сервиса

python

# Глобальные переменные
iso_model = None
scaler = None
model_loaded = False
feature_names = [
    'request_length', 'param_count', 'special_char_ratio',
    'url_depth', 'user_agent_length', 'content_length',
    'request_time_seconds', 'status_code'
]

Разбор:

    feature_names - список признаков в том же порядке, как в обучении

    model_loaded - флаг успешной загрузки модели

python

def load_models():
    """Загрузка моделей с проверкой"""
    global iso_model, scaler, model_loaded

    try:
        logger.info("🔄 Загрузка Isolation Forest модели...")
        iso_model = joblib.load('models/isolation_forest_real.joblib')
        logger.info("✅ Isolation Forest модель загружена")

        logger.info("🔄 Загрузка Scaler...")
        scaler = joblib.load('models/scaler.joblib')
        logger.info("✅ Scaler загружен")

Разбор:

    joblib.load() - загрузка сериализованных моделей

    Загружаются две модели: Isolation Forest и Scaler

    Scaler используется для масштабирования признаков

python

@app.get("/health")
async def health():
    return {
        "status": "healthy" if model_loaded else "unhealthy",
        "service": "Isolation Forest (FULL)",
        "timestamp": time.time(),
        "model_loaded": model_loaded,
        "model_type": "Isolation Forest",
        "features_count": len(feature_names),
        "version": "2.0-full"
    }

Разбор:

    Health endpoint возвращает статус сервиса

    Включает информацию о модели и версии

python

@app.post("/predict")
async def predict(request: PredictionRequest):
    """Полноценное предсказание с использованием ML модели"""

    if not model_loaded:
        return {
            "error": "Модель не загружена",
            "service": "Isolation Forest",
            "timestamp": time.time(),
            "model_used": False
        }

    try:
        # Извлекаем фичи в правильном порядке
        features_list = []
        missing_features = []

        for feature in feature_names:
            if feature in request.features:
                value = request.features[feature]
                try:
                    features_list.append(float(value))
                except:
                    features_list.append(0.0)
            else:
                # Если фича отсутствует, используем значение по умолчанию
                missing_features.append(feature)
                if feature == 'status_code':
                    features_list.append(200.0)
                elif feature == 'request_length':
                    features_list.append(500.0)
                # ... другие значения по умолчанию

Разбор:

    Извлекает признаки в правильном порядке для модели

    Если признак отсутствует, использует значение по умолчанию

    Преобразует все значения в float для совместимости с моделью

python

        # Преобразуем в numpy array
        features_array = np.array([features_list])

        # Масштабируем
        features_scaled = scaler.transform(features_array)

        # Предсказание Isolation Forest
        prediction = iso_model.predict(features_scaled)[0]  # 1 = нормальный, -1 = аномалия
        anomaly_score = float(iso_model.score_samples(features_scaled)[0])

Разбор:

    scaler.transform(features_array) - масштабирование признаков

    iso_model.predict() - возвращает 1 (нормальный) или -1 (аномалия)

    iso_model.score_samples() - оценка аномальности (меньше = более аномальный)

2. service_random.py

Назначение: REST API для Random Forest модели
python

label_mapping = {
    0: "normal",
    1: "sqli",
    2: "xss",
    3: "lfi",
    4: "rce",
    5: "brute"
}

Разбор:

    Маппинг числовых меток на текстовые названия классов

python

def load_models():
    """Загрузка моделей Random Forest"""
    global rf_model, label_encoder, scaler, model_loaded

    try:
        logger.info("🔄 Загрузка Random Forest модели...")
        rf_model = joblib.load('models/random_forest_real.joblib')
        logger.info("✅ Random Forest модель загружена")

        logger.info("🔄 Загрузка Label Encoder...")
        label_encoder = joblib.load('models/label_encoder.joblib')
        logger.info("✅ Label Encoder загружен")

Разбор:

    Random Forest требует LabelEncoder для преобразования текстовых меток в числа

    LabelEncoder сохраняет mapping между классами и их числовыми представлениями

python

        # Предсказание Random Forest
        prediction_encoded = rf_model.predict(features_scaled)[0]
        prediction_proba = rf_model.predict_proba(features_scaled)[0]

        # Декодируем метку
        try:
            prediction_label = label_encoder.inverse_transform([prediction_encoded])[0]
        except:
            # Если не удалось декодировать, используем mapping
            prediction_label = label_mapping.get(prediction_encoded, f"class_{prediction_encoded}")

Разбор:

    rf_model.predict() - возвращает предсказанный класс

    rf_model.predict_proba() - возвращает вероятности для каждого класса

    label_encoder.inverse_transform() - преобразует числовую метку обратно в текст

3. train_real_models.py

Назначение: Обучение ML моделей
python

def generate_training_data():
    """Генерация синтетических данных для тренировки"""
    np.random.seed(42)

    # Нормальный трафик (1000 примеров)
    normal_data = {
        'request_length': np.random.randint(200, 500, 1000),
        'param_count': np.random.randint(1, 6, 1000),
        'special_char_ratio': np.random.uniform(0.01, 0.05, 1000),
        'url_depth': np.random.randint(1, 5, 1000),
        'user_agent_length': np.random.randint(80, 150, 1000),
        'content_length': np.random.randint(100, 1000, 1000),
        'request_time_seconds': np.random.uniform(0.1, 1.0, 1000),
        'status_code': [200] * 1000
    }

Разбор:

    np.random.seed(42) - фиксация случайности для воспроизводимости

    Генерация 1000 нормальных записей с характеристиками нормального трафика

python

    # Атаки (500 примеров)
    attack_data = {
        'request_length': np.random.randint(500, 2000, 500),
        'param_count': np.random.randint(5, 30, 500),
        'special_char_ratio': np.random.uniform(0.1, 0.5, 500),
        'url_depth': np.random.randint(5, 10, 500),
        'user_agent_length': np.random.randint(10, 60, 500),
        'content_length': np.random.randint(2000, 5000, 500),
        'request_time_seconds': np.random.uniform(1.0, 5.0, 500),
        'status_code': np.random.choice([400, 404, 500], 500)
    }

Разбор:

    Атаки имеют отличительные признаки:

        Более длинные запросы (500-2000 символов)

        Больше параметров (5-30)

        Больше спецсимволов (10-50%)

        Более глубокие URL (5-10 уровней)

        Ошибки сервера (400, 404, 500)

python

def train_isolation_forest(X_train):
    """Тренировка Isolation Forest для обнаружения аномалий"""
    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=0.1,  # 10% аномалий
        random_state=42,
        n_jobs=-1
    )
    
    iso_forest.fit(X_train)
    joblib.dump(iso_forest, 'models/isolation_forest_real.joblib')

Разбор:

    n_estimators=100 - 100 деревьев в лесу

    contamination=0.1 - ожидаемая доля аномалий (10%)

    n_jobs=-1 - использование всех доступных ядер CPU

🌐 Веб-интерфейс
1. admin_backend.py

Назначение: Backend API для админ панели
python

@app.get("/api/stats")
async def get_stats():
    """Статистика из базы данных"""
    try:
        conn = sqlite3.connect('data/attacks.db')
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM attacks")
        total = cursor.fetchone()[0] or 0

        cursor.execute("SELECT COUNT(*) FROM attacks WHERE detected = 1")
        detected = cursor.fetchone()[0] or 0

        cursor.execute("SELECT COUNT(DISTINCT source_ip) FROM attacks WHERE detected = 1")
        blocked = cursor.fetchone()[0] or 0

        conn.close()

Разбор:

    Подсчет общей статистики из базы данных:

        total - всего записей

        detected - обнаруженных атак

        blocked - уникальных заблокированных IP

2. admin/html/index.html

Назначение: Frontend админ панели
javascript

function formatTime(timestamp) {
    try {
        const date = new Date(timestamp);
        return date.toLocaleTimeString();
    } catch (e) {
        return timestamp;
    }
}

Разбор:

    Форматирование timestamp в читаемое время

javascript

async function checkServices() {
    const btn = document.getElementById('refresh-btn');
    const spinner = document.getElementById('refresh-spinner');
    const text = document.getElementById('refresh-text');

    btn.disabled = true;
    spinner.style.display = 'inline-block';
    text.textContent = 'Checking...';

    try {
        const response = await fetch(`${API_BASE}/api/services/status`);
        const data = await response.json();

Разбор:

    Асинхронный запрос к API для получения статуса сервисов

    UI обратная связь: блокировка кнопки, показ спиннера

javascript

function getAttackBadgeClass(attackType) {
    if (!attackType) return 'badge-unknown';

    const type = attackType.toLowerCase();
    if (type.includes('sql') || type === 'sqli') return 'badge-sqli';
    if (type.includes('xss')) return 'badge-xss';
    if (type.includes('lfi') || type.includes('path')) return 'badge-lfi';
    if (type.includes('rce') || type.includes('command')) return 'badge-rce';
    if (type.includes('error')) return 'badge-error';
    if (type === 'normal') return 'badge-normal';
    return 'badge-unknown';
}

Разбор:

    Определение CSS класса для badge в зависимости от типа атаки

    Использует includes для гибкого определения типа

🗃️ База данных
Структура таблицы attacks:
sql

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
);

Поля:

    id - уникальный идентификатор записи

    timestamp - время атаки в ISO формате

    attack_type - тип атаки (sqli, xss, lfi, rce, brute, normal)

    source_ip - IP источник (формат: 192.168.1.XXX)

    endpoint - URL, на который была атака

    payload - полезная нагрузка (первые 100 символов)

    isolation_result - результат Isolation Forest

    random_result - результат Random Forest

    detected - флаг обнаружения (0/1)

    ml_service - какой сервис обнаружил ('isolation', 'random', 'both')

⚙️ Конфигурация
1. docker-compose.yml
yaml

services:
  ml-isolation:
    build: ./ml-core
    container_name: orchid-ml-isolation
    ports:
      - "8001:8000"
    volumes:
      - ./ml-core:/app
      - ./data/models:/app/models
    working_dir: /app
    command: ["python", "-m", "uvicorn", "service_isolation:app", "--host", "0.0.0.0", "--port", "8000"]
    environment:
      - PYTHONPATH=/app
    restart: unless-stopped
    networks:
      - orchid-network

Разбор:

    build: ./ml-core - сборка из Dockerfile в папке ml-core

    ports: - "8001:8000" - маппинг порта хоста 8001 на порт контейнера 8000

    volumes: - ./data/models:/app/models - монтирование папки с моделями

    restart: unless-stopped - автоматический перезапуск при падении

2. .env.example
bash

# RabbitMQ
RABBITMQ_USER=orchid_admin
RABBITMQ_PASS=SecurePass123!

# PostgreSQL
DB_NAME=orchid_db
DB_USER=orchid_user
DB_PASSWORD=SecureDBPass123!

# JWT
JWT_SECRET=your_super_secret_jwt_key_change_in_production

# Core settings
LOG_LEVEL=info
CORS_ORIGINS=http://localhost:3000

# ML Settings
IF_CONTAMINATION=0.05
RF_MODEL_PATH=/app/models/random_forest_v1.joblib

Разбор:

    Переменные окружения для конфигурации

    Включает настройки для потенциальных расширений (RabbitMQ, PostgreSQL, JWT)

🔍 Отладка и мониторинг
Полезные команды для отладки:
bash

# 1. Проверка логов контейнеров
docker-compose logs ml-isolation --tail 50
docker-compose logs ml-random --tail 50
docker-compose logs admin-backend --tail 50

# 2. Проверка состояния БД
sqlite3 data/attacks.db "SELECT * FROM attacks ORDER BY timestamp DESC LIMIT 5;"
sqlite3 data/attacks.db "SELECT attack_type, COUNT(*) as count FROM attacks GROUP BY attack_type;"

# 3. Проверка сетевых соединений
netstat -tulpn | grep -E '(8001|8002|8003|3000|3001)'

# 4. Проверка использования ресурсов
docker stats --no-stream

# 5. Тестирование API вручную
curl -X POST http://localhost:8001/predict -H "Content-Type: application/json" -d '{
  "features": {
    "request_length": 1500,
    "param_count": 25,
    "special_char_ratio": 0.3,
    "url_depth": 8,
    "user_agent_length": 30,
    "content_length": 4000,
    "request_time_seconds": 3.5,
    "status_code": 500
  },
  "metadata": {
    "source": "test",
    "timestamp": "2024-01-15T12:00:00Z"
  }
}'

🚀 Производительность и оптимизация
1. Оптимизация ML моделей:
python

# В train_real_models.py можно изменить параметры:
iso_forest = IsolationForest(
    n_estimators=50,        # Быстрее, но менее точный
    max_samples='auto',     # Размер подвыборки
    contamination=0.05,     # Ожидаемая доля аномалий
    random_state=42,
    n_jobs=-1              # Параллельная обработка
)

2. Кэширование предсказаний:
python

from functools import lru_cache

@lru_cache(maxsize=1000)
def cached_predict(features_tuple):
    """Кэширование предсказаний для одинаковых запросов"""
    return model.predict([features_tuple])

3. Асинхронная обработка:
python

@app.post("/predict")
async def predict(request: PredictionRequest):
    # Асинхронная обработка
    result = await asyncio.to_thread(process_prediction, request)
    return result

📈 Метрики и анализ
SQL запросы для анализа:
sql

-- 1. Эффективность детектирования по типам атак
SELECT 
    attack_type,
    COUNT(*) as total,
    SUM(CASE WHEN detected = 1 THEN 1 ELSE 0 END) as detected,
    ROUND(100.0 * SUM(CASE WHEN detected = 1 THEN 1 ELSE 0 END) / COUNT(*), 2) as detection_rate
FROM attacks
GROUP BY attack_type
ORDER BY detection_rate DESC;

-- 2. Распределение атак по часам
SELECT 
    strftime('%H', timestamp) as hour,
    COUNT(*) as attacks,
    ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM attacks), 2) as percentage
FROM attacks
WHERE attack_type != 'normal'
GROUP BY hour
ORDER BY hour;

-- 3. Топ IP источников атак
SELECT 
    source_ip,
    COUNT(*) as attacks,
    GROUP_CONCAT(DISTINCT attack_type) as types
FROM attacks
WHERE detected = 1
GROUP BY source_ip
ORDER BY attacks DESC
LIMIT 10;

🔧 Расширение системы
Добавление новой ML модели:

    Создать файл ml-core/service_new_model.py

    Добавить обучение в train_real_models.py

    Обновить docker-compose.yml с новым сервисом

    Обновить scripts/test_ml.py для тестирования

    Обновить админку для отображения результатов

Интеграция с реальным трафиком:
python

# Вместо генерации случайных данных:
def parse_real_traffic(log_line):
    """Парсинг реальных логов веб-сервера"""
    # Пример для Nginx логов
    pattern = r'(\S+) \S+ \S+ \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"'
    match = re.match(pattern, log_line)
    
    if match:
        ip, timestamp, request, status, size, referer, user_agent = match.groups()
        return {
            'source_ip': ip,
            'timestamp': timestamp,
            'request': request,
            'status_code': int(status),
            'content_length': int(size),
            'user_agent': user_agent
        }

🎯 Заключение

Система Orchid предоставляет комплексное решение для обнаружения веб-атак с использованием современных ML алгоритмов. Код спроектирован с учетом модульности, расширяемости и простоты использования.

Ключевые особенности кода:

    Модульность - каждый компонент независим

    Контейнеризация - легкое развертывание через Docker

    REST API - стандартизированные интерфейсы

    Масштабируемость - возможность добавления новых моделей

    Мониторинг - полноценная система наблюдения

Система готова к использованию в образовательных целях и может быть расширена для production использования с дополнительными мерами безопасности.
