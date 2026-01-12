# 🛡️ Orchid Security System v2.0

**Система обнаружения веб-атак на основе машинного обучения с использованием Isolation Forest и Random Forest**

## 📋 Содержание
- [Теоретическая основа](#теоретическая-основа)
- [Архитектура системы](#архитектура-системы)
- [Быстрый старт](#быстрый-старт)
- [Детальное руководство](#детальное-руководство)
- [Возможные проблемы и решения](#возможные-проблемы-и-решения)
- [Мониторинг и анализ](#мониторинг-и-анализ)
- [API документация](#api-документация)
- [Структура проекта](#структура-проекта)

---

## 🧠 Теоретическая основа

### **Isolation Forest (Лес изоляции)**
**Принцип работы:** Алгоритм обнаруживает аномалии по принципу "изоляции". Чем меньше шагов нужно для изоляции точки данных, тем более аномальной она считается.

**Математическая основа:**

Пусть X = {x₁, x₂, ..., xₙ} - набор данных
Для каждого дерева:

    Случайно выбираем подвыборку

    Рекурсивно разделяем данные случайными разделениями

    Аномалии изолируются быстрее (меньшая глубина)

Аномальность вычисляется как:
s(x, n) = 2^{-E(h(x))/c(n)}
где h(x) - глубина изоляции
c(n) - средняя глубина для n точек



**Преимущества:**
- ✅ Не требует размеченных данных (unsupervised)
- ✅ Эффективен с высокоразмерными данными
- ✅ Низкая вычислительная сложность O(n log n)

### **Random Forest (Случайный лес)**
**Принцип работы:** Ансамбль решающих деревьев, каждое обучается на случайной подвыборке данных и признаков.

**Математическая основа:**

Пусть имеем M деревьев:
Для m = 1..M:
1. Bootstrap выборка из обучающих данных
2. Случайный выбор k признаков из p
3. Построение дерева решений

Прогноз для нового образца:
ŷ = mode({T₁(x), T₂(x), ..., Tₘ(x)}) # для классификации
text


**Преимущества:**
- ✅ Снижение переобучения
- ✅ Оценка важности признаков
- ✅ Устойчивость к выбросам

### **Извлекаемые признаки из HTTP-запросов:**
1. **request_length** - длина запроса (аномалия: >1000 символов)
2. **param_count** - количество параметров (аномалия: >10)
3. **special_char_ratio** - доля спецсимволов (аномалия: >0.2)
4. **url_depth** - глубина URL (аномалия: >6)
5. **user_agent_length** - длина User-Agent (аномалия: <50)
6. **content_length** - размер содержимого (аномалия: >2000)
7. **request_time_seconds** - время выполнения (аномалия: >2.0s)
8. **status_code** - код ответа (аномалия: 4xx/5xx)

---

## 🏗️ Архитектура системы

┌─────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│ Juice Shop │────│ ML Сервисы │────│ Веб-админка │
│ (localhost:3001)│ │ (8001, 8002) │ │ (localhost:3000) │
└─────────────────┘ └──────────────────┘ └──────────────────┘
│ │ │
└───────────────────────┼───────────────────────┘
│
┌────────┴────────┐
│ Мониторинг │
│ (SSE стриминг) │
└─────────────────┘
│
┌────────┴────────┐
│ База данных │
│ (SQLite) │
└─────────────────┘
text


**Компоненты системы:**
1. **ML Сервисы** (порты 8001, 8002) - REST API для детектирования атак
2. **Juice Shop** (порт 3001) - тестовое уязвимое приложение
3. **Admin Panel** (порт 3000) - веб-интерфейс мониторинга
4. **Admin Backend** (порт 8003) - API для админки
5. **Monitor Service** - сбор и анализ трафика

---

## 🚀 Быстрый старт

### **Предварительные требования:**
```bash
# Проверка установки
docker --version              # Docker 20.10+
docker-compose --version      # Docker Compose 2.0+
python3 --version            # Python 3.11+
sqlite3 --version            # SQLite 3.30+

Установка и запуск за 5 минут:
bash

# 1. Клонирование и переход
git clone <репозиторий>
cd orchid-system_final

# 2. Установка прав и инициализация
chmod +x scripts/*.sh
./scripts/init_project.sh

# 3. Обучение моделей (если нет предобученных)
cd ml-core
python train_real_models.py
cp models/*.joblib ../data/models/
cd ..

# 4. Запуск системы
./scripts/run-orchid.sh

# 5. Проверка работы
python scripts/test_ml.py

Быстрые команды:
bash

make run      # Запуск всей системы
make test     # Тестирование ML сервисов
make monitor  # Запуск мониторинга
make clean    # Остановка и очистка

📖 Детальное руководство
1. Обучение моделей
bash

cd ml-core
python train_real_models.py

Процесс обучения:

    Генерация синтетических данных (1500 записей)

    Масштабирование признаков (StandardScaler)

    Обучение Isolation Forest (100 деревьев, contamination=0.1)

    Обучение Random Forest (100 деревьев, max_depth=10)

    Сохранение моделей в формате .joblib

2. Конфигурация системы

Важные файлы конфигурации:

    configs/.env - переменные окружения

    docker-compose.yml - конфигурация контейнеров

    ml-core/requirements.txt - зависимости ML сервисов

3. Настройка мониторинга
bash

# Редактирование параметров мониторинга
vim scripts/monitor_juice_improved.py

# Основные параметры:
DB_PATH = "data/attacks.db"        # Путь к БД
STREAM_PORT = 8082                  # Порт для SSE стриминга
CHECK_INTERVAL = 1.0               # Интервал проверок (сек)

🔧 Возможные проблемы и решения
Проблема 1: Контейнеры не запускаются
text

Ошибка: "port already in use"

Решение:
bash

# Найти и убить процесс на порту
sudo lsof -ti:8001 | xargs kill -9  # для порта 8001

# Или освободить все порты Orchid
./scripts/stop-orchid.sh
sudo fuser -k 8001/tcp 8002/tcp 8003/tcp 3000/tcp 3001/tcp

Проблема 2: ML модели не загружаются
text

Ошибка: "model_loaded: false" в /health

Решение:
bash

# 1. Проверить наличие моделей
ls -la data/models/*.joblib

# 2. Переобучить модели
cd ml-core
python train_real_models.py
cp models/*.joblib ../data/models/

# 3. Перезапустить ML сервисы
docker-compose restart ml-isolation ml-random

Проблема 3: Juice Shop не запускается
text

Ошибка: "Juice Shop may not be fully responsive"

Решение:
bash

# 1. Дать больше времени на запуск (до 60 секунд)
sleep 60

# 2. Проверить логи
docker logs orchid-juice-shop --tail 50

# 3. Использовать slim версию
# В docker-compose.yml заменить:
# image: bkimminich/juice-shop:slim

Проблема 4: CORS ошибки в браузере
text

Ошибка: "Access-Control-Allow-Origin"

Решение:
bash

# 1. Проверить CORS настройки в service_isolation.py
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Разрешить все источники
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 2. Перезапустить сервисы
docker-compose restart ml-isolation ml-random admin-backend

Проблема 5: Нет данных в админке
text

База данных пуста или не обновляется

Решение:
bash

# 1. Проверить соединение с БД
sqlite3 data/attacks.db "SELECT COUNT(*) FROM attacks;"

# 2. Проверить права на запись
ls -la data/attacks.db
chmod 666 data/attacks.db  # Разрешить запись

# 3. Запустить мониторинг вручную
python scripts/monitor_juice_improved.py

Проблема 6: Ошибка памяти в контейнерах
text

Ошибка: "Killed" или контейнер перезапускается

Решение:
bash

# 1. Увеличить лимиты Docker
# В ~/.docker/daemon.json:
{
  "default-shm-size": "1g",
  "memory": "4g"
}

# 2. Перезапустить Docker
sudo systemctl restart docker

# 3. Очистить неиспользуемые ресурсы
docker system prune -af

Проблема 7: SSE стриминг не работает
text

Ошибка: "Failed to start stream server"

Решение:
bash

# 1. Проверить занятость порта 8082
sudo netstat -tulpn | grep :8082

# 2. Освободить порт
sudo kill -9 $(sudo lsof -ti:8082)

# 3. Изменить порт в мониторе
sed -i 's/8082/8083/g' scripts/monitor_juice_improved.py

📊 Мониторинг и анализ
Команды для анализа:
bash

# 1. Просмотр логов в реальном времени
tail -f data/logs/attacks.log

# 2. Анализ базы данных
sqlite3 data/attacks.db "SELECT attack_type, COUNT(*) as count FROM attacks GROUP BY attack_type ORDER BY count DESC;"

# 3. Статистика по времени
sqlite3 data/attacks.db "SELECT strftime('%H:00', timestamp) as hour, COUNT(*) as attacks FROM attacks GROUP BY hour ORDER BY hour;"

# 4. Поиск ложных срабатываний
sqlite3 data/attacks.db "SELECT * FROM attacks WHERE detected = 0 AND attack_type != 'normal';"

Метрики эффективности:

    Точность (Accuracy): (TP + TN) / (TP + TN + FP + FN)

    Полнота (Recall): TP / (TP + FN)

    Точность детектирования (Precision): TP / (TP + FP)

    F1-Score: 2 * (Precision * Recall) / (Precision + Recall)

Где:

    TP (True Positive) - правильно обнаруженные атаки

    TN (True Negative) - правильно пропущенный нормальный трафик

    FP (False Positive) - ложные срабатывания

    FN (False Negative) - пропущенные атаки

🔌 API документация
Isolation Forest Service (порт 8001)
http

GET  /health         # Проверка состояния сервиса
GET  /model-info     # Информация о модели
POST /predict        # Обнаружение аномалий

Пример запроса:
POST /predict
{
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
    "source": "juice-shop",
    "timestamp": "2024-01-15T12:00:00Z"
  }
}

Ответ:
{
  "is_anomaly": true,
  "anomaly_score": -0.87,
  "prediction": "sqli",
  "confidence": 0.92,
  "service": "Isolation Forest"
}

Random Forest Service (порт 8002)
http

GET  /health         # Проверка состояния сервиса
GET  /model-info     # Информация о модели
POST /predict        # Классификация атак

Ответ:
{
  "prediction": "sqli",
  "confidence": 0.95,
  "is_attack": true,
  "service": "Random Forest",
  "top_predictions": [
    {"label": "sqli", "confidence": 0.95},
    {"label": "xss", "confidence": 0.03},
    {"label": "rce", "confidence": 0.02}
  ]
}

Admin Backend API (порт 8003)
http

GET  /api/health                 # Проверка состояния
GET  /api/services/status        # Статус всех сервисов
GET  /api/stats                  # Статистика атак
GET  /api/attacks/recent?limit=20 # Последние атаки
GET  /api/attacks/today          # Атаки за сегодня
DELETE /api/attacks              # Очистка базы данных

📁 Структура проекта
text

orchid-system_final/
├── 📁 admin/                    # Веб-админка
│   ├── 📁 html/                # Фронтенд
│   │   ├── index.html          # Основной интерфейс
│   │   └── proxy-config.js     # Конфигурация прокси
│   └── Dockerfile             # Docker для nginx
│
├── 📁 ml-core/                 # ML сервисы
│   ├── 📁 models/             # Модели ML
│   │   ├── isolation_forest_real.joblib
│   │   ├── random_forest_real.joblib
│   │   ├── label_encoder.joblib
│   │   └── scaler.joblib
│   ├── service_isolation.py   # Isolation Forest API
│   ├── service_random.py      # Random Forest API
│   ├── train_real_models.py   # Обучение моделей
│   └── Dockerfile            # Docker для ML сервисов
│
├── 📁 scripts/                # Скрипты управления
│   ├── run-orchid.sh         # Запуск системы
│   ├── stop-orchid.sh        # Остановка системы
│   ├── test_ml.py            # Тестирование ML сервисов
│   ├── monitor_juice_improved.py # Мониторинг атак
│   ├── test-agent.py         # Генератор тестового трафика
│   ├── final_validation.py   # Финальная проверка
│   ├── init_project.sh       # Инициализация проекта
│   └── migrate_database.sh   # Миграция БД
│
├── 📁 data/                   # Данные и логи
│   ├── 📁 models/            # ML модели (симлинк)
│   ├── 📁 logs/              # Логи приложения
│   ├── 📁 training/          # Данные для обучения
│   └── attacks.db           # База данных SQLite
│
├── 📁 configs/               # Конфигурационные файлы
│   ├── docker-compose.yml    # Конфигурация Docker
│   ├── .env.example         # Пример переменных окружения
│   └── .env                 # Фактические переменные
│
├── 📁 docs/                  # Документация
│   ├── API_DOCS.md          # API документация
│   └── CONTRIBUTING.md      # Руководство для разработчиков
│
├── admin_backend.py         # API бэкенд админки
├── docker-compose.yml       # Основной Docker Compose
├── Dockerfile              # Docker для бэкенда
├── Dockerfile.admin        # Docker для админки
├── Makefile               # Управление проектом
├── requirements.txt       # Python зависимости
└── README.md             # Эта документация

🚨 Предупреждения и рекомендации
Безопасность:

    ⚠️ Не использовать в production без дополнительной настройки безопасности

    ⚠️ Изменить пароли по умолчанию в .env файле

    ⚠️ Ограничить доступ к портам 8001-8003, 3000-3001

Производительность:

    📈 Для повышения производительности:

        Кэшировать предсказания моделей

        Использовать асинхронные запросы

        Оптимизировать запросы к БД

Масштабирование:

    🔄 Для масштабирования системы:

        Заменить SQLite на PostgreSQL

        Добавить балансировщик нагрузки

        Внедрить очереди сообщений (Redis/RabbitMQ)

📚 Дополнительные ресурсы
Теоретические материалы:

    Isolation Forest оригинальная статья

    Random Forest в scikit-learn

    OWASP Juice Shop

Инструменты для тестирования:

    Burp Suite - для тестирования безопасности

    SQLMap - для тестирования SQL инъекций

    ZAP - автоматизированный сканер безопасности

👥 Разработчики и лицензия

Разработано: Команда Orchid Security
Версия: 2.0.0
Лицензия: MIT License
Дата последнего обновления: $(date +%Y-%m-%d)
Благодарности:

    OWASP за Juice Shop

    Scikit-learn team за ML библиотеки

    FastAPI team за фреймворк

    Docker team за контейнеризацию

Важно: Эта система предназначена исключительно для образовательных целей и тестирования в контролируемых средах. Использование для атак на системы без явного разрешения незаконно.
