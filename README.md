# 🛡️ Orchid — Honeypot + ML Ensemble для обнаружения веб-атак

**Orchid** — это интеллектуальная система обнаружения атак, объединяющая:

- **Honeypot** (на базе OWASP Juice Shop) для привлечения злоумышленников.
- **Ансамбль ML-моделей** (Isolation Forest и Random Forest), которые анализируют трафик в реальном времени.
- **Веб‑интерфейс** для мониторинга и управления.
- **Telegram-бота** для мгновенных уведомлений и блокировки IP.

Система автоматически собирает данные об атаках, сохраняет их в SQLite, а также умеет блокировать подозрительные IP через iptables.

---

## 🧠 Концепция

Orchid имитирует реальное веб-приложение (Juice Shop), привлекая атакующих. Все входящие запросы анализируются двумя ML‑моделями:

- **Isolation Forest** — выявляет аномалии (нетипичные запросы).
- **Random Forest** — классифицирует тип атаки (SQLi, XSS, LFI, RCE, Brute‑force, XXE).

Результаты сохраняются в базе данных и отображаются на дашборде. При превышении порога атак с одного IP система автоматически добавляет правило блокировки в iptables.

---

## 📦 Технологии

- **Python 3.11+**
- **FastAPI** — бэкенд и ML‑сервисы
- **Uvicorn** — ASGI‑сервер
- **Docker / Docker Compose** — контейнеризация
- **SQLite** — хранение событий
- **Scikit‑learn** — ML‑модели
- **Pandas / NumPy** — обработка данных
- **Nginx** — раздача статики админки
- **Telegram Bot API** — уведомления
- **Leaflet + OpenStreetMap** — карта атак

---

## ⚙️ Установка и запуск

### 1. Клонирование репозитория

```bash
git clone https://github.com/yourusername/orchid.git
cd orchidё
```
2. Создание виртуального окружения и установка зависимостей

Проект требует Python 3.11 или выше.
bash
```
python3.11 -m venv venv
source venv/bin/activate      # Linux / Mac
# или venv\Scripts\activate     # Windows

pip install --upgrade pip
pip install -r requirements.txt
pip install -r ml-core/requirements.txt
```
Дополнительно для Telegram‑бота и карты:
bash
```
pip install python-telegram-bot geoip2
```
3. Настройка базы данных и моделей
bash
```
# Инициализация структуры папок и БД
./scripts/init_project.sh

# Скачайте GeoLite2‑City.mmdb (бесплатно с MaxMind) и поместите в data/
# Либо отключите геолокацию, удалив соответствующий код.

# Обучение моделей (если нужно переобучить)
cd ml-core
python train_real_models.py
cd ..
```
4. Запуск через Docker Compose (рекомендуется)
bash
```
docker-compose up -d
```
Это поднимет:

    ML‑сервисы (порты 8001, 8002)

    Admin Backend (порт 8003)

    Admin Panel (nginx, порт 3000)

    Juice Shop (порт 3001)

5. Запуск монитора (генератор трафика)
bash
```
python scripts/monitor_juice_improved.py
```
🖥️ Интерфейс

    Админ‑панель: http://localhost:3000

    Juice Shop: http://localhost:3001

    API бэкенда: http://localhost:8003/docs (Swagger)

🔧 Возможные ошибки и их решения

1. Ошибка подключения к ML‑сервисам (Connection refused)

Причина: контейнеры не запущены или порты заняты.

Решение:
bash
```
docker-compose ps          # посмотреть статус
docker-compose logs ml-isolation   # логи конкретного сервиса
```
Убедитесь, что порты 8001, 8002, 8003, 3000, 3001 свободны.
2. База данных не создаётся / ошибки SQLite

Решение:
bash
```
# Вручную создать таблицы
sqlite3 data/attacks.db < schema.sql
# Либо перезапустить admin_backend, он сам создаст таблицы при запуске
```
3. Ошибка Address already in use

Решение: освободите порт или измените проброс портов в docker-compose.yml.
bash
```
sudo lsof -i :8001   # узнать, какой процесс занимает порт
kill -9 <PID>
```
5. Звук не воспроизводится

    Положите файл cat.mp3 в папку admin/html/. Если его нет, будет использован синтезированный звук через Web Audio.

