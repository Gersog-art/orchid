#!/bin/bash
echo "🔄 Инициализация проекта Orchid..."
echo "📁 Создаем структуру папок..."
mkdir -p data/{models,training,logs}
mkdir -p configs tests docs

# Копируем конфиги если их нет
echo "⚙️  Настраиваем конфигурации..."
if [ ! -f configs/.env ] && [ -f .env.example ]; then
    cp .env.example configs/.env
    echo "   ✅ Создан configs/.env из .env.example"
fi

# Создаем симлинки для обратной совместимости
echo "🔗 Создаем симлинки..."
if [ ! -L .env ] && [ -f configs/.env ]; then
    ln -sf configs/.env .env
    echo "   ✅ Создан симлинк .env -> configs/.env"
fi

if [ ! -L attacks.db ] && [ -f data/attacks.db ]; then
    ln -sf data/attacks.db attacks.db
    echo "   ✅ Создан симлинк attacks.db -> data/attacks.db"
fi

# Проверяем наличие моделей
echo "🤖 Проверяем ML модели..."
if [ -d "ml-core/models" ]; then
    # Копируем модели из ml-core в data/models
    cp -n ml-core/models/*.joblib data/models/ 2>/dev/null || true
    
    # Проверяем скопированные модели
    model_count=$(ls -1 data/models/*.joblib 2>/dev/null | wc -l)
    if [ $model_count -gt 0 ]; then
        echo "   ✅ Найдено $model_count моделей в data/models/"
    else
        echo "   ⚠️  Модели не найдены в data/models/"
        echo "      Запустите: cd ml-core && python train_real_models.py"
        echo "      Затем: cp ml-core/models/*.joblib data/models/"
    fi
fi

# Проверяем наличие базы данных
echo "📊 Проверяем базу данных..."
if [ ! -f data/attacks.db ]; then
    echo "   📄 Создаем новую базу данных..."
    sqlite3 data/attacks.db <<'SQL_EOF'
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
);
SQL_EOF
    echo "   ✅ База данных создана: data/attacks.db"
else
    echo "   ✅ База данных уже существует: data/attacks.db"
fi

# Создаем лог файлы
echo "📝 Настраиваем логи..."
touch data/logs/{app,attacks,errors}.log 2>/dev/null || true

# Настраиваем права
chmod +x scripts/*.sh 2>/dev/null || true

echo "✅ Инициализация завершена!"
