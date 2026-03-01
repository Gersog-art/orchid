#!/bin/bash

echo "Starting Orchid Security System..."

echo "🔄 Миграция базы данных..."
./scripts/migrate_database.sh

echo "🔄 Инициализация проекта..."
./scripts/init_project.sh

# Проверка Docker
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "Error: Docker Compose is not installed"
    exit 1
fi

# Запуск сервисов
echo "Starting Docker containers..."
docker-compose up -d

echo "Waiting for services to start..."
sleep 8

# Проверка сервисов
check_service() {
    local name=$1
    local port=$2
    local endpoint=$3
    local max_attempts=15
    local attempt=1

    echo "Waiting for $name to be ready..."

    while [ $attempt -le $max_attempts ]; do
        # Проверяем, что сервис отвечает с кодом 200
        if curl -s -o /dev/null -w "%{http_code}" http://localhost:$port$endpoint | grep -q "200"; then
            echo "✓ $name is ready"
            return 0
        fi

        echo "Attempt $attempt/$max_attempts: $name not ready yet..."
        sleep 2
        attempt=$((attempt + 1))
    done

    echo "⚠️  $name may not be fully responsive"
    return 1
}

# Проверка сервисов
check_service "Isolation Forest" 8001 "/health" || true
check_service "Random Forest" 8002 "/health" || true
check_service "Admin Backend" 8003 "/api/health" || true
check_service "Juice Shop" 3001 "/" || true

echo ""
echo "========================================="
echo "Orchid System Started Successfully!"
echo "========================================="
echo ""
echo "Services:"
echo "- Admin Panel (Real): http://localhost:3000/real_dashboard.html"
echo "- Admin Panel (Old): http://localhost:3000/index.html"
echo "- Juice Shop: http://localhost:3001"
echo "- Isolation Forest API: http://localhost:8001/health"
echo "- Random Forest API: http://localhost:8002/health"
echo "- Admin Backend API: http://localhost:8003/api/health"
echo ""
echo "To stop: ./stop-orchid.sh"
echo "To test: python3 test_ml.py"
echo "To monitor: python3 monitor_juice_improved.py"
echo ""
echo "IMPORTANT: Train models first:"
echo "cd ml-core && python train_real_models.py"
