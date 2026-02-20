#!/bin/bash
echo "🔍 Проверка всех сервисов Orchid..."
echo "=" * 60

# Проверка портов
services=(
  "Isolation Forest:8001/health"
  "Random Forest:8002/health"
  "Admin Backend:8003/api/health"
  "Admin Panel:3000"
  "Juice Shop:3001"
)

for service in "${services[@]}"; do
  name="${service%:*}"
  url="http://localhost:${service#*:}"
  
  if curl -s -f --max-time 3 "$url" > /dev/null; then
    echo "✅ $name: РАБОТАЕТ ($url)"
  else
    echo "❌ $name: НЕ ДОСТУПЕН ($url)"
  fi
done

echo "=" * 60
echo "📊 Проверка базы данных:"
if [ -f "data/attacks.db" ]; then
  count=$(sqlite3 data/attacks.db "SELECT COUNT(*) FROM attacks" 2>/dev/null || echo "0")
  echo "   Записей в БД: $count"
else
  echo "   База данных не найдена"
fi

echo "=" * 60
echo "🤖 Проверка ML моделей:"
if [ -d "data/models" ]; then
  echo "   Модели:"
  ls -la data/models/*.joblib 2>/dev/null | while read model; do
    size=$(echo "$model" | awk '{print $5}')
    name=$(echo "$model" | awk '{print $9}')
    echo "   - $(basename "$name") (${size} байт)"
  done || echo "   Модели не найдены"
else
  echo "   Папка models не найдена"
fi
