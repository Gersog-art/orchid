#!/bin/bash
# Orchid System Management Script

set -e

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Функции
usage() {
    echo -e "${BLUE}Orchid Security System Management${NC}"
    echo "Usage: $0 {start|stop|restart|status|logs|init|backup|restore|monitor|sniffer|analyzer|train|help}"
    echo ""
    echo "  start       Запустить все сервисы (docker + фоновые процессы)"
    echo "  stop        Остановить все сервисы"
    echo "  restart     Перезапустить все сервисы"
    echo "  status      Показать статус всех компонентов"
    echo "  logs        Показать логи (можно указать имя сервиса)"
    echo "  init        Инициализировать проект (создать папки, БД)"
    echo "  backup      Создать резервную копию БД и логов"
    echo "  restore     Восстановить из последней резервной копии"
    echo "  monitor     Запустить/остановить генератор трафика (async_monitor)"
    echo "  sniffer     Запустить/остановить сниффер"
    echo "  analyzer    Запустить/остановить анализатор эксплойтов"
    echo "  train       Переобучить ML модели"
    echo "  help        Показать эту справку"
    echo ""
    echo "Пример: $0 start"
}

# Проверка, запущен ли процесс по имени
is_running() {
    pgrep -f "$1" > /dev/null 2>&1
    return $?
}

# Запуск docker сервисов
docker_up() {
    echo -e "${GREEN}Запуск Docker контейнеров...${NC}"
    docker-compose up -d
    echo -e "${GREEN}Docker контейнеры запущены.${NC}"
}

# Остановка docker сервисов
docker_down() {
    echo -e "${YELLOW}Остановка Docker контейнеров...${NC}"
    docker-compose down
    echo -e "${GREEN}Docker контейнеры остановлены.${NC}"
}

# Статус docker
docker_status() {
    echo -e "${BLUE}Docker контейнеры:${NC}"
    docker-compose ps
}

# Логи docker
docker_logs() {
    if [ -z "$1" ]; then
        docker-compose logs --tail=100 -f
    else
        docker-compose logs --tail=100 -f "$1"
    fi
}

# Запуск фонового Python скрипта
run_python_script() {
    local name=$1
    local script=$2
    if is_running "$script"; then
        echo -e "${YELLOW}$name уже запущен.${NC}"
    else
        echo -e "${GREEN}Запуск $name...${NC}"
        cd scripts
        nohup python "$script" > /dev/null 2>&1 &
        cd - > /dev/null
        sleep 1
        if is_running "$script"; then
            echo -e "${GREEN}$name запущен.${NC}"
        else
            echo -e "${RED}Не удалось запустить $name.${NC}"
        fi
    fi
}

# Остановка фонового Python скрипта
stop_python_script() {
    local name=$1
    local script=$2
    if is_running "$script"; then
        echo -e "${YELLOW}Остановка $name...${NC}"
        pkill -f "$script"
        sleep 1
        if is_running "$script"; then
            echo -e "${RED}Не удалось остановить $name.${NC}"
        else
            echo -e "${GREEN}$name остановлен.${NC}"
        fi
    else
        echo -e "${YELLOW}$name не запущен.${NC}"
    fi
}

# Инициализация проекта
init_project() {
    echo -e "${BLUE}Инициализация проекта...${NC}"
    ./scripts/init_project.sh
    echo -e "${GREEN}Инициализация завершена.${NC}"
}

# Бэкап
backup() {
    local backup_dir="backups/$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    echo -e "${BLUE}Создание резервной копии в $backup_dir...${NC}"
    if [ -f data/attacks.db ]; then
        cp data/attacks.db "$backup_dir/"
        echo -e "${GREEN}БД скопирована.${NC}"
    else
        echo -e "${YELLOW}БД не найдена, пропускаем.${NC}"
    fi
    if [ -d logs ]; then
        cp -r logs "$backup_dir/"
        echo -e "${GREEN}Логи скопированы.${NC}"
    fi
    if [ -d data/logs ]; then
        cp -r data/logs "$backup_dir/"
        echo -e "${GREEN}Логи из data скопированы.${NC}"
    fi
    echo -e "${GREEN}Резервная копия создана в $backup_dir.${NC}"
}

# Восстановление из последнего бэкапа
restore() {
    local latest=$(ls -td backups/*/ 2>/dev/null | head -1)
    if [ -z "$latest" ]; then
        echo -e "${RED}Нет резервных копий в папке backups/.${NC}"
        exit 1
    fi
    echo -e "${BLUE}Восстановление из $latest...${NC}"
    if [ -f "$latest/attacks.db" ]; then
        cp "$latest/attacks.db" data/ 2>/dev/null && echo -e "${GREEN}БД восстановлена.${NC}" || echo -e "${RED}Ошибка восстановления БД.${NC}"
    fi
    if [ -d "$latest/logs" ]; then
        cp -r "$latest/logs" . 2>/dev/null && echo -e "${GREEN}Логи восстановлены.${NC}"
    fi
    if [ -d "$latest/logs" ]; then
        cp -r "$latest/logs" data/ 2>/dev/null && echo -e "${GREEN}Логи в data восстановлены.${NC}"
    fi
    echo -e "${GREEN}Восстановление завершено.${NC}"
}

# Переобучение моделей
train_models() {
    echo -e "${BLUE}Переобучение ML моделей...${NC}"
    cd ml-core
    python prepare_training_data.py || echo -e "${RED}Ошибка prepare_training_data.py${NC}"
    python merge_datasets.py || echo -e "${RED}Ошибка merge_datasets.py${NC}"
    python train_real_models.py || echo -e "${RED}Ошибка train_real_models.py${NC}"
    if [ -f models/random_forest_real.joblib ]; then
        cp models/*.joblib ../data/models/ 2>/dev/null && echo -e "${GREEN}Модели скопированы в data/models.${NC}"
    fi
    cd ..
    echo -e "${GREEN}Процесс обучения завершён (проверьте вывод выше на ошибки).${NC}"
}

# Главная логика
case "$1" in
    start)
        docker_up
        run_python_script "Монитор" "async_monitor.py"
        run_python_script "Сниффер" "traffic_sniffer.py"
        run_python_script "Анализатор" "exploit_analyzer.py"
        ;;
    stop)
        stop_python_script "Монитор" "async_monitor.py"
        stop_python_script "Сниффер" "traffic_sniffer.py"
        stop_python_script "Анализатор" "exploit_analyzer.py"
        docker_down
        ;;
    restart)
        $0 stop
        sleep 2
        $0 start
        ;;
    status)
        docker_status
        echo -e "${BLUE}Фоновые процессы:${NC}"
        is_running "async_monitor.py" && echo -e "  Монитор: ${GREEN}запущен${NC}" || echo -e "  Монитор: ${RED}остановлен${NC}"
        is_running "traffic_sniffer.py" && echo -e "  Сниффер: ${GREEN}запущен${NC}" || echo -e "  Сниффер: ${RED}остановлен${NC}"
        is_running "exploit_analyzer.py" && echo -e "  Анализатор: ${GREEN}запущен${NC}" || echo -e "  Анализатор: ${RED}остановлен${NC}"
        ;;
    logs)
        if [ -z "$2" ]; then
            docker_logs
        else
            if [[ "$2" == "monitor" || "$2" == "sniffer" || "$2" == "analyzer" ]]; then
                local script=""
                case "$2" in
                    monitor) script="async_monitor.py" ;;
                    sniffer) script="traffic_sniffer.py" ;;
                    analyzer) script="exploit_analyzer.py" ;;
                esac
                if is_running "$script"; then
                    echo -e "${YELLOW}Логи $2 (Ctrl+C для выхода):${NC}"
                    # Ищем файл лога (если скрипт перенаправляет вывод)
                    if [ -f "scripts/$script.log" ]; then
                        tail -f "scripts/$script.log"
                    else
                        echo -e "${RED}Файл лога не найден. Попробуйте: tail -f nohup.out${NC}"
                    fi
                else
                    echo -e "${RED}$2 не запущен.${NC}"
                fi
            else
                docker_logs "$2"
            fi
        fi
        ;;
    init)
        init_project
        ;;
    backup)
        backup
        ;;
    restore)
        restore
        ;;
    monitor)
        if [ "$2" == "start" ]; then
            run_python_script "Монитор" "async_monitor.py"
        elif [ "$2" == "stop" ]; then
            stop_python_script "Монитор" "async_monitor.py"
        else
            echo -e "${YELLOW}Использование: $0 monitor {start|stop}${NC}"
        fi
        ;;
    sniffer)
        if [ "$2" == "start" ]; then
            run_python_script "Сниффер" "traffic_sniffer.py"
        elif [ "$2" == "stop" ]; then
            stop_python_script "Сниффер" "traffic_sniffer.py"
        else
            echo -e "${YELLOW}Использование: $0 sniffer {start|stop}${NC}"
        fi
        ;;
    analyzer)
        if [ "$2" == "start" ]; then
            run_python_script "Анализатор" "exploit_analyzer.py"
        elif [ "$2" == "stop" ]; then
            stop_python_script "Анализатор" "exploit_analyzer.py"
        else
            echo -e "${YELLOW}Использование: $0 analyzer {start|stop}${NC}"
        fi
        ;;
    train)
        train_models
        ;;
    help|*)
        usage
        ;;
esac
