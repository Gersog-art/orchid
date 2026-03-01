#!/bin/bash

# Скрипт для добавления правила sudo без пароля для iptables
# Запускать с правами root или через sudo

if [ "$EUID" -ne 0 ]; then
    echo "Пожалуйста, запустите с sudo: sudo $0"
    exit 1
fi

# Определяем пользователя, который вызвал sudo
REAL_USER=${SUDO_USER:-$(who am i | awk '{print $1}')}
if [ -z "$REAL_USER" ]; then
    REAL_USER=$(logname 2>/dev/null || echo $USER)
fi

echo "Настраиваем sudo для пользователя: $REAL_USER"

# Проверяем, есть ли уже правило
if sudo -l -U "$REAL_USER" | grep -q "NOPASSWD:.*iptables"; then
    echo "Правило уже существует. Выход."
    exit 0
fi

# Добавляем строку в sudoers (через visudo -f для безопасности)
SUDOERS_FILE="/etc/sudoers.d/orchid-iptables"
RULE="$REAL_USER ALL=(ALL) NOPASSWD: /usr/sbin/iptables"

# Проверяем синтаксис перед записью
echo "$RULE" | visudo -c -f - >/dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "$RULE" > "$SUDOERS_FILE"
    chmod 440 "$SUDOERS_FILE"
    echo "✅ Правило добавлено в $SUDOERS_FILE"
else
    echo "❌ Ошибка синтаксиса. Правило не добавлено."
    exit 1
fi

echo "Готово. Теперь iptables можно вызывать через sudo без пароля."
