#!/usr/bin/env bash
#
# VPN-клиент СКЗИ (ГОСТ) — автоматический запуск для Linux / macOS.
#
# Делает всё за вас:
#   1. находит Python 3
#   2. устанавливает зависимости (PyQt5; pygost уже встроен в проект)
#   3. генерирует тестовые сертификаты (если их нет)
#   4. запускает тестовый сервер в фоне
#   5. открывает графический интерфейс
#
# Запуск:  ./run.sh    (или:  bash run.sh)
#
set -e
cd "$(dirname "$0")"

echo "============================================================"
echo "  VPN-клиент СКЗИ (ГОСТ) — автоматический запуск"
echo "============================================================"
echo

# --- Шаг 1: поиск Python ---
if command -v python3 >/dev/null 2>&1; then
    PY=python3
elif command -v python >/dev/null 2>&1; then
    PY=python
else
    echo "[ОШИБКА] Python не найден."
    echo "Установите Python 3.10+:  sudo apt install python3 python3-pip"
    exit 1
fi
echo "[1/4] Python: $($PY --version)"
echo

# --- Шаг 2: установка зависимостей ---
echo "[2/4] Установка зависимостей (PyQt5)..."
$PY -m pip install --quiet --disable-pip-version-check -r requirements.txt
echo "    Готово."
echo

# --- Шаг 3: генерация сертификатов ---
echo "[3/4] Проверка сертификатов..."
if [ ! -f certs/client.der ]; then
    echo "    Генерация тестовых сертификатов..."
    $PY -m utils.cert_gen
else
    echo "    Сертификаты уже существуют."
fi
echo

# --- Шаг 4: запуск сервера (в фоне) и GUI ---
echo "[4/4] Запуск тестового сервера и интерфейса..."
$PY server.py &
SERVER_PID=$!
echo "    Сервер запущен (PID $SERVER_PID)."

# Останавливаем сервер автоматически при выходе из GUI
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT

sleep 2
echo "    Открытие графического интерфейса..."
echo
$PY vpn_gui.py

echo
echo "Работа завершена, сервер остановлен."
