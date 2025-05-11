from flask import Flask, request, jsonify
import json
import os
import hashlib
from datetime import datetime, timedelta
import string
import random
import logging
import uuid  # Для генерации уникальных токенов

app = Flask(__name__)

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Пути к JSON-файлам
USERS_FILE = "users.json"
KEYS_FILE = "keys.json"
SESSIONS_FILE = "sessions.json"  # Новый файл для сессий

# Инициализация JSON-файлов
def init_files():
    if not os.path.exists(USERS_FILE):
        logger.info("Создание users.json")
        with open(USERS_FILE, 'w') as f:
            json.dump({}, f)
    if not os.path.exists(KEYS_FILE):
        logger.info("Создание keys.json")
        with open(KEYS_FILE, 'w') as f:
            json.dump({}, f)
    if not os.path.exists(SESSIONS_FILE):
        logger.info("Создание sessions.json")
        with open(SESSIONS_FILE, 'w') as f:
            json.dump({}, f)

# Загрузка данных из JSON
def load_json(file_path):
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Ошибка чтения {file_path}: {str(e)}")
        return {}

# Сохранение данных в JSON
def save_json(file_path, data):
    try:
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        logger.error(f"Ошибка записи {file_path}: {str(e)}")

# Хеширование пароля
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Проверка срока действия аккаунта
def is_account_valid(expiry_date):
    if expiry_date == "permanent":
        return True
    try:
        expiry = datetime.fromisoformat(expiry_date)
        return datetime.now() < expiry
    except ValueError:
        logger.error(f"Неверный формат expiry_date: {expiry_date}")
        return False

# Удаление истекших аккаунтов
def clean_expired_accounts():
    users = load_json(USERS_FILE)
    updated = False
    for username, data in list(users.items()):
        if not is_account_valid(data["expiry_date"]):
            del users[username]
            updated = True
            logger.info(f"Удален истекший аккаунт: {username}")
    if updated:
        save_json(USERS_FILE, users)

# Генерация ключа
def generate_key():
    return "SKY-" + ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(24))

# Генерация токена сессии
def generate_session_token():
    return str(uuid.uuid4())

# Проверка токена сессии
def is_session_valid(token):
    sessions = load_json(SESSIONS_FILE)
    if token in sessions:
        expiry = datetime.fromisoformat(sessions[token]["expiry"])
        if datetime.now() < expiry:
            return True
        else:
            del sessions[token]
            save_json(SESSIONS_FILE, sessions)
            logger.info(f"Удалена истекшая сессия: {token}")
    return False

# Маршрут для создания ключа
@app.route('/generate_key', methods=['POST'])
def generate_key_route():
    data = request.get_json()
    duration = data.get('duration')

    if duration not in [13, 30, "permanent"]:
        logger.warning(f"Неверный срок действия: {duration}")
        return jsonify({"error": "Неверный срок действия. Допустимые значения: 13, 30, permanent"}), 400

    keys = load_json(KEYS_FILE)
    key = generate_key()
    while key in keys:
        key = generate_key()
        logger.debug(f"Повтор ключа, генерируем новый: {key}")

    keys[key] = {
        "duration": duration,
        "used": False
    }
    save_json(KEYS_FILE, keys)
    logger.info(f"Сгенерирован ключ: {key}, срок: {duration}")

    return jsonify({"key": key, "duration": duration}), 200

# Маршрут для входа
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        logger.warning("Отсутствует имя пользователя или пароль")
        return jsonify({"error": "Имя пользователя и пароль обязательны"}), 400

    clean_expired_accounts()
    users = load_json(USERS_FILE)

    if username in users and users[username]["password"] == hash_password(password):
        if is_account_valid(users[username]["expiry_date"]):
            # Генерация токена сессии
            token = generate_session_token()
            sessions = load_json(SESSIONS_FILE)
            sessions[token] = {
                "username": username,
                "expiry": (datetime.now() + timedelta(minutes=10)).isoformat()
            }
            save_json(SESSIONS_FILE, sessions)
            logger.info(f"Успешный вход: {username}, выдан токен: {token}")
            return jsonify({"message": "Вход успешен", "session_token": token}), 200
        else:
            del users[username]
            save_json(USERS_FILE, users)
            logger.info(f"Удален истекший аккаунт при входе: {username}")
            return jsonify({"error": "Аккаунт истёк"}), 401
    logger.warning(f"Неуспешный вход: {username}")
    return jsonify({"error": "Неверное имя пользователя или пароль"}), 401

# Маршрут для проверки токена сессии
@app.route('/verify_session', methods=['POST'])
def verify_session():
    data = request.get_json()
    token = data.get('session_token')

    if not token:
        logger.warning("Отсутствует токен сессии")
        return jsonify({"error": "Токен сессии обязателен"}), 400

    if is_session_valid(token):
        sessions = load_json(SESSIONS_FILE)
        username = sessions[token]["username"]
        logger.info(f"Токен сессии валиден: {token}, пользователь: {username}")
        return jsonify({"message": "Сессия валидна", "username": username}), 200
    else:
        logger.warning(f"Невалидный или истекший токен: {token}")
        return jsonify({"error": "Невалидный или истекший токен"}), 401

# Маршрут для регистрации
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    key = data.get('key')
    username = data.get('username')
    password = data.get('password')

    if not key or not username or not password:
        logger.warning("Отсутствует ключ, имя пользователя или пароль")
        return jsonify({"error": "Ключ, имя пользователя и пароль обязательны"}), 400

    clean_expired_accounts()
    keys = load_json(KEYS_FILE)
    users = load_json(USERS_FILE)

    if key not in keys:
        logger.warning(f"Неверный ключ: {key}")
        return jsonify({"error": "Неверный ключ"}), 401

    if keys[key]["used"]:
        logger.warning(f"Ключ уже использован: {key}")
        return jsonify({"error": "Ключ уже использован"}), 401

    if username in users:
        logger.warning(f"Имя пользователя занято: {username}")
        return jsonify({"error": "Имя пользователя уже занято"}), 400

    duration = keys[key]["duration"]
    if duration == "permanent":
        expiry_date = "permanent"
    else:
        expiry_date = (datetime.now() + timedelta(days=duration)).isoformat()

    users[username] = {
        "password": hash_password(password),
        "expiry_date": expiry_date
    }
    keys[key]["used"] = True

    save_json(USERS_FILE, users)
    save_json(KEYS_FILE, keys)
    logger.info(f"Успешная регистрация: {username}, ключ: {key}")

    # Генерация токена сессии после регистрации
    token = generate_session_token()
    sessions = load_json(SESSIONS_FILE)
    sessions[token] = {
        "username": username,
        "expiry": (datetime.now() + timedelta(minutes=10)).isoformat()
    }
    save_json(SESSIONS_FILE, sessions)
    logger.info(f"Выдан токен сессии после регистрации: {token}")

    return jsonify({"message": "Регистрация успешна", "session_token": token}), 200

if __name__ == "__main__":
    init_files()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
