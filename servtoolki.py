from flask import Flask, request, jsonify
import json
import os
import hashlib
from datetime import datetime, timedelta
import string
import random

app = Flask(__name__)

# Пути к JSON-файлам
USERS_FILE = "users.json"
KEYS_FILE = "keys.json"

# Инициализация JSON-файлов
def init_files():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'w') as f:
            json.dump({}, f)
    if not os.path.exists(KEYS_FILE):
        with open(KEYS_FILE, 'w') as f:
            json.dump({}, f)

# Загрузка данных из JSON
def load_json(file_path):
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except:
        return {}

# Сохранение данных в JSON
def save_json(file_path, data):
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)

# Хеширование пароля
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Проверка срока действия аккаунта
def is_account_valid(expiry_date):
    if expiry_date == "permanent":
        return True
    expiry = datetime.fromisoformat(expiry_date)
    return datetime.now() < expiry

# Удаление истекших аккаунтов
def clean_expired_accounts():
    users = load_json(USERS_FILE)
    updated = False
    for username, data in list(users.items()):
        if not is_account_valid(data["expiry_date"]):
            del users[username]
            updated = True
    if updated:
        save_json(USERS_FILE, users)

# Генерация ключа по формуле
def generate_key():
    return "SKY-" + ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(24))

# Маршрут для создания ключа
@app.route('/generate_key', methods=['POST'])
def generate_key_route():
    data = request.get_json()
    duration = data.get('duration')

    if duration not in [13, 30, "permanent"]:
        return jsonify({"error": "Неверный срок действия. Допустимые значения: 13, 30, permanent"}), 400

    keys = load_json(KEYS_FILE)
    key = generate_key()
    while key in keys:  # Убедимся, что ключ уникален
        key = generate_key()

    keys[key] = {
        "duration": duration,
        "used": False
    }
    save_json(KEYS_FILE, keys)

    return jsonify({"key": key, "duration": duration}), 200

# Маршрут для входа
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Имя пользователя и пароль обязательны"}), 400

    clean_expired_accounts()
    users = load_json(USERS_FILE)

    if username in users and users[username]["password"] == hash_password(password):
        if is_account_valid(users[username]["expiry_date"]):
            return jsonify({"message": "Вход успешен"}), 200
        else:
            del users[username]
            save_json(USERS_FILE, users)
            return jsonify({"error": "Аккаунт истёк"}), 401
    return jsonify({"error": "Неверное имя пользователя или пароль"}), 401

# Маршрут для регистрации
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    key = data.get('key')
    username = data.get('username')
    password = data.get('password')

    if not key or not username or not password:
        return jsonify({"error": "Ключ, имя пользователя и пароль обязательны"}), 400

    clean_expired_accounts()
    keys = load_json(KEYS_FILE)
    users = load_json(USERS_FILE)

    if key not in keys:
        return jsonify({"error": "Неверный ключ"}), 401

    if keys[key]["used"]:
        return jsonify({"error": "Ключ уже использован"}), 401

    if username in users:
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

    return jsonify({"message": "Регистрация успешна"}), 200

if __name__ == "__main__":
    init_files()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
