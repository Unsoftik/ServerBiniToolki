from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import random
import string
import json
import os

app = Flask(__name__)

# Путь к JSON-файлу для хранения данных
DATA_FILE = "auth_data.json"
# Пин-код для генерации ключей
PIN_CODE = "1312"

# Инициализация данных
def init_data():
    if not os.path.exists(DATA_FILE):
        data = {"users": [], "keys": []}
        with open(DATA_FILE, 'w') as f:
            json.dump(data, f, indent=4)

# Загрузка данных из JSON
def load_data():
    with open(DATA_FILE, 'r') as f:
        return json.load(f)

# Сохранение данных в JSON
def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)

# Очистка просроченных аккаунтов
def clean_expired_accounts():
    data = load_data()
    current_time = datetime.now()
    data["users"] = [
        user for user in data["users"]
        if not user["expires_at"] or datetime.strptime(user["expires_at"], '%Y-%m-%d %H:%M:%S.%f') > current_time
    ]
    save_data(data)

@app.route('/generate_key', methods=['GET', 'POST'])
def generate_key():
    if request.method == 'POST':
        data = request.get_json()
        pin = data.get('pin')
        duration_days = data.get('duration_days')
    elif request.method == 'GET':
        pin = request.args.get('pin')
        duration_days = request.args.get('duration_days')
    data = request.get_json()
    pin = data.get('pin')
    duration_days = data.get('duration_days')

    if pin != PIN_CODE:
        return jsonify({"error": "Неверный пин-код"}), 403

    if duration_days not in [0, 13, 30]:
        return jsonify({"error": "Недопустимый срок действия ключа"}), 400

    key = "SKY-" + ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(24))
    auth_data = load_data()
    auth_data["keys"].append({
        "key": key,
        "duration_days": duration_days,
        "used": False
    })
    save_data(auth_data)

    return jsonify({"key": key, "duration_days": duration_days}), 200

# Регистрация
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    key = data.get('key')
    username = data.get('username')
    password = data.get('password')

    if not key or not username or not password:
        return jsonify({"error": "Необходимы ключ, имя пользователя и пароль"}), 400

    clean_expired_accounts()
    auth_data = load_data()

    # Проверка ключа
    key_data = next((k for k in auth_data["keys"] if k["key"] == key), None)
    if not key_data:
        return jsonify({"error": "Недействительный ключ"}), 400
    if key_data["used"]:
        return jsonify({"error": "Ключ уже использован"}), 400

    # Проверка уникальности имени пользователя
    if any(user["username"] == username for user in auth_data["users"]):
        return jsonify({"error": "Имя пользователя уже занято"}), 400

    # Вычисление срока действия
    duration_days = key_data["duration_days"]
    expires_at = None if duration_days == 0 else (datetime.now() + timedelta(days=duration_days)).strftime('%Y-%m-%d %H:%M:%S.%f')

    # Регистрация пользователя
    auth_data["users"].append({
        "username": username,
        "password": generate_password_hash(password),
        "created_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'),
        "expires_at": expires_at
    })

    # Отметка ключа как использованного
    key_data["used"] = True
    save_data(auth_data)

    return jsonify({"message": "Регистрация успешна"}), 200

# Логин
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Необходимы имя пользователя и пароль"}), 400

    clean_expired_accounts()
    auth_data = load_data()

    user = next((u for u in auth_data["users"] if u["username"] == username), None)
    if not user:
        return jsonify({"error": "Пользователь не найден"}), 404

    if user["expires_at"] and datetime.strptime(user["expires_at"], '%Y-%m-%d %H:%M:%S.%f') < datetime.now():
        auth_data["users"] = [u for u in auth_data["users"] if u["username"] != username]
        save_data(auth_data)
        return jsonify({"error": "Аккаунт просрочен и удален"}), 403

    if check_password_hash(user["password"], password):
        return jsonify({"message": "Вход успешен"}), 200
    else:
        return jsonify({"error": "Неверный пароль"}), 401

if __name__ == "__main__":
    init_data()
    app.run(host='0.0.0.0', port=5000)
