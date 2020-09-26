from flask import Flask, request, jsonify, g, abort # Импортируем библиотеки для работы Flaskimport json # Модуль для создания json
from flask_mail import Mail, Message
from flask_httpauth import HTTPBasicAuth # Импортируем библиотеку для автоматизации авторизации пользователя
import os # Модуль для взаимодействия с ОС
import secrets # Модуль для генерации случайных симоволов
import string # Модуль для операций со строками
import base64 # Модуль для шифрования/дешифрования в base64
import json # Модуль для создания json
import hashlib


def auth_decorator(func):
    def wrapper():
        try:
            request_token = request.headers.get("Authorization").split()
        except Exception as e:
            response = jsonify({"Error": str(e)})
            response.status_code = 401
            return response
        with open("user.json") as f:
            user_token = json.load(f)["token"]
        if request_token[0] == "Bearer" and request_token[1] == user_token:
            return func()
        else:
            response = jsonify({"status" : 401 })
            response.status_code = 401
            return response
    wrapper.__name__ = func.__name__
    return wrapper



app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
mail = Mail(app)

app.config['MAIL_SERVER'] = "smtp.mail.ru"
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'marina.test.vasileva@list.ru'
app.config['MAIL_DEFAULT_SENDER'] = 'marina.test.vasileva@list.ru'
app.config["MAIL_PASSWORD"] = 'U3toIOU*oad1'

id = 1

class User:
    def __init__(self, **kargs):
        self.id = kargs["id"]
        self.email = kargs["email"]
        self.password = kargs["password"]
        self.token = kargs["token"]
        self.balance = 100

    def verify_password(self, password):
        return hashlib.md5(password.encode()).hexdigest() == self.password


@app.route('/register', methods = ['POST'])
def new_user():
    email = request.json.get('email')
    password = request.json.get('password')
    #Если не указан эмейл или пароль, возвращается ошибка
    if email is None or password is None:
        abort(400) 
    user = User(id = id, email = email, password=hashlib.md5(password.encode()).hexdigest(), token=generate_token())
    send_confirmation_letter(user)
    with open("user.json", "w") as f:
        json.dump(user.__dict__, f)
    return jsonify({"id": user.id, 'email': user.email, "status" : 200 })

@app.route('/login', methods = ['POST'])
def login():
    email = request.json.get('email')
    password = request.json.get('password')
    user_obj = load_user()
    if user_obj.verify_password(password):
        return jsonify({"token": user_obj.token, "status": 200})
    else:
        return jsonify({"status": 401})

@app.route('/users/edit', methods=['POST'])
@auth_decorator
def edit_user():
    try:
        user = load_user()
        user.surname = request.json.get('surname')
        user.name = request.json.get('name')
        user.patronym = request.json.get('patronym')
        user.phone = request.json.get('phone')
        save_user(user)
        return jsonify({"status": 200})
    except Exception as e:
        response = jsonify({"error": str(e)})
        response.status_code = 500
        return response
    
@app.route('/credentials/edit', methods=["POST"])
@auth_decorator
def edit_credentials():
    new_email = request.json.get('email')
    new_password = request.json.get('password')

    try:
        user = load_user()
        user.email = new_email if new_email is not None else user.email
        user.password = hashlib.md5(new_password.encode()).hexdigest() if new_password is not None else user.password
        save_user(user)
        response = jsonify({"status": 200, "email": user.email, "pass": user.password})
    except Exception as e:
        response = jsonify({"error": str(e)})
    return response


@app.route('/calls/get')
@auth_decorator
def get_calls():
    page =  request.json.get('paginate')["page"]
    per_page =  request.json.get('paginate')["per_page"]
    with open('calls.json') as f:
        calls = json.load(f)
    calls_to_send = []
    for i in range((page - 1) * per_page, (page * per_page)):
        calls_to_send.append(calls[i])
    response = jsonify({"calls": calls_to_send})
    return response

@app.route('/calls/delete', methods = ["POST"])
@auth_decorator
def detele_call():
    with open('calls.json') as f:
        calls = json.load(f)
    calls_to_delete = request.json.get("callsToDelete")
    for call in calls:
        print(call["callId"])
        if int(call["callId"]) in calls_to_delete:
            calls.pop(calls.index(call))
    with open('calls.json', 'w') as f:
        json.dump(calls, f)
    return jsonify({"status": 200})
        


@app.route('/test')
@auth_decorator
def test():
    return jsonify({"response": request.authorization})

def generate_token():
    return ''.join(secrets.choice(string.ascii_uppercase + string.digits) for i in range(20)) 

def load_user():
    with open('user.json') as f:
        user = json.load(f)
    user_obj = User(**user)
    return user_obj

def save_user(user):
    with open("user.json", "w") as f:
        json.dump(user.__dict__, f)

def send_confirmation_letter(user):
    msg = Message("Подтвердите регистрацию", recipients=[user.email])
    msg.body = "Привет"
    mail.send(msg)

if __name__ == '__main__':
    app.run(debug=True)
