from flask import request, redirect, render_template, Blueprint, session
from os import environ as env
import requests
import base64
import hashlib
import secrets
import jwt

auth_code_pkce_bp = Blueprint('auth_code_pkce', __name__, template_folder='templates')

KEYCLOAK_URL = env.get('KEYCLOAK_URL')
REALM = env.get("REALM")
CLIENT_ID = env.get("CLIENT_ID_AUTH_CODE_PKCE")
REDIRECT_URI = 'http://localhost:8000/callback_auth_pkce'

def generate_code_verifier():
    """Функция создает сессионное случайное значение сode_verifier в base64"""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode('utf-8')

def generate_code_challenge(code_verifier):
    """Функция создает сессионное значение code challenge на основании входящего параметра code verifier в base64"""
    digest = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('utf-8')
    if code_challenge:
        print(f'{code_challenge} [+] code_challenge успешно сгенирован')
    else:
        print('[-] Не удалось сгенерировать code_challenge')
        return "Error generating code_challenge", 500
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('utf-8')

@auth_code_pkce_bp.route('/auth_code_PKCE')
def auth_code_PKCE():
    """Функция отображает страницу для ввода логина и пароля"""
    return render_template('auth_code_PKCE.html')

@auth_code_pkce_bp.route('/login_auth_code_pkce')
def login_auth_code():
    '''Функция аутентификации пользователя в IAM'''
    print('[+] Старт аутентификации')
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    session['code_verifier'] = code_verifier
    state = secrets.token_urlsafe(16)  # Генерация случайного значения state
    session['state'] = state
    print(session['state'])

    auth_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/auth?client_id={CLIENT_ID}&response_type=code&scope=openid&redirect_uri={REDIRECT_URI}&state={state}&code_challenge={code_challenge}&code_challenge_method=S256"
    
    return redirect(auth_url)

@auth_code_pkce_bp.route('/callback_auth_pkce')
def callback_auth_pkce():
    '''Функция принимает ответ от IAM после аутентифкации клиента с параметрами auth_code'''
    session['code'] = request.args.get('code')
    print(session['code'])
    state = request.args.get('state')
    print(state)
    session_state = session.get('state')
    print(session_state)

    # Проверка для снижения риска атаки CSRF
    if not state or state != session_state:
        return "State mismatch or missing state parameter.", 400

    # Проверка code_verifier в ответе
    code_verifier = session.get('code_verifier')
    if not code_verifier:
        return "Code verifier not found in session.", 400
    
    return render_template('auth_code_PKCE.html', code=session['code'], state=state, code_verifier=code_verifier)

@auth_code_pkce_bp.route('/token_auth_code_pkce')
def token_auth_code_pkce():
    '''Функция обменивает полученный ранее auth_code на токены досткпа (access_token и др.)'''
    token_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"
    code_verifier = session.get('code_verifier')
    data = {
        'grant_type': 'authorization_code',
        'client_id': CLIENT_ID,
        'code': session['code'],
        'redirect_uri': REDIRECT_URI,
        'code_verifier': code_verifier
    }
    response = requests.post(token_url, data=data)

    # сохраняем и парсим токены по необходимым переменным
    tokens = response.json()
    session['access_token'] = tokens['access_token']
    session['id_token'] = tokens['id_token']
    r_token = tokens['refresh_token']
    # Декодируем JWT токены без проверки подписи для вывода на фронтальный компонент
    decoded_access_token = jwt.decode(session['access_token'], options={"verify_signature": False})
    decoded_id_token = jwt.decode(session['id_token'], options={"verify_signature": False})
    decoded_refresh_token = jwt.decode(r_token, options={"verify_signature": False})
    return render_template('auth_code_PKCE.html', r_token=decoded_refresh_token, access_token=decoded_access_token, id_token=decoded_id_token, code=session.get("code"), state=session.get('state'), code_verifier=code_verifier)

@auth_code_pkce_bp.route("/logout_auth_pkce")
def logout_auth_pkce():
    '''Функция выхода пользователя из сессии на IAM. Очищает и завершает все текущие сессии и возвращает пользователя на основную страницу с использованием метода id_token_hint'''
    id_token = session['id_token']
    print(id_token)
    # проверка наличия токена в сессии flask
    if not id_token:
        return "id_token не был передан", 400

    logout_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/logout?client_id={CLIENT_ID}&id_token_hint={id_token}"
    response = requests.get(logout_url)

    if response.status_code == 200:
        session.clear()
        return redirect("/auth_code_PKCE")
    else:
        return "Ошибка при выходе из сессии пользователя", 500