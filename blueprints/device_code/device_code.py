from flask import render_template, Blueprint, jsonify, session, redirect
import requests
from os import environ as env


# Blueprint for the device code flow
device_code_bp = Blueprint('device_flow', __name__, template_folder='templates')

KEYCLOAK_URL = env.get('KEYCLOAK_URL')
REALM = env.get('REALM')
CLIENT_ID = env.get('CLIENT_ID_DEVICE')

@device_code_bp.route('/login_device_code', methods=['GET', 'POST'])
def home():
    return render_template('login_device_code.html')

@device_code_bp.route('/get-device-code', methods=['POST'])
def get_device_code():
    url = f'{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/auth/device'
    data = {
        'client_id': CLIENT_ID,
        }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
        }
    response = requests.post(url, data=data, headers=headers)
    
    if response.status_code == 200:
        session['device_code_data'] = response.json()
        return jsonify(response.json())
    else:
        return jsonify({'error': 'Failed to obtain device code'}), response.status_code

@device_code_bp.route('/user-access-grand', methods=['GET'])
def user_access():
    device_code_data = session.get('device_code_data')
    if device_code_data:
        verification_uri_complete = device_code_data.get('verification_uri_complete')
        if verification_uri_complete:
            return redirect(verification_uri_complete)
    return "Device code data is missing or incomplete", 400

@device_code_bp.route('/get-token', methods=['POST'])
def get_token():
    device_code_data = session.get('device_code_data')
    if not device_code_data:
        return jsonify({'error': 'Device code data not found in session'}), 400
    url = f'{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token'
    data = {
        'client_id': CLIENT_ID,
        'device_code': device_code_data.get('device_code'),
        'grant_type': 'urn:ietf:params:oauth:grant-type:device_code'
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    response = requests.post(url, data=data, headers=headers)

    session['access_token'] = response.json()['access_token'] # парсим и сохраняем токен для проверки на защищенной странице
    session['refresh_token'] = response.json()['refresh_token'] # парсим refresh_token sдля использования в функции logout_device_code

    if response.status_code == 200:
        return jsonify(response.json())
    else:
        return jsonify({'error': 'Failed to obtain access token'}), response.status_code
    
@device_code_bp.route("/logout_device_code")
def logout_device_code():
    '''Функция выхода пользователя из сессии на IAM. Очищает и завершает все текущие сессии 
    и возвращает пользователя на основную страницу с использованием метода id_token_hint'''
    refresh_token = session['refresh_token']
    redirect_uri = 'http://localhost:8000/login_device_code'
    # проверка наличия токена в сессии flask
    if not refresh_token:
        return "refresh_token не был передан", 400

    logout_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/logout?client_id={CLIENT_ID}&refresh_token={refresh_token},redirect_uri={redirect_uri}"
    response = requests.get(logout_url)
    if response.status_code == 200:
        session.clear()
        return redirect(logout_url)
    else:
        return "Ошибка при выходе из сессии пользователя", 500
    