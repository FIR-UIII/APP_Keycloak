from flask import jsonify, Blueprint, render_template, session
import requests
import jwt
from os import environ as env

auth_client_credentials_bp = Blueprint("auth_client_credentials", __name__, template_folder="templates")

CLIENT_ID = env.get('CLIENT_ID_PASSWORD')
CLIENT_SECRET = env.get('CLIENT_SECRET_PASSWORD')
KEYCLOAK_TOKEN_URL = 'http://localhost:8080/realms/web_app/protocol/openid-connect/token'

data = {
        'grant_type':'client_credentials',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'scope':'openid email'
        }

@auth_client_credentials_bp.route('/login_client_credentials')
def login_client_credentials_page():
    return render_template("login_client_credentials.html", data=data)

@auth_client_credentials_bp.route('/get_token', methods=['GET'])
def get_token():
    """
    Obtain an access token from Keycloak using the client credentials flow.
    """
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    response = requests.post(KEYCLOAK_TOKEN_URL, data=data, headers=headers)
    # помещает в сессию flask токен для дальнейшего использования при переходе на защищенный эндпоинт
    session['access_token'] = response.json()['access_token']
    session['id_token'] = response.json()['id_token']
    # декодируем токен для вывода на фронтальный компонент
    decoded_access_token = jwt.decode(session['access_token'], options={"verify_signature": False})
    decoded_id_token = jwt.decode(session['id_token'], options={"verify_signature": False})
    if response.status_code == 200:
        return render_template("login_client_credentials.html", decoded_access_token=decoded_access_token, decoded_id_token=decoded_id_token, data=data)
    else:
        return jsonify({'error': 'Failed to obtain token', 'status_code': response.status_code})
