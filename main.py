from os import environ as env
from authlib.integrations.flask_client import OAuth
import jwt
import jwt.algorithms
import requests
from flask import Flask, render_template, request, session
from blueprints.auth_code.auth_code import auth_code_bp
from blueprints.auth_implicit.implicit_flow import auth_implicit_bp
from blueprints.client_credentials.client_credentials import auth_client_credentials_bp
from blueprints.ROPC.ropc import ropc_bp
from blueprints.device_code.device_code import device_code_bp
from blueprints.auth_code_pkce.auth_code_pkce import auth_code_pkce_bp
from blueprints.basic_auth.basic_auth import basic_auth_bp
from blueprints.digest_auth.digest_auth import digest_auth_bp
from blueprints.token_auth.token_auth import token_auth_bp
from dotenv import load_dotenv

load_dotenv()

# configuration http://localhost:8080/realms/web_app/.well-known/openid-configuration
app = Flask(__name__)

KEYCLOAK_URL = env.get("KEYCLOAK_URL")
REALM = env.get("REALM")
app.config['BASIC_AUTH_USERNAME'] = env.get('BASIC_AUTH_USERNAME')
app.config['BASIC_AUTH_PASSWORD'] = env.get('BASIC_AUTH_PASSWORD')
app.config['BASIC_AUTH_FORCE'] = True
app.config['BASIC_AUTH_REALM'] = env.get('BASIC_AUTH_REALM')
app.secret_key = env.get("APP_SECRET_KEY") # проверить нужна ли эта строка? при миграции blueprint могли отвалиться зависимости


oauth = OAuth(app)
# blueprints/auth_code/auth_code.py > Authorization code flow
app.register_blueprint(auth_code_bp(oauth))
# blueprints/auth_implicit/implicit_flow.py > Implicit flow
app.register_blueprint(auth_implicit_bp)
# blueprints/client_credentials/client_credentials.py > Client credentials flow
app.register_blueprint(auth_client_credentials_bp)
# blueprints/ROPC/ropc.py > Password flow
app.register_blueprint(ropc_bp)
# blueprints/device_code/device_code.py > Device code flow
app.register_blueprint(device_code_bp)
# blueprints/auth_code_pkce/auth_code_pkce.py > Authorization code flow with PKCE
app.register_blueprint(auth_code_pkce_bp)
# blueprints/basic_auth/basic_auth.py > Basic
app.register_blueprint(basic_auth_bp)
# blueprints/digest_auth/digest_auth.py > Digest
app.register_blueprint(digest_auth_bp)
# blueprints/token_auth/token_auth.py > Token
app.register_blueprint(token_auth_bp)

@app.route("/")
def home():
    return render_template("home.html")

@app.route('/load_info')
def load_info():
    """Функция отображает информацию о реалме"""
    pass
    # url = f'http://localhost/realms/web_app/.well-known/openid-configuration'
    # get_data = requests.get(url)
    # info = get_data.text
    # return render_template('home.html', realm_info=info)

@app.route('/clear_session')
def clear_session():
    session.clear()
    return render_template("home.html")

@app.route('/protected_page')
def protected_page():
    '''Защищаемая страница с целью перехода на нее после успешной аутентификации и получения доступа по access token. 
    Для успешного отображения проводится валидация токена'''
    public_key = get_kc_public_key()
    # выгружаем токен из сессии внутри flask, чтобы не передавать токен через URL
    access_token = session.get('access_token')
    # валидация токена и обработка ошибок при парсинге токена
    if access_token is None:
        return render_template("token_missing.html")
    else:
        try:
            decoded_token = jwt.decode(access_token, public_key, audience='account', algorithms=["RS256"])
            return render_template('protected_page.html', decoded_token=decoded_token)
        except access_token is None:
            return "Access token not found in the session", 401
        except jwt.ExpiredSignatureError: 
            return "Expired signature", 401
        except jwt.InvalidAudienceError:
            return "Invalid audience", 401
        except jwt.PyJWTError as e:
            return "JWT error: " + str(e), 401
        except Exception as e:
            return "Error: " + str(e), 401

def check_token(access_token):
    if session['access_token'] is None:
        return "Access token not found in the session", 401
    else:
        return 1


def get_kc_public_key():
    '''Функция скачивает сертификат и извлекает публичный ключ для проверки JWT токенов'''
    cert_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/certs"
    responce = requests.get(cert_url)
    public_key_info = responce.json()["keys"][0]
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(public_key_info)
    return public_key

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=env.get("PORT", 8000), debug=True)