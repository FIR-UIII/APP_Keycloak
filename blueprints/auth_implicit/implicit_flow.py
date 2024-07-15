from flask import redirect, render_template, session, url_for, Blueprint, request
from os import environ as env
import requests

auth_implicit_bp = Blueprint("auth_implicit", __name__, template_folder="templates")

CLIENT_ID = env.get("CLIENT_ID_IMPLICIT")   
REALM = env.get("REALM")
KEYCLOAK_URL = env.get("KEYCLOAK_URL")


@auth_implicit_bp.route("/login_implicit_page")
def login_implicit_page():
    '''Функция отображает страницу для пользователя'''
    return render_template("login_implicit_page.html")

@auth_implicit_bp.route("/login_implicit")
def login_implicit():
    '''Функция производит аутентификацию пользователя'''
    authorization_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/auth"
    params = {
        "response_type": "id_token token",  # Сразу запрашиваем токен без auth_code
        "client_id": CLIENT_ID,
        "redirect_uri": "http://localhost:8000/callback_implicit",
        "scope": "openid email",
        "state": "af0ifjsldkj", #TODO нужно сделать генератор
        "nonce": "0S6_WzA2Mj",  #TODO нужно сделать генератор
    }

    return redirect(f"{authorization_url}?{requests.compat.urlencode(params)}")


@auth_implicit_bp.route("/callback_implicit")
def callback_implicit():
    query = request.query_string.decode("utf-8").split("&")
    print(query)
    # session['id_token'] = session.get("id_token") # для использования в функции logout_auth()
    return redirect(url_for("auth_implicit.login_implicit_page"))