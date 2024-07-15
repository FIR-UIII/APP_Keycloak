import json
from flask import redirect, render_template, session, url_for, request, Blueprint
import requests
import jwt
from os import environ as env

REALM = env.get("REALM")
CLIENT_ID = env.get("CLIENT_ID_AUTH_CODE")
KEYCLOAK_URL = env.get("KEYCLOAK_URL")
CLIENT_SECRET = env.get("CLIENT_SECRET_AUTH_CODE")


def auth_code_bp(oauth):
    auth_code_bp = Blueprint("auth_code", __name__, template_folder="templates")

    # TODO: определить место хранения секретов в отдельном хранилище
    oauth.register(
        "auth0",
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        client_kwargs={
            "scope": "openid profile email",
        },
        server_metadata_url=f'{KEYCLOAK_URL}/realms/{REALM}/.well-known/openid-configuration'
    )

    @auth_code_bp.route("/login_auth_code")
    def page_auth_code():
        auth_code = session.get("auth_code", "Authorization Code не был получен")
        access_token = session.get("a_token", "Access Token не был получен")
        id_token = session.get("id_token", "ID Token не был получен")
        refresh_token = session.get("refresh_token", "Refresh Token не был получен")
        return render_template("/login_auth.html", session=session.get('user'), auth_code=auth_code, access_token=json.dumps(session.get('user'), indent=4), id_t=id_token, r_token=refresh_token, a_token=access_token)
    
    @auth_code_bp.route("/login_auth")
    def login_auth():
        return oauth.auth0.authorize_redirect(
            redirect_uri=url_for("auth_code.callback_auth", _external=True)
        )

    @auth_code_bp.route("/callback_auth", methods=["GET", "POST"])
    def callback_auth():
        code = request.args.get('code')
        token = oauth.auth0.authorize_access_token()
        session["user"] = token
        session["auth_code"] = code
        session["access_token"] = token.get("access_token")
        session["a_token"] = jwt.decode(token.get("access_token"), options={"verify_signature": False})
        session["id_token"] = jwt.decode(token.get("id_token"), options={"verify_signature": False})
        session["refresh_token"] = jwt.decode(token.get("refresh_token"), options={"verify_signature": False})
        session["r_token"] = token.get("refresh_token") # для использования в функции logout_auth() нужен сырой токен
        return redirect("login_auth_code")
    
    @auth_code_bp.route("/logout_auth")
    def logout_auth():
        requests.post(f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/logout", data={'client_id': CLIENT_ID, 'client_secret': CLIENT_SECRET, 'refresh_token': session["r_token"]})
        session.clear()
        return redirect("/login_auth_code") 
    

    return auth_code_bp
