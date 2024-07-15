import json
from flask import redirect, render_template, session, url_for, request, Blueprint
import requests
from os import environ as env

ropc_bp = Blueprint("ropc", __name__, template_folder="templates")

# Keycloak server details
KEYCLOAK_URL = env.get('KEYCLOAK_URL')
REALM = env.get('REALM')
CLIENT_ID = env.get('CLIENT_ID_ROPC')

@ropc_bp.route("/login_ropc", methods=["GET", "POST"])
def login_ropc():
    if request.method == "POST":
        username = request.form["username"] # информация с html id="username"
        password = request.form["password"] # информация с html id="password"
        token_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"
        data = {
            "client_id": CLIENT_ID,
            "username": username,
            "password": password,
            "grant_type": "password",
            "scope": "openid profile email"
            }
        
        response = requests.post(token_url, data=data)
            
        if response.status_code == 200:
            token_info = response.json()
            session["user"] = token_info
            return redirect(url_for("ropc.user_info"))
        
        else:
            return redirect(url_for("ropc.failed_login"))
        
    return render_template("login_ropc.html")

@ropc_bp.route("/user_info")
def user_info():
    if "user" in session:
        user_info = session["user"]
        session['id_token'] = user_info["id_token"]
        session['access_token'] = user_info["access_token"]
        print(session['access_token'])
        return render_template("user_info.html", user_info=json.dumps(user_info, indent=4))
    return redirect(url_for("ropc.login_ropc"))

@ropc_bp.route("/failed_login")
def failed_login():
    return render_template("failed_login.html")
