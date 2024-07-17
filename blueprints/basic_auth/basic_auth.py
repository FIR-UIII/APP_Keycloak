from flask import Blueprint, render_template, redirect, url_for, session
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash


basic_auth_bp = Blueprint("basic_auth", __name__, template_folder="templates")

auth = HTTPBasicAuth()

users = {
    "test": generate_password_hash("test"),
    "admin": generate_password_hash("admin")
}

@auth.verify_password
# декоратор проверки правльности пароля и логина. Выводит имя пользователя 
def verify_password(username, password):
    if username in users and \
            check_password_hash(users.get(username), password):
        return username

@basic_auth_bp.route('/basic_auth')
# отображает страницу для пользователя
def basic_auth_page():
    return render_template('/basic_auth_page.html')

@basic_auth_bp.route('/login_basic_auth')
# функция ввода логина и пароля по схеме basic
@auth.login_required
def index():
    session['user'] = auth.current_user()
    return redirect(url_for("basic_auth.login_page"))

@basic_auth_bp.route('/basic_auth_login_successeful')
# отображает пользователю страницу после успешной аутентификации
def login_page():
    user = session['user']
    return render_template('/login_successeful.html', user=user)

@basic_auth_bp.route('/login_auth_login_failed')
# отображает пользователю страницу после неудачной аутентификации
def login_failed():
    return render_template('/login_failed.html')

@basic_auth_bp.route('/logout_basic_auth')
# функция выхода из системы по схеме basic
def logout():
    session.clear() #  нет очистки пользовательских кук.
    return redirect(url_for("basic_auth.basic_auth_page"))