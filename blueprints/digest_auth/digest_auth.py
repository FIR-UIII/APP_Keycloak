from flask import Blueprint
from flask_httpauth import HTTPDigestAuth

digest_auth_bp = Blueprint("digest_auth", __name__, template_folder="templates")

auth_app = HTTPDigestAuth()

users = {
    "test": "test",
    "admin": "admin"
}

@auth_app.get_password
def get_pw(username):
    if username in users:
        return users.get(username)
    return None

@digest_auth_bp.route('/digest_auth')
@auth_app.login_required
def digest_auth_page():
    return "Hello, {}!".format(auth_app.username())
