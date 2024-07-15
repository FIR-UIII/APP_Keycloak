from flask import Blueprint
from flask_httpauth import HTTPTokenAuth

token_auth_bp = Blueprint('token_auth', __name__, template_folder="templates")

auth = HTTPTokenAuth(scheme='Bearer')

tokens = {
    "admin": "admin",
    "secret-token-2": "susan"
}

@auth.verify_token
def verify_token(token):
    if token in tokens:
        return tokens[token]

@token_auth_bp.route('/token_auth')
@auth.login_required
def token_auth_page():
    return "Hello, {}!".format(auth.current_user())