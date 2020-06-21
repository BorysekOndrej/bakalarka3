from werkzeug.security import generate_password_hash, check_password_hash
# werkzeug.security provides salting internally, which is amazing
import app
import config

jwt = app.jwt

import flask_jwt_extended

def hash_password(password: str) -> str:
    return generate_password_hash(str)


def check_password(known_password_hash: str, password_to_check: str) -> bool:
    return check_password_hash(known_password_hash, password_to_check)


@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    return False  # todo: token is not blacklisted


def get_user_id_from_jwt(jwt):
    return jwt["id"]


# based on explanation at https://stackoverflow.com/a/10724898/
def jwt_refresh_token_if_check_enabled():
    def decorator(func):
        if config.SlackConfig.check_refresh_cookie_on_callback_endpoint:
            return flask_jwt_extended.jwt_refresh_token_required(func)
        return func
    return decorator
