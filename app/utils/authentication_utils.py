from typing import Optional

import flask_jwt_extended
from flask_jwt_extended import JWTManager
from werkzeug.security import generate_password_hash, check_password_hash
# werkzeug.security provides salting internally, which is amazing

import config

jwt_instance = JWTManager()


def hash_password(password: str) -> str:
    return generate_password_hash(str)


def check_password(known_password_hash: str, password_to_check: str) -> bool:
    return check_password_hash(known_password_hash, password_to_check)


@jwt_instance.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    return False  # todo: token is not blacklisted


def get_user_id_from_jwt(jwt) -> int:
    return jwt["id"]


def get_user_id_from_current_jwt() -> Optional[int]:
    try:
        user_jwt = flask_jwt_extended.get_jwt_identity()
        user_id = get_user_id_from_jwt(user_jwt)
        return user_id
    except:
        return None


# based on explanation at https://stackoverflow.com/a/10724898/
def jwt_refresh_token_if_check_enabled(condition):
    def decorator(func):
        if condition:
            return flask_jwt_extended.jwt_refresh_token_required(func)
        return func
    return decorator
