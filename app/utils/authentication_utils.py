from werkzeug.security import generate_password_hash, check_password_hash
# werkzeug.security provides salting internally, which is amazing
import app

jwt = app.jwt


def hash_password(password: str) -> str:
    return generate_password_hash(str)


def check_password(known_password_hash: str, password_to_check: str) -> bool:
    return check_password_hash(known_password_hash, password_to_check)


@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    return False  # todo: token is not blacklisted


def get_user_id_from_jwt(jwt):
    return jwt["id"]
