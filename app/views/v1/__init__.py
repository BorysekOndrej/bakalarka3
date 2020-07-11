from flask import Blueprint

bp = Blueprint('apiV1', __name__)

from . import part1, notification_settings, auth
