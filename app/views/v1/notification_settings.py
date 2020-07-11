import json
import jsons
from typing import Optional

from app.utils.notifications.actions import set_notification_settings_raw_single_target
from app.utils.notifications.user_preferences import get_effective_notification_settings, \
    get_effective_active_notification_settings, load_preferences_from_string, \
    CONNECTION_DB_MODELS_TYPES


from . import bp

from flask import request, jsonify
from loguru import logger

import flask_jwt_extended

import app.db_models as db_models
import app.utils.authentication_utils as authentication_utils
import app.actions as actions


@bp.route('/notification_settings_raw', methods=['GET'])
@bp.route('/notification_settings_raw/undefined', methods=['GET'])
@bp.route('/notification_settings_raw/null', methods=['GET'])
@bp.route('/notification_settings_raw/<int:target_id>', methods=['GET'])
@flask_jwt_extended.jwt_required
def api_notification_settings_raw(user_id=None, target_id=None):
    if user_id is None:
        user_id = authentication_utils.get_user_id_from_current_jwt()

    if target_id is not None and not actions.can_user_get_target_definition_by_id(target_id, user_id):
        return "Target either doesn't exist or user is not allowed to see it.", 401

    res = db_models.db.session \
        .query(db_models.ConnectionStatusOverrides) \
        .filter(db_models.ConnectionStatusOverrides.user_id == user_id) \
        .filter(db_models.ConnectionStatusOverrides.target_id == target_id) \
        .first()

    pref = res.preferences if res else ""
    res2 = load_preferences_from_string(pref)

    return jsons.dumps(res2), 200


@bp.route('/notification_settings_raw', methods=['POST'])
@bp.route('/notification_settings_raw/undefined', methods=['POST'])
@bp.route('/notification_settings_raw/null', methods=['POST'])
@bp.route('/notification_settings_raw/<int:target_id>', methods=['POST'])
@flask_jwt_extended.jwt_required
def api_set_notification_settings_raw(user_id: Optional[int] = None, target_id: Optional[int] = None):
    if user_id is None:
        user_id = authentication_utils.get_user_id_from_current_jwt()

    if target_id is not None and not actions.can_user_get_target_definition_by_id(target_id, user_id):
        return "Target either doesn't exist or user is not allowed to see it.", 401

    data = json.loads(request.data)
    ok = set_notification_settings_raw_single_target(user_id, target_id, data)
    if ok:
        return api_notification_settings_raw(user_id, target_id)
    return "fail", 400


@bp.route('/notification_settings', methods=['GET'])
@bp.route('/notification_settings/undefined', methods=['GET'])
@bp.route('/notification_settings/null', methods=['GET'])
@bp.route('/notification_settings/<int:target_id>', methods=['GET'])
@flask_jwt_extended.jwt_required
def api_notification_settings(user_id=None, target_id=None):
    if user_id is None:
        user_id = authentication_utils.get_user_id_from_current_jwt()

    if target_id is not None and not actions.can_user_get_target_definition_by_id(target_id, user_id):
        return "Target either doesn't exist or user is not allowed to see it.", 401

    connection_lists = get_effective_notification_settings(user_id, target_id)
    return jsonify(connection_lists)


@bp.route('/active_notification_settings', methods=['GET'])
@bp.route('/active_notification_settings/undefined', methods=['GET'])
@bp.route('/active_notification_settings/null', methods=['GET'])
@bp.route('/active_notification_settings/<int:target_id>', methods=['GET'])
@flask_jwt_extended.jwt_required
def api_active_notification_settings(user_id=None, target_id=None):
    if user_id is None:
        user_id = authentication_utils.get_user_id_from_current_jwt()

    if target_id is not None and not actions.can_user_get_target_definition_by_id(target_id, user_id):
        return "Target either doesn't exist or user is not allowed to see it.", 401

    connection_lists = get_effective_active_notification_settings(user_id, target_id)
    return jsonify(connection_lists)


@bp.route('/channel_connection/<string:channel_name>/<string:channel_id>', methods=['DELETE'])
@flask_jwt_extended.jwt_required
def api_channel_connection_delete(channel_name: str, channel_id: int):
    user_id = authentication_utils.get_user_id_from_current_jwt()
    try:
        channel_db_model = CONNECTION_DB_MODELS_TYPES[channel_name]
    except KeyError:
        return "This channel doesn't exist.", 400

    existing_connection = db_models.db.session \
        .query(channel_db_model) \
        .filter(channel_db_model.user_id == user_id) \
        .filter(channel_db_model.id == channel_id) \
        .first()

    if existing_connection:
        db_models.db.session.delete(existing_connection)
        db_models.db.session.commit()

    return 'ok', 200
