import datetime
import json
import random

from flask import Blueprint, current_app

import app.object_models as object_models
import app.utils.sslyze_scanner as sslyze_scanner
from config import FlaskConfig

bp = Blueprint('apiV1', __name__)

import flask
from flask import request, jsonify
from loguru import logger

import flask_jwt_extended

import app.utils.db_utils as db_utils
import app.utils.db_utils_advanced as db_utils_advanced
import app.scan_scheduler as scan_scheduler
import app.db_schemas as db_schemas
import app.db_models as db_models
import app.utils.authentication_utils as authentication_utils
import app.actions as actions
# from config import FlaskConfig


@bp.route('/get_next_targets_batch')
def api_get_next_targets_batch():
    return jsonify(scan_scheduler.get_batch_to_scan())


@bp.route('/get_target_id_from_definition', methods=['POST'])
@flask_jwt_extended.jwt_required
def get_target_id(target_def=None):
    if target_def:
        data = target_def
    else:
        data = json.loads(request.data)
    # logger.warning(data)
    data["protocol"] = data.get("protocol", "HTTPS").replace("TlsWrappedProtocolEnum.", "")  # todo: remove this hack
    target = db_utils_advanced.generic_get_create_edit_from_data(db_schemas.TargetSchema, data, get_only=True)
    if not target:
        return "fail", 400
    user_jwt = flask_jwt_extended.get_jwt_identity()
    user_id = authentication_utils.get_user_id_from_jwt(user_jwt)

    # validate that the user entered the target definition at least once. Protection against enumaration attack.
    if not actions.can_user_get_target_definition_by_id(target.id, user_id):
        return "fail", 400
    return jsonify({"id": target.id}), 200


@bp.route('/get_target_from_id/<int:target_id>', methods=['GET'])
@flask_jwt_extended.jwt_required
def api_get_target_from_id(target_id):
    user_jwt = flask_jwt_extended.get_jwt_identity()
    user_id = authentication_utils.get_user_id_from_jwt(user_jwt)

    target = actions.get_target_from_id_if_user_can_see(target_id, user_id)
    if target is None:
        return "Target either doesn't exist or you're allowed to see it.", 400
    return db_schemas.TargetSchema().dump(target), 200


@bp.route('/target/<int:target_id>', methods=['GET', 'DELETE'])
@flask_jwt_extended.jwt_required
def api_target_by_id(target_id: int):
    user_jwt = flask_jwt_extended.get_jwt_identity()
    user_id = authentication_utils.get_user_id_from_jwt(user_jwt)

    target = actions.get_target_from_id_if_user_can_see(target_id, user_id)
    if target is None:
        return "Target either doesn't exist or you're allowed to see it.", 400

    if request.method == 'DELETE':
        scan_order: db_models.ScanOrder = db_utils_advanced.generic_get_create_edit_from_data(
            db_schemas.ScanOrderSchema,
            {"target_id": target.id, "user_id": user_id},
            get_only=True
        )
        scan_order.active = False
        db_models.db.session.commit()
        db_utils.actions_on_modification(scan_order)


    scan_order = db_utils_advanced.generic_get_create_edit_from_data(db_schemas.ScanOrderSchema,
                                                                     {"target_id": target.id, "user_id": user_id},
                                                                     get_only=True)

    notifications = db_utils_advanced.generic_get_create_edit_from_data(db_schemas.NotificationsSchema,
                                                                        {"target_id": target.id, "user_id": user_id},
                                                                        get_only=True)

    return jsonify(actions.full_target_settings_to_dict(target, scan_order, notifications))


@bp.route('/add_target', methods=['POST', 'PUT'])
@bp.route('/target', methods=['PUT', 'PATCH'])
@flask_jwt_extended.jwt_required
def api_target():
    user_jwt = flask_jwt_extended.get_jwt_identity()
    user_id = authentication_utils.get_user_id_from_jwt(user_jwt)

    data = json.loads(request.data)
    data["target"]["protocol"] = data.get("protocol", "HTTPS").replace("TlsWrappedProtocolEnum.",
                                                                       "")  # todo: remove this hack
    data["target"].pop("id", None)
    target = db_utils_advanced.generic_get_create_edit_from_data(db_schemas.TargetSchema, data["target"])

    if data.get("scanOrder", None):
        scan_order_def = db_utils.merge_dict_with_copy_and_overwrite(data.get("scanOrder", {}),
                                                                     {"target_id": target.id, "user_id": user_id})
        db_utils_advanced.generic_get_create_edit_from_data(db_schemas.ScanOrderSchema, scan_order_def)

    if data.get("notifications", None):
        notifications_def = db_utils.merge_dict_with_copy_and_overwrite({"preferences": data.get("notifications", {})},
                                                                        {"target_id": target.id, "user_id": user_id})
        db_utils_advanced.generic_get_create_edit_from_data(db_schemas.NotificationsSchema, notifications_def)

    return api_target_by_id(target.id)


@bp.route('/add_scan_order', methods=['POST'])
def api_add_scan_order():
    data = json.loads(request.data)
    schema = db_schemas.ScanOrderSchema(session=db_models.db)
    # todo deduplicate
    # todo validation
    data["user_id"] = random.randrange(100000)  # todo: make dynamic (from server side)
    result = schema.load(data)
    db_models.db.session.add(result)
    db_models.db.session.commit()
    db_utils.actions_on_modification(result)
    return repr(result)


@bp.route('/login', methods=['POST'])
def api_login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)

    msg = ""

    if not username:
        msg += "Missing username parameter. "
    if not password:
        msg += "Missing password parameter. "
    if len(msg):
        return jsonify({"msg": msg}), 400

    # todo: validate inputs

    res = db_models.db.session \
        .query(db_models.User) \
        .filter(db_models.User.username == username) \
        .first()

    if res is None:
        return jsonify({"msg": "Bad username or password"}), 401

    # todo: check bogus password even when username doesn't exist to eliminate timing attack
    res: db_models.User
    is_password_valid: bool = authentication_utils.check_password(res.password_hash, password)

    if not is_password_valid:
        return jsonify({"msg": "Bad username or password"}), 401  # todo: make sure 401 msgs are same

    identity = {"id": res.id, "username": res.username}
    access_token = flask_jwt_extended.create_access_token(identity=identity, fresh=True)
    refresh_token = flask_jwt_extended.create_refresh_token(identity=identity)
    response_object = jsonify(access_token=access_token)
    response_object: flask.Response

    flask_jwt_extended.set_refresh_cookies(response_object, refresh_token)

    # response_object.set_cookie("refresh_token", refresh_token,
    #                            max_age=FlaskConfig.JWT_REFRESH_TOKEN_EXPIRES.total_seconds(),
    #                            secure=True, httponly=True,
    #                            domain=None,  # todo
    #                            path='/')  # todo

    return response_object, 200


@bp.route('/register', methods=['POST'])
def api_register():
    data = json.loads(request.data)
    # todo: validation
    exists_username = db_models.db.session \
        .query(db_models.User.id) \
        .filter(db_models.User.username == data["username"]) \
        .first()

    if exists_username is not None:
        return jsonify({"msg": "Username already exists"}), 400  # is there way avoid username enumeration?

    data["password_hash"] = authentication_utils.generate_password_hash(data["password"])
    data.pop("password")
    data["main_api_key"] = "API-546654-"+str(random.randrange(10000))  # todo
    logger.warning(data)

    schema = db_schemas.UserSchema(session=db_models.db)
    new_user = schema.load(data)  # this wouldn't work straight away, for example password_hash wouldn't work

    db_models.db.session.add(new_user)
    db_models.db.session.commit()

    return jsonify({"msg": "ok"}), 200


@bp.route('/refreshToken', methods=['GET'])
@flask_jwt_extended.jwt_refresh_token_required
def refresh():
    # logger.error(request.cookies)
    current_user = flask_jwt_extended.get_jwt_identity()
    # logger.error(current_user)
    new_token = flask_jwt_extended.create_access_token(identity=current_user, fresh=False)
    ret = {'access_token': new_token}
    import time
    time.sleep(10)  # todo: remove after debugging
    return jsonify(ret), 200


@bp.route('/get_user_targets')
@flask_jwt_extended.jwt_required
def api_get_user_targets():
    jwt = flask_jwt_extended.get_jwt_identity()
    # logger.debug(jwt)
    res = db_models.db.session \
        .query(db_models.Target, db_models.ScanOrder.active) \
        .join(db_models.ScanOrder) \
        .filter(db_models.ScanOrder.user_id == jwt["id"]) \
        .all()

    schema = db_schemas.TargetSchema(many=True)
    json_dict = schema.dump([x.Target for x in res])

    for obj in json_dict:
        for single_res in res:
            if obj["id"] == single_res.Target.id:
                obj["active"] = 'yes' if single_res.active else 'no'

    for x in json_dict:
        x["grade"] = random.choice([chr(ord('A')+i) for i in range(5)])
        x["expires"] = datetime.date(2020, 1, 1) + datetime.timedelta(days=random.randint(10, 500))

    json_string = json.dumps(json_dict, default=str)
    # logger.debug(json_string)
    return json_string, 200


@bp.route('/sslyze_scan_targets', methods=['POST'])
@flask_jwt_extended.jwt_required
def api_sslyze_scan_targets():
    twe = object_models.load_json_to_targets_with_extra(request.data)
    return jsonify(actions.sslyze_scan(current_app, twe)), 200
