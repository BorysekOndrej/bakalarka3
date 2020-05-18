import datetime
import json
import random
from typing import List, Tuple

from flask import Blueprint, current_app

import app.object_models as object_models
import app.utils.sslyze_scanner as sslyze_scanner
import app.utils.ct_search as ct_search

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
    return jsonify(scan_scheduler.convert_batch_to_scan_to_list_of_dicts(scan_scheduler.get_batch_to_scan()))


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

    notifications = db_utils_advanced.generic_get_create_edit_from_data(db_schemas.NotificationSettingsSchema,
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
        db_utils_advanced.generic_get_create_edit_from_data(db_schemas.NotificationSettingsSchema, notifications_def)

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
    if FlaskConfig.DEBUG:
        import time
        time.sleep(10)  # todo: remove after debugging
    return jsonify(ret), 200


@bp.route('/get_user_targets')
@flask_jwt_extended.jwt_required
def api_get_user_targets():
    jwt = flask_jwt_extended.get_jwt_identity()
    # logger.debug(jwt)

    res = db_models.db.session \
        .query(db_models.ScanOrder, db_models.Target, db_models.LastScan, db_models.ScanResults) \
        .outerjoin(db_models.ScanResults, db_models.LastScan.result_id == db_models.ScanResults.id)\
        .filter(db_models.LastScan.target_id == db_models.Target.id) \
        .filter(db_models.ScanOrder.target_id == db_models.Target.id) \
        .filter(db_models.ScanOrder.user_id == jwt["id"]) \
        .all()

    # res: List[Tuple[db_models.ScanOrder, db_models.Target, db_models.LastScan, db_models.ScanResults]]

    schema = db_schemas.TargetSchema(many=True)
    json_dict = schema.dump([x.Target for x in res])

    for obj in json_dict:
        for single_res in res:
            if obj["id"] == single_res.Target.id:
                obj["active"] = 'yes' if single_res.ScanOrder.active else 'no'

                obj["expires"] = "Not scanned yet"
                obj["grade"] = "Not scanned yet"
                if single_res.ScanResults is None:
                    continue

                cert_info = single_res.ScanResults.certificate_information

                certificates_in_received_chain: List[db_models.Certificate] = db_models.Certificate.select_from_list(
                    cert_info.received_certificate_chain_list.chain)
                obj["expires"] = min([x.notAfter for x in certificates_in_received_chain])

                certificates_in_verified_chain: List[db_models.Certificate] = db_models.Certificate.select_from_list(
                    cert_info.verified_certificate_chain_list.chain)
                obj["grade"] = "A" if len(certificates_in_verified_chain) else "F"

    # for x in json_dict:
    #     x["grade"] = random.choice([chr(ord('A')+i) for i in range(5)])
    #     x["expires"] = datetime.date(2020, 1, 1) + datetime.timedelta(days=random.randint(10, 500))

    json_string = json.dumps(json_dict, default=str)
    # logger.debug(json_string)
    return json_string, 200


@bp.route('/sslyze_scan_targets', methods=['POST'])
@flask_jwt_extended.jwt_required
def api_sslyze_scan_targets():
    twe = object_models.load_json_to_targets_with_extra(request.data)
    scan_result = actions.sslyze_scan(twe)
    actions.sslyze_send_scan_results(scan_result)
    return scan_result, 200


@bp.route('/sslyze_scan_due_targets', methods=['GET'])
@flask_jwt_extended.jwt_required
def api_sslyze_scan_due_targets():
    return actions.sslyze_enqueue_waiting_scans()


@bp.route('/sslyze_import_scan_results', methods=['POST'])
@bp.route('/sslyze_import_scan_results/<string:sensor_key>', methods=['POST'])
def api_sslyze_import_scan_results(sensor_key=None):
    valid_access = False
    if FlaskConfig.REMOTE_COLLECTOR_KEY and sensor_key:
        valid_access = FlaskConfig.REMOTE_COLLECTOR_KEY == sensor_key
    if request.remote_addr == '127.0.0.1':
        valid_access = True
    if not valid_access:
        logger.warning(
            f'Request to import scan results: unauthorized: key: {sensor_key}, IP: {request.remote_addr}')
        return 'Access only allowed with valid REMOTE_COLLECTOR_KEY or from localhost', 401

    data = json.loads(request.data)
    if not data.get('results_attached', False):
        return "No results attached flag", 400
    data["results"] = json.loads(data.get("results", "[]"))
    new_res = []
    for x in data["results"]:
        new_res.append(json.dumps(x))
    data["results"] = new_res
    actions.sslyze_send_scan_results(data)
    return "ok", 200


@bp.route('/get_result_for_target/<int:target_id>', methods=['GET'])
@flask_jwt_extended.jwt_required
def api_get_result_for_target(target_id):
    user_jwt = flask_jwt_extended.get_jwt_identity()
    user_id = authentication_utils.get_user_id_from_jwt(user_jwt)

    last_scan, scan_result = actions.get_last_scan_and_result(target_id, user_id)
    last_scan: db_models.LastScan
    scan_result: db_models.ScanResults

    if scan_result is None:
        return "Target either doesn't exist or the current user doesn't have permission to view it.", 401

    last_scanned = last_scan.last_scanned
    last_scanned_datetime = db_models.timestamp_to_datetime(last_scanned)

    scan_result_str = db_schemas.ScanResultsSchema().dumps(scan_result)

    return jsonify({'result': json.loads(scan_result_str), 'time': last_scanned_datetime}), 200


@bp.route('/get_basic_cert_info_for_target/<int:target_id>', methods=['GET'])
@flask_jwt_extended.jwt_required
def api_get_basic_cert_info_for_target(target_id):
    user_jwt = flask_jwt_extended.get_jwt_identity()
    user_id = authentication_utils.get_user_id_from_jwt(user_jwt)

    last_scan, scan_result = actions.get_last_scan_and_result(target_id, user_id)
    last_scan: db_models.LastScan
    scan_result: db_models.ScanResults

    if scan_result is None:
        return "Target either doesn't exist or the current user doesn't have permission to view it.", 401

    last_scanned_datetime = db_models.timestamp_to_datetime(last_scan.last_scanned)
    cert_info = scan_result.certificate_information
    verified_chain = cert_info.verified_certificate_chain_list
    certificates_in_chain: List[db_models.Certificate] = db_models.Certificate.select_from_list(verified_chain.chain)

    list_cert = certificates_in_chain[0]

    return {'chain_notBefore': max([x.notBefore for x in certificates_in_chain]),
            'chain_notAfter': min([x.notAfter for x in certificates_in_chain]),
            'leaf_sni': list_cert.subject_alternative_name_list,
            'leaf_subject': list_cert.subject,
            'information_fetched_on': last_scanned_datetime
            }, 200


@bp.route('/notification_settings', methods=['GET', 'POST'])
@bp.route('/notification_settings/<int:user_id>', methods=['GET', 'POST'])
@bp.route('/notification_settings/<int:user_id>/null', methods=['GET', 'POST'])
@bp.route('/notification_settings/<int:user_id>/<int:target_id>', methods=['GET', 'POST'])
@flask_jwt_extended.jwt_required
def api_notification_settings(user_id=None, target_id=None):
    if user_id is None:
        user_jwt = flask_jwt_extended.get_jwt_identity()
        user_id = authentication_utils.get_user_id_from_jwt(user_jwt)

    if target_id is not None and not actions.can_user_get_target_definition_by_id(target_id, user_id):
        return "Target either doesn't exist or user is not allowed to see it.", 401

    get_only = request.method == "GET"

    potentialy_new_model = db_models.NotificationSettings()
    potentialy_new_model.user_id = user_id
    potentialy_new_model.target_id = target_id

    if not get_only:
        potentialy_new_model.preferences = json.loads(request.data)

    res = db_utils_advanced.generic_get_create_edit_from_transient(db_schemas.NotificationSettingsSchema,
                                                                   potentialy_new_model,
                                                                   get_only=get_only)
    if res is None:
        return "{}", 200

    res: db_models.NotificationSettings
    logger.debug(f'notification_settings {user_id} {target_id} {res}')
    return res.preferences, 200


@bp.route('/scan_result_history', methods=['GET'])
@bp.route('/scan_result_history/<int:x_days>', methods=['GET'])
@flask_jwt_extended.jwt_required
def api_scan_result_history(user_id=None, x_days=30):
    if user_id is None:
        user_jwt = flask_jwt_extended.get_jwt_identity()
        user_id = authentication_utils.get_user_id_from_jwt(user_jwt)

    res = actions.get_scan_history(user_id, x_days)

    if res is None:
        return "[]", 200

    res_arr = []
    for x in res:
        new_dict = {
            "timestamp": None,
            "target": None,
            "result_simplified": None,
        }
        if x.ScanResultsHistory:
            new_dict["timestamp"] = x.ScanResultsHistory.timestamp
        new_dict["target"] = json.loads(db_schemas.TargetSchema().dumps(x.Target))
        new_dict["result_simplified"] = json.loads(db_schemas.ScanResultsSimplifiedSchema().dumps(x.ScanResultsSimplified))
        res_arr.append(new_dict)

    return json.dumps(res_arr, indent=3), 200


@bp.route('/ct_get_subdomains/<string:domain>')
def api_ct_get_subdomains(domain):
    return jsonify({"hostname": domain, "result": ct_search.get_subdomains_from_ct(domain)})
