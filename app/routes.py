import datetime
import json
import random

import flask
from flask import render_template, request, jsonify

import flask_jwt_extended

import db_utils
import sslyze_parse_result
import scan_scheduler
from app import app, db_models, logger
import dns_utils
import ct_search
import sslyze_scanner
import extract_test
import db_schemas
import authentication_utils
from authentication_utils import check_if_token_in_blacklist
import utils.normalize_jsons
import actions
# from config import FlaskConfig


@app.route('/')
@app.route('/index')
def index():
    test_arg = [{"title": "title1", "content": "content1"}, {"title": "title2", "content": "content2"}]
    return render_template('index.html', title='Page title', test_arg=test_arg)


@app.route('/dashboard')
def dashboard_index():
    return render_template('index.html', title='Dashboard', test_arg=[])


@app.route('/dashboard/login')
def dashboard_login():
    return render_template('index.html', title='Dashboard login', test_arg=[])


@app.route('/api/v1/get_next_targets_batch')
def api_get_next_targets_batch():
    return jsonify(scan_scheduler.get_batch_to_scan())


@app.route('/debug/html/batch_direct_scan')
def debug_batch_direct_scan_html():
    return render_template('debug_html/batch_direct_scan.html')


@app.route('/debug/<string:domain>')
@app.route('/debug/')
def debug_overview(domain="borysek.eu"):
    return render_template('debug_overview.html', domain=domain)


@app.route('/api/debug/sslyze_get_direct_scan/<string:domain>')
def debug_sslyze_get_direct_scan(domain):
    ntwe = db_models.TargetWithExtra(db_models.Target(hostname=domain))
    res = sslyze_scanner.scan_to_json(ntwe)
    return res


@app.route('/api/debug/sslyze_batch_direct_scan', methods=['POST'])
def debug_sslyze_batch_direct_scan():
    # logger.warning(request.data)
    data = json.loads(request.data)
    twe = []
    for x in data.get("targets", []):
        ntwe = db_models.TargetWithExtra(db_models.Target.from_repr_to_transient(x))
        twe.append(ntwe)
    res = sslyze_scanner.scan_domains_to_json(twe)
    answers = []
    for x in res:
        answers.append(json.loads(x))
    return json.dumps(answers, indent=3)


@app.route('/api/debug/dns_resolve_domain/<string:domain>')
def debug_dns_resolve_domain(domain):
    return jsonify({"hostname": domain, "result": dns_utils.get_ips_for_domain(domain)})


@app.route('/api/debug/ct_get_subdomains/<string:domain>')
def debug_ct_get_subdomains(domain):
    return jsonify({"hostname": domain, "result": ct_search.get_subdomains_from_ct(domain)})


@app.route('/api/debug/db_get_all')
def debug_db_get_all():
    return extract_test.test_extract_from_db()


@app.route('/api/debug/db_initialize_from_file')
def debug_db_initialize_from_file():
    sslyze_parse_result.run()
    return jsonify({})


@app.route('/api/debug/db_backdate_last_enqued')
def debug_db_backdate_last_enqued():
    res_len = scan_scheduler.backdate_enqueued_targets()
    return jsonify({"number_of_backdated_itimes": res_len})


@app.route('/api/debug/domain_to_target_string/<string:domain>')
def debug_domain_to_target_string(domain):
    return repr(db_models.Target(hostname=domain))


@app.route('/api/v1/get_target_id_from_definition', methods=['POST'])
@flask_jwt_extended.jwt_required
def get_target_id(target_def=None):
    if target_def:
        data = target_def
    else:
        data = json.loads(request.data)
    # logger.warning(data)
    data["protocol"] = data.get("protocol", "HTTPS").replace("TlsWrappedProtocolEnum.", "")  # todo: remove this hack
    target = actions.generic_get_create_edit_from_data(db_schemas.TargetSchema, data, get_only=True)
    if not target:
        return "fail", 400
    user_jwt = flask_jwt_extended.get_jwt_identity()
    user_id = authentication_utils.get_user_id_from_jwt(user_jwt)

    # validate that the user entered the target definition at least once. Protection against enumaration attack.
    if not actions.can_user_get_target_definition_by_id(target.id, user_id):
        return "fail", 400
    return jsonify({"id": target.id}), 200


@app.route('/api/v1/get_target_from_id/<int:target_id>', methods=['GET'])
@flask_jwt_extended.jwt_required
def api_get_target_from_id(target_id):
    user_jwt = flask_jwt_extended.get_jwt_identity()
    user_id = authentication_utils.get_user_id_from_jwt(user_jwt)

    target = actions.get_target_from_id_if_user_can_see(target_id, user_id)
    if target is None:
        return "Target either doesn't exist or you're allowed to see it.", 400
    return db_schemas.TargetSchema().dump(target), 200


@app.route('/api/v1/target/<int:target_id>', methods=['GET', 'DELETE'])
@flask_jwt_extended.jwt_required
def api_target_by_id(target_id: int):
    user_jwt = flask_jwt_extended.get_jwt_identity()
    user_id = authentication_utils.get_user_id_from_jwt(user_jwt)

    target = actions.get_target_from_id_if_user_can_see(target_id, user_id)
    if target is None:
        return "Target either doesn't exist or you're allowed to see it.", 400

    if request.method == 'DELETE':
        scan_order: db_models.ScanOrder = actions.generic_get_create_edit_from_data(
            db_schemas.ScanOrderSchema,
            {"target_id": target.id, "user_id": user_id},
            get_only=True
        )
        scan_order.active = False
        db_models.db.session.commit()
        db_utils.actions_on_modification(scan_order)


    scan_order = actions.generic_get_create_edit_from_data(db_schemas.ScanOrderSchema,
                                                           {"target_id": target.id, "user_id": user_id},
                                                           get_only=True)

    notifications = actions.generic_get_create_edit_from_data(db_schemas.NotificationsSchema,
                                                              {"target_id": target.id, "user_id": user_id},
                                                              get_only=True)

    return jsonify(actions.full_target_settings_to_dict(target, scan_order, notifications))


@app.route('/api/v1/add_target', methods=['POST', 'PUT'])
@app.route('/api/v1/target', methods=['PUT', 'PATCH'])
@flask_jwt_extended.jwt_required
def api_target():
    user_jwt = flask_jwt_extended.get_jwt_identity()
    user_id = authentication_utils.get_user_id_from_jwt(user_jwt)

    data = json.loads(request.data)
    data["target"]["protocol"] = data.get("protocol", "HTTPS").replace("TlsWrappedProtocolEnum.",
                                                                       "")  # todo: remove this hack
    data["target"].pop("id", None)
    target = actions.generic_get_create_edit_from_data(db_schemas.TargetSchema, data["target"])

    if data.get("scanOrder", None):
        scan_order_def = db_utils.merge_dict_with_copy_and_overwrite(data.get("scanOrder", {}),
                                                                     {"target_id": target.id, "user_id": user_id})
        actions.generic_get_create_edit_from_data(db_schemas.ScanOrderSchema, scan_order_def)

    if data.get("notifications", None):
        notifications_def = db_utils.merge_dict_with_copy_and_overwrite({"preferences": data.get("notifications", {})},
                                                                        {"target_id": target.id, "user_id": user_id})
        actions.generic_get_create_edit_from_data(db_schemas.NotificationsSchema, notifications_def)

    return api_target_by_id(target.id)


@app.route('/api/v1/add_scan_order', methods=['POST'])
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


@app.route('/api/v1/login', methods=['POST'])
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


@app.route('/api/v1/register', methods=['POST'])
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


@app.route('/api/v1/refreshToken', methods=['GET'])
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


@app.route('/api/debug/scenario1', methods=['GET'])
def scenario1():
    try:
        db_models.User(username="test1", email="test1@example.com",
                       password_hash=authentication_utils.generate_password_hash("lorem"), main_api_key="aaaaa")
        db_models.Target.from_kwargs({"hostname": "borysek.eu"})

        # dt_sec = datetime.timedelta(seconds=60)

        db_models.ScanOrder.from_kwargs({"target_id": 1, "user_id": 1, "periodicity": 60})

        # date_offseted = datetime.datetime.now() - datetime.timedelta(days=10)
        # db.session.query(db_models.LastScan) \
        #     .update({db_models.LastScan.last_enqueued: date_offseted}, synchronize_session='fetch')

        db_models.db.session.commit()
    finally:
        pass
    return "done"


@app.route('/api/debug/normalizeJsons', methods=['GET'])
def scenario2():
    try:
        utils.normalize_jsons.run()
    finally:
        pass
    return "done"


@app.route('/api/debug/loginSetRefreshCookie', methods=['GET'])
def loginSetRefreshCookie():
    identity = {"id": 1, "username": "test1"}
    refresh_token = flask_jwt_extended.create_refresh_token(identity=identity)
    response_object = jsonify({})
    flask_jwt_extended.set_refresh_cookies(response_object, refresh_token)
    return response_object, 200


@app.route('/api/debug/setAccessCookie', methods=['GET'])
@flask_jwt_extended.jwt_refresh_token_required
def debugSetAccessCookie():
    current_user = flask_jwt_extended.get_jwt_identity()
    access_token = flask_jwt_extended.create_access_token(identity=current_user, expires_delta=datetime.timedelta(days=1))
    response_object = jsonify({})
    flask_jwt_extended.set_access_cookies(response_object, access_token)
    return response_object, 200


@app.route('/api/debug/cors', methods=['GET'])
def cors1():
    from flask_cors import CORS
    return "done", 200


@app.route('/api/v1/get_user_targets')
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


@app.route('/api/debug/updateTarget', methods=['GET'])
def updateTarget1():
    res = db_models.db.session \
        .query(db_models.Target) \
        .first()
    res.port = random.randint(100, 1000)
    db_models.db.session.commit()
    return "done", 200


@app.route('/api/debug/get_or_create_or_update_by_unique', methods=['GET'])
def test_get_or_create_or_update_by_unique():
    target1 = {"hostname": "lorem.borysek.eu"}
    db_utils.get_or_create_or_update_by_unique(db_models.Target, **target1)
    return "done", 200