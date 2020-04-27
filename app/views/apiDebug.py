import datetime
import json
import random

from flask import Blueprint
from config import FlaskConfig

bp = Blueprint('apiDebug', __name__)


from flask import request, jsonify, current_app

import flask_jwt_extended

import app.utils.db_utils as db_utils
import app.utils.sslyze_parse_result as sslyze_parse_result
import app.scan_scheduler as scan_scheduler
from app import db_models, logger
import app.utils.dns_utils as dns_utils
import app.utils.ct_search as ct_search
import app.utils.sslyze_scanner as sslyze_scanner
import app.utils.extract_test as extract_test
import app.utils.authentication_utils as authentication_utils
import app.utils.normalize_jsons as normalize_jsons
import app.object_models as object_models


@bp.route('/sslyze_get_direct_scan/<string:domain>')
def debug_sslyze_get_direct_scan(domain):
    ntwe = object_models.TargetWithExtra(db_models.Target(hostname=domain))
    res = sslyze_scanner.scan_to_json(ntwe)
    return res


@bp.route('/sslyze_batch_direct_scan', methods=['POST'])
def debug_sslyze_batch_direct_scan():
    # logger.warning(request.data)
    data = json.loads(request.data)
    twe = []
    for x in data.get("targets", []):
        ntwe = object_models.TargetWithExtra(db_models.Target.from_repr_to_transient(x))
        twe.append(ntwe)
    res = sslyze_scanner.scan_domains_to_json(twe)
    answers = []
    for x in res:
        answers.append(json.loads(x))
    return json.dumps(answers, indent=3)


@bp.route('/sslyze_batch_scan_enqueue_redis', methods=['POST'])
def debug_sslyze_batch_scan_enqueue_redis():
    if not FlaskConfig.REDIS_ENABLED:
        return "Redis support is not enabled in config", 500
    import app.utils.sslyze_background_redis as sslyze_background_redis

    # At this point I don't have access to DB (this can be run on sensor), so I can't really fully validate.
    twe = object_models.load_json_to_targets_with_extra(request.data)
    ntwe_json_list = object_models.TargetWithExtraSchema().dump(twe, many=True)
    ntwe_json_string = json.dumps(ntwe_json_list)

    return sslyze_background_redis.redis_sslyze_enqueu(current_app, ntwe_json_string), 200


@bp.route('/sslyze_batch_scan_result_redis/<string:job_id>', methods=['GET'])
def debug_sslyze_batch_scan_result_redis(job_id):
    if not FlaskConfig.REDIS_ENABLED:
        return "Redis support is not enabled in config", 500
    import app.utils.sslyze_background_redis as sslyze_background_redis

    job = sslyze_background_redis.redis_sslyze_fetch_job(current_app, job_id)

    return jsonify({
        'id': job.get_id(),
        'status': job.is_finished,
        'meta': job.meta,
        'result': job.result
    })


@bp.route('/dns_resolve_domain/<string:domain>')
def debug_dns_resolve_domain(domain):
    return jsonify({"hostname": domain, "result": dns_utils.get_ips_for_domain(domain)})


@bp.route('/ct_get_subdomains/<string:domain>')
def debug_ct_get_subdomains(domain):
    return jsonify({"hostname": domain, "result": ct_search.get_subdomains_from_ct(domain)})


@bp.route('/db_get_all')
def debug_db_get_all():
    return extract_test.test_extract_from_db()


@bp.route('/db_initialize_from_file')
def debug_db_initialize_from_file():
    sslyze_parse_result.run()
    return jsonify({})


@bp.route('/db_backdate_last_enqued')
def debug_db_backdate_last_enqued():
    res_len = scan_scheduler.backdate_enqueued_targets()
    return jsonify({"number_of_backdated_itimes": res_len})


@bp.route('/domain_to_target_string/<string:domain>')
def debug_domain_to_target_string(domain):
    return repr(db_models.Target(hostname=domain))


@bp.route('/scenario1', methods=['GET'])
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


@bp.route('/normalizeJsons', methods=['GET'])
def scenario2():
    try:
        normalize_jsons.run()
    finally:
        pass
    return "done"


@bp.route('/loginSetRefreshCookie', methods=['GET'])
def loginSetRefreshCookie():
    identity = {"id": 1, "username": "test1"}
    refresh_token = flask_jwt_extended.create_refresh_token(identity=identity)
    response_object = jsonify({})
    flask_jwt_extended.set_refresh_cookies(response_object, refresh_token)
    return response_object, 200


@bp.route('/setAccessCookie', methods=['GET'])
@flask_jwt_extended.jwt_refresh_token_required
def debugSetAccessCookie():
    current_user = flask_jwt_extended.get_jwt_identity()
    access_token = flask_jwt_extended.create_access_token(identity=current_user, expires_delta=datetime.timedelta(days=1))
    response_object = jsonify({})
    flask_jwt_extended.set_access_cookies(response_object, access_token)
    return response_object, 200


@bp.route('/cors', methods=['GET'])
def cors1():
    return "done", 200


@bp.route('/updateTarget', methods=['GET'])
def updateTarget1():
    res = db_models.db.session \
        .query(db_models.Target) \
        .first()
    res.port = random.randint(100, 1000)
    db_models.db.session.commit()
    return "done", 200


@bp.route('/get_or_create_or_update_by_unique', methods=['GET'])
def test_get_or_create_or_update_by_unique():
    target1 = {"hostname": "lorem.borysek.eu"}
    db_utils.get_or_create_or_update_by_unique(db_models.Target, **target1)
    return "done", 200
