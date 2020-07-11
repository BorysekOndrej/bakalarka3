import json

from sqlalchemy.orm.exc import NoResultFound

from config import FlaskConfig

from . import bp

from flask import request, jsonify
from loguru import logger

import flask_jwt_extended

import app.scan_scheduler as scan_scheduler
import app.db_models as db_models
import app.actions as actions


@bp.route('/get_next_targets_batch')
def api_get_next_targets_batch():
    return jsonify(scan_scheduler.convert_batch_to_scan_to_list_of_dicts(scan_scheduler.get_batch_to_scan()))


@bp.route('/sslyze_scan_due_targets', methods=['GET'])
@flask_jwt_extended.jwt_required
def api_sslyze_scan_due_targets():
    return actions.sslyze_enqueue_waiting_scans()


@bp.route('/sslyze_scan_due_targets/<string:sensor_key>', methods=['GET'])
def api_sslyze_scan_due_targets_via_sensor_key(sensor_key=None):
    valid_access = False
    if FlaskConfig.REMOTE_COLLECTOR_KEY and sensor_key:
        valid_access = FlaskConfig.REMOTE_COLLECTOR_KEY == sensor_key
    if request.remote_addr == '127.0.0.1':
        valid_access = True
    if not valid_access:
        logger.warning(
            f'Request to scan due targets: unauthorized: key: {sensor_key}, IP: {request.remote_addr}')
        return 'Access only allowed with valid REMOTE_COLLECTOR_KEY or from localhost', 401

    return actions.sslyze_enqueue_waiting_scans()


@bp.route('/sslyze_enqueue_now/<int:target_id>', methods=['GET'])
@flask_jwt_extended.jwt_required
def api_sslyze_enqueue_now(target_id):
    try:
        res = db_models.db.session \
            .query(db_models.LastScan) \
            .filter(db_models.LastScan.target_id == target_id) \
            .one()
    except NoResultFound as e:
        return "Target id not found", 400  # todo: check status code

    res: db_models.LastScan
    res.last_scanned = None
    # todo: consider also resetting last_enqueued
    db_models.db.session.commit()
    return "ok", 200


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
