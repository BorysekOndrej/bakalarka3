import datetime
import json
from typing import Optional, List, Dict, Tuple

import app.scan_scheduler as scan_scheduler
from app import db_models, db_schemas, logger
import app.object_models as object_models
import app.utils.db_utils_advanced as db_utils_advanced
import app.utils.sslyze_scanner as sslyze_scanner
import app.utils.sslyze_parse_result as sslyze_parse_result

from config import FlaskConfig, SslyzeConfig
import app.utils.sslyze_result_simplify as sslyze_result_simplify


def can_user_get_target_definition_by_id(target_id: int, user_id: int) -> bool:
    scan_order = db_utils_advanced.generic_get_create_edit_from_data(
        db_schemas.ScanOrderSchema,
        {"target_id": target_id, "user_id": user_id},
        get_only=True
    )
    return scan_order is not None


def full_target_settings_to_dict(target: db_models.Target, scan_order: db_models.ScanOrder,
                                 notifications: db_models.NotificationSettings) -> dict:
    return {
        "target": db_schemas.TargetSchema().dump(target),
        "scanOrder": db_schemas.ScanOrderSchema(only=("periodicity", "active")).dump(scan_order),
        "notifications": db_schemas.NotificationSettingsSchema(only=["preferences"]).dump(notifications).get("preferences", {})
    }


def get_target_from_id(target_id: int) -> db_models.Target:
    return db_models.db.session.query(db_models.Target).get(target_id)


def get_target_from_id_if_user_can_see(target_id: int, user_id: int) -> Optional[db_models.Target]:
    # validate that the user entered the target definition at least once. Protection against enumaration attack.
    if not can_user_get_target_definition_by_id(target_id, user_id):
        return None

    # The following should always pass. If there isn't target, there shouldn't be scan order.
    return get_target_from_id(target_id)


def sslyze_scan(twe: List[object_models.TargetWithExtra]) -> Dict:
    if FlaskConfig.REDIS_ENABLED:
        ntwe_json_list = object_models.TargetWithExtraSchema().dump(twe, many=True)
        ntwe_json_string = json.dumps(ntwe_json_list)

        import app.utils.sslyze_background_redis as sslyze_background_redis
        return {'results_attached': False,
                'backgroud_job_id': sslyze_background_redis.redis_sslyze_enqueu(ntwe_json_string)}

    list_of_results_as_json: List[str] = sslyze_scanner.scan_domains_to_json(twe)
    answer = {'results_attached': True, 'results': list_of_results_as_json}
    sslyze_send_scan_results(answer)
    return answer


def sslyze_enqueue_waiting_scans():
    if FlaskConfig.REMOTE_COLLECTOR:
        # todo: get from collector
        pass
    else:
        twe = scan_scheduler.get_batch_to_scan()
        if len(twe) == 0:
            return {'results_attached': False,
                    'empty_job': True}

    return sslyze_scan(twe)


def sslyze_send_scan_results(scan_dict: dict) -> bool:
    if not scan_dict.get('results_attached', False):
        return False
    results: List[str] = scan_dict.get("results", [])
    if FlaskConfig.REMOTE_COLLECTOR:
        # todo: sent to collector
        return True

    for single_result_str in results:
        try:
            single_result: dict = json.loads(single_result_str)
            scan_result = sslyze_parse_result.insert_scan_result_into_db(single_result)
            # scan_result_simple = sslyze_result_simplify.sslyze_result_simplify(scan_result)
            # db_models.db.session.add(scan_result_simple)
        except Exception as e:
            logger.warning("Failed inserting or parsing scan result. Skipping it.")
            logger.exception(e)
            if not SslyzeConfig.soft_fail_on_result_parse_fail:
                raise
    return True


def get_last_scan_and_result(target_id: int, user_id: int) -> Optional[Tuple[db_models.LastScan, db_models.ScanResults]]:
    if not can_user_get_target_definition_by_id(target_id, user_id):
        return None

    scan_result = db_models.db.session\
        .query(db_models.LastScan, db_models.ScanResults)\
        .filter(db_models.LastScan.target_id == target_id) \
        .filter(db_models.LastScan.result_id == db_models.ScanResults.id) \
        .one()

    return scan_result


def get_scan_history(user_id: int, x_days: int = 30):  # -> Optional[Tuple[db_models.LastScan, db_models.ScanResults]]:
    today = datetime.datetime.now()
    start = today - datetime.timedelta(days=x_days)
    start_timestamp = db_models.datetime_to_timestamp(start)

    res = db_models.db.session \
        .query(db_models.ScanOrder, db_models.Target, db_models.ScanResultsHistory, db_models.ScanResultsSimplified) \
        .outerjoin(db_models.ScanResultsHistory,
                   db_models.ScanResultsHistory.target_id == db_models.ScanOrder.target_id) \
        .outerjoin(db_models.ScanResultsSimplified,
                   db_models.ScanResultsHistory.scanresult_id == db_models.ScanResultsSimplified.scanresult_id) \
        .filter(db_models.ScanOrder.target_id == db_models.Target.id) \
        .filter(db_models.ScanOrder.active == True) \
        .filter(db_models.ScanOrder.user_id == user_id) \
        .filter(db_models.ScanResultsHistory.timestamp >= start_timestamp) \
        .all()

    return res
