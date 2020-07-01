import datetime
import json
from itertools import chain
from typing import Optional, List, Dict, Tuple

from sqlalchemy import or_

import app.scan_scheduler as scan_scheduler
import app.utils.randomCodes as randomCodes
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
                                 notifications: dict) -> dict:
    return {
        "target": db_schemas.TargetSchema().dump(target),
        "scanOrder": db_schemas.ScanOrderSchema(only=("periodicity", "active")).dump(scan_order),
        "notifications": notifications
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


def list_connections_of_type(db_model, user_id) -> List[dict]:
    connections = db_models.db.session \
        .query(db_model) \
        .filter(db_model.user_id == user_id) \
        .all()

    result_arr = []
    if connections:
        for x in connections:
            result_arr.append(x.as_dict())

    return result_arr


def merge_dict_by_strategy(more_general: dict, more_specific: dict) -> dict:
    preference_merge_strategy = more_specific.get("preference_merge_strategy", "classic")
    if preference_merge_strategy == "classic":
        return {**more_general, **more_specific}
    if preference_merge_strategy == "more_general_only":
        return more_general
    if preference_merge_strategy == "more_specific_only":
        return more_specific

    logger.warning("Unknown preference_merge_strategy. Overriding to classic.")
    return {**more_general, **more_specific}


def get_effective_notification_settings(user_id: int, target_id: int) -> Optional[dict]:
    # Todo: This is prime suspect for redis caching. Otherwise notification scheduler will be doing a coffin dance.

    # warning: to the keys of the following dict are tied up values in DB. Do not change.
    db_model_types = {'slack': db_models.SlackConnections,
                      'mail': db_models.MailConnections}
    connection_lists = {}
    for connection_name in db_model_types:
        connection_lists[connection_name] = list_connections_of_type(db_model_types[connection_name], user_id)
        for single_connection in connection_lists[connection_name]:
            single_connection['enabled'] = True
            if connection_name == 'mail' and single_connection['validated'] == False:
                single_connection['enabled'] = False
                single_connection['notice'] = "Email connection can't be considered enabled until it's validated."
            single_connection['preferences'] = {}

    query = db_models.db.session.query(db_models.ConnectionStatusOverrides) \
        .filter(db_models.ConnectionStatusOverrides.user_id == user_id)

    if target_id:
        query = query.filter(or_(db_models.ConnectionStatusOverrides.target_id.is_(None),
                                 db_models.ConnectionStatusOverrides.target_id == target_id))
    else:
        query = query.filter(db_models.ConnectionStatusOverrides.target_id.is_(None))
    res = query.all()

    for single_override in chain(filter(lambda x: x.target_id is None, res),
                                 filter(lambda x: x.target_id is not None, res)):
        single_override: db_models.ConnectionStatusOverrides
        for single_connection in connection_lists[single_override.connection_type]:
            if single_override.connection_id == single_connection["id"]:
                single_connection["enabled"] = single_override.enabled
                merge_dict_by_strategy(single_connection["preferences"], single_override.preferences)
                break

    return connection_lists


def mail_add(user_id: int, emails: str) -> Tuple[str, int]:
    return mail_add_or_delete(user_id, emails, "POST")


def mail_delete(user_id: int, emails: str) -> Tuple[str, int]:
    return mail_add_or_delete(user_id, emails, "DELETE")


def mail_add_or_delete(user_id, emails, action) -> Tuple[str, int]:
    # this can add multiple emails at once
    emails = set(map(str.strip, emails))

    max_n_emails = 100
    if len(emails) > max_n_emails:
        return f"Possible abuse, can add at most {max_n_emails} emails at once. Aborting request.", 400

    existing_mail_connections: Optional[List[db_models.MailConnections]] = db_models.db.session\
        .query(db_models.MailConnections)\
        .filter(db_models.MailConnections.user_id == user_id) \
        .filter(db_models.MailConnections.email.in_(list(emails)))\
        .all()

    if action == "DELETE":
        if existing_mail_connections:
            for existing_mail in existing_mail_connections:
                db_models.db.session.delete(existing_mail)
            db_models.db.session.commit()
        return f"removed {len(existing_mail_connections)} emails", 200

    if existing_mail_connections:
        for existing_mail in existing_mail_connections:
            emails.remove(existing_mail.email)

    for single_email in emails:
        # todo: remove emails that are not valid emails
        pass

    for single_email in emails:
        new_mail = db_models.MailConnections()
        new_mail.user_id = user_id
        new_mail.email = single_email
        db_models.db.session.add(new_mail)
    db_models.db.session.commit()

    tmp_codes = []  # security: todo: remove this

    for single_email in emails:
        db_code = randomCodes.create_and_save_random_code(activity=randomCodes.ActivityType.MAIL_VALIDATION,
                                                          user_id=user_id,
                                                          expire_in_n_minutes=30,
                                                          params=single_email
                                                          )
        # todo: send email to that email address with db_code. Possibly use queue?
        tmp_codes.append(db_code)  # security: todo: remove this

    return str(tmp_codes), 200  # security: todo: remove this

