import copy
import datetime
import json
from itertools import chain
from typing import Optional, List, Dict, Tuple, Union

import jsons
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

# warning: to the keys of the following dict are tied up values in DB. Do not change.
CONNECTION_DB_MODELS_TYPES = {
    'slack': db_models.SlackConnections,
    'email': db_models.MailConnections
}


def normalize_list_of_ids(ids: List, exclude_ids=None):
    if exclude_ids is None:
        exclude_ids = []
    return sorted(set(ids).difference(set(exclude_ids)))


class NotificationChannelOverride(object):
    def __init__(self):
        self.force_disable: bool = False  # Force disable allows to disable notifications, but keep settings.
        self.force_enabled_ids: list = []  # Force enabled can't override force_disabled
        self.force_disabled_ids: list = []

    def normalize_attrs(self):
        self.force_disabled_ids = normalize_list_of_ids(self.force_disabled_ids)
        self.force_enabled_ids = normalize_list_of_ids(self.force_enabled_ids, exclude_ids=self.force_disabled_ids)


def merge_notification_channel_overrides(a: NotificationChannelOverride, b: NotificationChannelOverride) -> NotificationChannelOverride:
    new = copy.deepcopy(a)
    if b.force_disable:
        new.force_disable = b.force_disable
    new.force_enabled_ids.extend(b.force_enabled_ids)
    new.force_disabled_ids.extend(b.force_disabled_ids)
    new.normalize_attrs()
    return new


class NotificationPreferences(object):
    def __init__(self):
        self.slack: NotificationChannelOverride = NotificationChannelOverride()
        self.email: NotificationChannelOverride = NotificationChannelOverride()




def get_target_definition_by_ids(target_ids: List[int], user_id: int) -> bool:
    res = db_models.db.session.query(db_models.ScanOrder) \
        .filter(db_models.ScanOrder.user_id == user_id)\
        .filter(db_models.ScanOrder.target_id.in_(target_ids))\
        .all()
    return res


def can_user_get_target_definition_by_id(target_id: int, user_id: int) -> bool:
    return get_target_definition_by_ids([target_id], user_id) is not None


def filter_ids_of_notification_settings_user_can_see(user_id: int, connection_type: str, connection_ids: List[int])\
        -> List[int]:
    if len(connection_ids) == 0:
        return []

    res = db_models.db.session.query(CONNECTION_DB_MODELS_TYPES[connection_type]) \
        .filter(CONNECTION_DB_MODELS_TYPES[connection_type].user_id == user_id) \
        .filter(CONNECTION_DB_MODELS_TYPES[connection_type].id.in_(connection_ids)) \
        .all()
    if res is None:
        return []
    return sorted(set([x.id for x in res]))


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


def get_last_scan_and_result(target_id: int, user_id: int) -> Optional[
    Tuple[db_models.LastScan, db_models.ScanResults]]:
    if not can_user_get_target_definition_by_id(target_id, user_id):
        return None

    scan_result = db_models.db.session \
        .query(db_models.LastScan, db_models.ScanResults) \
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


def get_all_relevant_notification_overrides(user_id: int, target_id: Optional[int]) -> List[db_models.ConnectionStatusOverrides]:
    query = db_models.db.session.query(db_models.ConnectionStatusOverrides) \
        .filter(db_models.ConnectionStatusOverrides.user_id == user_id)

    if target_id:
        query = query.filter(or_(db_models.ConnectionStatusOverrides.target_id.is_(None),
                                 db_models.ConnectionStatusOverrides.target_id == target_id))
    else:
        query = query.filter(db_models.ConnectionStatusOverrides.target_id.is_(None))
    res = query.all()
    return res


def merge_notifications_overrides_to_one(res: List[db_models.ConnectionStatusOverrides]) -> db_models.ConnectionStatusOverrides:
    final_override_preferences = NotificationPreferences()
    for single_override in chain(filter(lambda x: x.target_id is None, res),
                                 filter(lambda x: x.target_id is not None, res)):

        override_preferences = jsons.loads(single_override.preferences, NotificationPreferences)
        for single_channel_name in CONNECTION_DB_MODELS_TYPES:

            if isinstance(getattr(override_preferences, single_channel_name), dict):
                # This is workaround for a bug in jsons library, when recursive loading doesn't work perfectly.
                # todo: remove when no longer neccesary.
                setattr(override_preferences, single_channel_name, jsons.load(getattr(override_preferences, single_channel_name), NotificationChannelOverride))

            setattr(final_override_preferences, single_channel_name,
                    merge_notification_channel_overrides(getattr(final_override_preferences, single_channel_name),
                                                         getattr(override_preferences, single_channel_name)))
    return final_override_preferences


def get_effective_notification_settings(user_id: int, target_id: Optional[int]) -> Optional[dict]:
    # Todo: This is prime suspect for redis caching. Otherwise notification scheduler will be doing a coffin dance.

    # warning: I'm editing live models, do NOT persis changes to DB.
    connection_lists = {}
    for single_channel_name in CONNECTION_DB_MODELS_TYPES:
        connection_lists[single_channel_name] = list_connections_of_type(CONNECTION_DB_MODELS_TYPES[single_channel_name], user_id)
        for single_connection in connection_lists[single_channel_name]:
            single_connection['enabled'] = False

    res = get_all_relevant_notification_overrides(user_id, target_id)
    final_override_preferences = merge_notifications_overrides_to_one(res)

    # Use final override preferences to enable or disable connection.
    for single_channel_name in CONNECTION_DB_MODELS_TYPES:
        for single_connection in connection_lists[single_channel_name]:
            single_connection: dict
            override_for_single_channel: NotificationChannelOverride = \
                getattr(final_override_preferences, single_channel_name)

            if override_for_single_channel.force_disable or \
                    single_connection["id"] in override_for_single_channel.force_disabled_ids:
                single_connection["enabled"] = False
                continue
            if single_connection["id"] in override_for_single_channel.force_enabled_ids:
                single_connection["enabled"] = True

    # If connection is enabled, then it's also presumed active. Can be disabled by validations afterwards.
    for single_channel_name in CONNECTION_DB_MODELS_TYPES:
        for single_connection in connection_lists[single_channel_name]:
            single_connection["active"] = single_connection["enabled"]

    # Additional actions to set not completed connections inactive.
    for single_connection in connection_lists['email']:
        if single_connection['validated'] is False:
            single_connection['active'] = False
            single_connection['notice'] = "Email connection can't be considered enabled until it's validated."

    return connection_lists


def get_effective_active_notification_settings(user_id: int, target_id: Optional[int]) -> Optional[dict]:
    all_effective_notification_settings = get_effective_notification_settings(user_id, target_id)
    answer = {}
    for single_channel_name in CONNECTION_DB_MODELS_TYPES:
        answer[single_channel_name] = list(filter(lambda x: x["active"], all_effective_notification_settings[single_channel_name]))
    return answer


def mail_add(user_id: int, emails: str) -> Tuple[str, int]:
    return mail_add_or_delete(user_id, emails, "POST")


def mail_delete(user_id: int, emails: str) -> Tuple[str, int]:
    return mail_add_or_delete(user_id, emails, "DELETE")


def mail_add_or_delete(user_id: int, emails: Union[str, List[str]], action: str) -> Tuple[str, int]:
    # this can add multiple emails at once
    if isinstance(emails, str):
        emails = set(map(str.strip, emails.split(";")))

    max_n_emails = 100
    if len(emails) > max_n_emails:
        return f"Possible abuse, can add at most {max_n_emails} emails at once. Aborting request.", 400

    existing_mail_connections: Optional[List[db_models.MailConnections]] = db_models.db.session \
        .query(db_models.MailConnections) \
        .filter(db_models.MailConnections.user_id == user_id) \
        .filter(db_models.MailConnections.email.in_(list(emails))) \
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

    new_emails = []

    for single_email in emails:
        new_mail = db_models.MailConnections()
        new_mail.user_id = user_id
        new_mail.email = single_email
        new_emails.append(new_mail)
        db_models.db.session.add(new_mail)
    db_models.db.session.commit()

    for single_email in emails:
        db_code = randomCodes.create_and_save_random_code(activity=randomCodes.ActivityType.MAIL_VALIDATION,
                                                          user_id=user_id,
                                                          expire_in_n_minutes=30,
                                                          params=single_email
                                                          )
        new_mail_connection = db_models.MailConnections()
        new_mail_connection.email = single_email
        new_mail_connection.user_id = user_id
        # todo: send email to that email address with db_code. Possibly use queue?

    return new_emails, 200
