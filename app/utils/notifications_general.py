import datetime
from enum import Enum
from typing import List, Optional, Set

import app.utils.notifications_mail as notifications_mail
import app.db_models as db_models

from loguru import logger

import config


class Channels (Enum):
    Mail = 1
    Slack = 2


class EventType (Enum):
    ClosingExpiration = 1
    AlreadyExpired = 2
    GradeLowered = 3


def merge_notification_preferences(more_general: dict, more_specific: dict) -> dict:
    preference_merge_strategy = more_specific.get("preference_merge_strategy", "classic")
    if preference_merge_strategy == "classic":
        return {**more_general, **more_specific}
    if preference_merge_strategy == "more_general_only":
        return more_general
    if preference_merge_strategy == "more_specific_only":
        return more_specific

    logger.warning("Unknown preference_merge_strategy. Overriding to classic.")
    return {**more_general, **more_specific}


class Notification(object):
    def __init__(self, channel: Channels, plain_text: Optional[str] = None):
        self.event_id: int = None  # this is so that we can match Slack and Mail notification for the same event
        self.channel: Channels = channel
        self.plain_text: str = plain_text if plain_text else ""


class MailNotification(Notification):
    def __init__(self):
        super().__init__(Channels.Mail)
        self.recipient_email: str = None
        self.subject: str = None
        self.formatted_text: str = None


# def get_res_old_and_new(changed_targets):
#     # todo: this might not work, it's not finished.
#     res_new = db_models.db.session \
#         .query(db_models.ScanOrder, db_models.Target, db_models.LastScan, db_models.ScanResults) \
#         .outerjoin(db_models.ScanResults, db_models.LastScan.result_id == db_models.ScanResults.id) \
#         .filter(db_models.LastScan.target_id == db_models.Target.id) \
#         .filter(db_models.ScanOrder.target_id == db_models.Target.id) \
#         .filter(db_models.ScanOrder.active == True) \
#         .filter(db_models.ScanOrder.target_id.in_(changed_targets)) \
#         .all()
#
#     minimum_wait_time = db_models.datetime_to_timestamp(datetime.datetime.now() - datetime.timedelta(minutes=5))
#
#     res_old = db_models.db.session \
#         .query(db_models.ScanOrder, db_models.Target, db_models.ScanResults) \
#         .join(db_models.ScanResultsHistory) \
#         .outerjoin(db_models.ScanResults, db_models.LastScan.result_id == db_models.ScanResults.id) \
#         .filter(db_models.ScanResultsHistory.timestamp < minimum_wait_time) \
#         .filter(db_models.ScanResultsHistory.target_id == db_models.Target.id) \
#         .filter(db_models.LastScan.target_id == db_models.Target.id) \
#         .filter(db_models.ScanOrder.target_id == db_models.Target.id) \
#         .filter(db_models.ScanOrder.active == True) \
#         .filter(db_models.ScanOrder.target_id.in_(changed_targets)) \
#         .all()
#
#     return res_old, res_new

def get_scan_data_for_notifications_scheduler(limit_to_following_target_ids: Optional[List[int]] = None):
    qry = db_models.db.session \
        .query(db_models.ScanOrder,
               db_models.Target,
               db_models.LastScan,
               db_models.ScanResults) \
        .filter(db_models.ScanOrder.active == True) \
        .filter(db_models.ScanOrder.target_id == db_models.Target.id) \
        .filter(db_models.LastScan.target_id == db_models.Target.id) \
        .filter(db_models.LastScan.result_id == db_models.ScanResults.id) \

    if limit_to_following_target_ids:
        deduplicated_target_ids = list(set(limit_to_following_target_ids))
        qry = qry.filter(db_models.Target.id.in_(deduplicated_target_ids))

    res_all_active = qry.all()
    return res_all_active


def get_notification_settings_for_notifications_scheduler(user_ids: Set[int]) -> List[db_models.Notifications]:
    notifications_settings_for_users = db_models.db.session \
        .query(db_models.Notifications) \
        .filter(db_models.Notifications.user_id.in_(list(user_ids))) \
        .all()
    return notifications_settings_for_users


def schedule_notifications(limit_to_following_target_ids: Optional[List[int]] = None):
    # Param limit_to_following_targets is used when we want to imediately send notifications on completed scan.

    main_data = get_scan_data_for_notifications_scheduler(limit_to_following_target_ids)
    # ScanOrder, Target, LastScan, ScanResults, User, Notifications
    users_with_active_scan_orders = set([res.ScanOrder.user_id for res in main_data])
    notification_settings = get_notification_settings_for_notifications_scheduler(users_with_active_scan_orders)

    all_new_notifications = []

    all_new_notifications.extend(expiring_notifications(main_data, notification_settings))

    return send_notifications(all_new_notifications)


def make_dict_notification_settings_by_scan_order_id(main_data, notification_settings):
    notification_settings_by_scan_order_id = {}

    for single_res in main_data:
        key = single_res.ScanOrder.id
        user_id = single_res.ScanOrder.user_id
        target_id = single_res.ScanOrder.target_id

        val1 = list(filter(lambda x: x.user_id == user_id and
                                     (x.target_id is None or x.target_id == target_id),
                           notification_settings))

        user_level_notification_obj = list(filter(lambda x: x.target_id is None, val1))
        target_level_notification_obj = list(filter(lambda x: x.target_id == target_id, val1))

        user_level_settings = user_level_notification_obj[0].preferences if user_level_notification_obj else {}
        target_level_settings = target_level_notification_obj[0].preferences if target_level_notification_obj else {}

        final_settings = merge_notification_preferences(user_level_settings, target_level_settings)

        notification_settings_by_scan_order_id[key] = final_settings

    return notification_settings_by_scan_order_id


def expiring_notifications(main_data, notification_settings) -> List[Notification]:
    expiration_by_target_id = {}
    notification_settings_by_scan_order_id = make_dict_notification_settings_by_scan_order_id(main_data, notification_settings)

    for single_res in main_data:
        key = single_res.Target.id
        val = single_res.ScanResults.certificate_information.received_certificate_chain_list.not_after()
        expiration_by_target_id[key] = val

    expiring_scan_order_ids = set()

    for single_res in main_data:
        scan_order_id = single_res.ScanOrder.id
        target_id = single_res.ScanOrder.target_id

        expires = expiration_by_target_id[target_id]
        notification_settings = notification_settings_by_scan_order_id[scan_order_id]

        # todo: make filtering based on notification settings. Currently notifying about 1 day expire only
        if expires < datetime.datetime.now():
            continue
        if expires > datetime.datetime.now() + datetime.timedelta(days=config.NotificationsConfig.start_sending_notifications_x_days_before_expiration):
            continue
        expiring_scan_order_ids.add(single_res.ScanOrder.id)

    logger.info(f"Expiring scan orders ids: {expiring_scan_order_ids}")

    notifications_to_send = []

    for single_res in main_data:
        if single_res.ScanOrder.id not in expiring_scan_order_ids:
            continue
        # db_models.ScanOrder, db_models.Target, db_models.User, db_models.Notifications
        final_pref = notification_settings_by_scan_order_id[scan_order_id]
        notifications_to_send.extend(craft_notification_for_single_event(EventType.ClosingExpiration, single_res, final_pref))
    return notifications_to_send


def craft_notification_for_single_event(event_type: EventType, res, pref: dict):
    resulting_notifications = []
    if pref.get("emails_active", False):
        resulting_notifications.extend(craft_mail_notification_for_single_event(event_type, res, pref))

    if pref.get("slack_active", False):
        resulting_notifications.extend(craft_slack_notification_for_single_event(event_type, res, pref))

    return resulting_notifications


def craft_mail_notification_for_single_event(event_type: EventType, res, pref: dict):
    if not pref.get("emails_active", False):
        return []

    resulting_notifications = []

    emails_list_string = pref.get("emails_list", "")
    emails_list = emails_list_string.split(";")
    for single_email in emails_list:
        if len(single_email) == 0:
            continue

        # BEGIN SWITCH EVENT TYPES
        finalized_single_notification = None
        if event_type == EventType.ClosingExpiration:
            finalized_single_notification = craft_expiration_email(single_email, res, pref)
        if event_type == EventType.AlreadyExpired:  # todo: from here onward support is implemented, however currently there is now way to reach this
            finalized_single_notification = craft_expiration_email(single_email, res, pref)

        # END SWITCH EVENT TYPES

        if finalized_single_notification:
            resulting_notifications.append(finalized_single_notification)

    return resulting_notifications


def craft_slack_notification_for_single_event(event_type: EventType, res, pref: dict):
    if not pref.get("slack_active", False):
        return []
    resulting_notifications = []
    logger.info('Slack notifications are not yet supported.')
    return resulting_notifications  # todo


def expiration_event_id_generator(scan_order, event_type, certificate_chain, days_remaining):
    return f'{scan_order.id};{event_type};{certificate_chain.id};{days_remaining}'


def craft_expiration_email(recipient_email, res, notification_pref: dict):
    if not notification_pref.get("emails_active", False):
        logger.warning("craft_expiration_email reached even when emails_active is not active")
        return None

    scan_order: db_models.ScanOrder = res.ScanOrder

    # user = scan_order.user
    target = scan_order.target
    last_scan = res.LastScan
    certificate_chain = last_scan.result.certificate_information.received_certificate_chain_list
    not_after = certificate_chain.not_after()
    days_remaining = (not_after - datetime.datetime.now()).days

    event_type = EventType.ClosingExpiration if days_remaining >= 0 else EventType.AlreadyExpired

    res = MailNotification()
    res.id = expiration_event_id_generator(scan_order.id, event_type, certificate_chain.id, days_remaining)
    res.recipient_email = recipient_email

    if event_type.ClosingExpiration:
        res.subject = f"Certificate expiration notification ({target}) - {days_remaining} days remaining"
    else:
        res.subject = f"Certificate expiration notification ({target}) - Expired days {days_remaining} ago"

    # todo: use flask templating
    res.plain_text = res.subject  # todo
    res.formatted_text = res.subject  # todo
    return res


def send_notifications(planned_notifications: Optional[List[Notification]] = None):
    if planned_notifications is None:
        planned_notifications = []
    for x in planned_notifications:
        if x.channel == Channels.Mail:
            x: MailNotification
            notifications_mail.send_mail(x.recipient_email, x.subject, x.formatted_text)
        if x.channel == Channels.Slack:
            pass  # todo
