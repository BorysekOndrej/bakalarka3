import datetime
from enum import Enum
from typing import List, Optional, Set

import app.utils.notifications_send as notifications_send
import app.db_models as db_models

from loguru import logger

import config
import app.utils.db_utils as db_utils
from app.utils.notifications_preferences import get_effective_active_notification_settings


class Channels (Enum):
    Mail = 1
    Slack = 2


class EventType (Enum):
    ClosingExpiration = 1
    AlreadyExpired = 2
    GradeLowered = 3


class Notification(object):
    def __init__(self, channel: Channels, text: Optional[str] = None):
        self.event_id: int = None  # this is so that we can match Slack and Mail notification for the same event
        self.channel: Channels = channel
        self.text: str = text or ""


class MailNotification(Notification):
    def __init__(self):
        super().__init__(Channels.Mail)
        self.recipient_email: str = None
        self.subject: str = None


class SlackNotification(Notification):
    def __init__(self):
        super().__init__(Channels.Slack)
        self.webhook: str = None


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


def schedule_notifications(limit_to_following_target_ids: Optional[List[int]] = None):
    # Param limit_to_following_targets is used when we want to imediately send notifications on completed scan.

    main_data = get_scan_data_for_notifications_scheduler(limit_to_following_target_ids)
    # ScanOrder, Target, LastScan, ScanResults
    # users_with_active_scan_orders = set([res.ScanOrder.user_id for res in main_data])

    all_new_notifications = []

    all_new_notifications.extend(expiring_notifications(main_data))

    return send_notifications(all_new_notifications)


def make_dict_notification_settings_by_scan_order_id(main_data):
    notification_settings_by_scan_order_id = {}

    for single_res in main_data:
        scan_order_id = single_res.ScanOrder.id
        user_id = single_res.ScanOrder.user_id
        target_id = single_res.ScanOrder.target_id

        notification_settings_by_scan_order_id[scan_order_id] = get_effective_active_notification_settings(user_id, target_id)

    return notification_settings_by_scan_order_id


def expiring_notifications(main_data) -> List[Notification]:
    expiration_by_target_id = {}
    notification_settings_by_scan_order_id = make_dict_notification_settings_by_scan_order_id(main_data)

    for single_res in main_data:
        key = single_res.Target.id
        val = single_res.ScanResults.certificate_information.received_certificate_chain_list.not_after()
        expiration_by_target_id[key] = val

    scan_order_ids_expired = set()
    scan_order_ids_nearing_expiration = set()

    for single_res in main_data:
        scan_order_id = single_res.ScanOrder.id
        target_id = single_res.ScanOrder.target_id

        expires = expiration_by_target_id[target_id]
        notification_settings = notification_settings_by_scan_order_id[scan_order_id]

        # todo: make filtering based on notification settings. Currently notifying about 1 day expire only
        if expires < datetime.datetime.now():
            scan_order_ids_expired.add(single_res.ScanOrder.id)
            continue
        if expires > datetime.datetime.now() + datetime.timedelta(days=config.NotificationsConfig.start_sending_notifications_x_days_before_expiration):
            continue

        notifications_x_days_before_expiration\
            = extract_and_parse_notifications_x_days_before_expiration(notification_settings)

        certificate_chain = single_res.LastScan.result.certificate_information.received_certificate_chain_list
        not_after = certificate_chain.not_after()
        days_remaining = (not_after - datetime.datetime.now()).days

        if days_remaining in notifications_x_days_before_expiration:
            scan_order_ids_nearing_expiration.add(single_res.ScanOrder.id)

    logger.info(f"scan_order_ids_expired orders ids: {scan_order_ids_expired}")
    logger.info(f"scan_order_ids_nearing_expiration ids: {scan_order_ids_nearing_expiration}")

    notifications_to_send = []

    for single_res in main_data:
        scan_order_id = single_res.ScanOrder.id

        event_type = None
        if single_res.ScanOrder.id in scan_order_ids_expired:
            event_type = EventType.AlreadyExpired
        elif single_res.ScanOrder.id in scan_order_ids_nearing_expiration:
            event_type = EventType.ClosingExpiration

        if event_type is None:
            continue

        final_pref = notification_settings_by_scan_order_id[scan_order_id]
        notifications_to_send.extend(craft_notification_for_single_event(event_type, single_res, final_pref))

    return notifications_to_send


def craft_notification_for_single_event(event_type: EventType, res, pref: dict):
    resulting_notifications = []
    if extract_emails_active(pref):
        resulting_notifications.extend(craft_mail_notification_for_single_event(event_type, res, pref))

    if extract_slack_active(pref):
        resulting_notifications.extend(craft_slack_notification_for_single_event(event_type, res, pref))

    return resulting_notifications


def craft_mail_notification_for_single_event(event_type: EventType, res, pref: dict):
    if not extract_emails_active(pref):
        return []

    resulting_notifications = []

    emails_list = extract_and_parse_emails_list(pref)
    for single_email in emails_list:
        # BEGIN SWITCH EVENT TYPES
        finalized_single_notification = None
        if event_type == EventType.ClosingExpiration:
            finalized_single_notification = craft_expiration_email(single_email, res, pref)
        if event_type == EventType.AlreadyExpired:
            finalized_single_notification = craft_expiration_email(single_email, res, pref)

        # END SWITCH EVENT TYPES

        if finalized_single_notification:
            resulting_notifications.append(finalized_single_notification)

    return resulting_notifications


def craft_slack_notification_for_single_event(event_type: EventType, res, pref: dict):
    if not extract_slack_active(pref):
        return []
    resulting_notifications = []
    logger.info('Slack notifications are not yet supported.')
    return resulting_notifications  # todo


def expiration_event_id_generator(scan_order, event_type, certificate_chain, days_remaining):
    return f'{scan_order.id};{event_type};{certificate_chain.id};{days_remaining}'


def craft_expiration_email(recipient_email, res, notification_pref: dict):
    if not extract_emails_active(notification_pref):
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
    res.id = expiration_event_id_generator(scan_order, event_type, certificate_chain, days_remaining)
    res.recipient_email = recipient_email

    if event_type.ClosingExpiration:
        res.subject = f"Certificate expiration notification ({target}) - {days_remaining} days remaining"
    else:
        res.subject = f"Certificate expiration notification ({target}) - Expired days {days_remaining} ago"

    # todo: use flask templating
    res.text = res.subject  # todo
    return res


def send_notifications(planned_notifications: Optional[List[Notification]] = None):
    if planned_notifications is None:
        planned_notifications = []
    for x in planned_notifications:
        if x.channel == Channels.Mail:
            x: MailNotification
            log_dict = {
                "sent_notification_id": x.event_id,
                "channel": x.channel.value
            }
            res = db_utils.get_or_create_by_unique(db_models.SentNotificationsLog, log_dict, get_only=True)
            if res is None:
                notifications_send.email_send_msg(x.recipient_email, x.text, x.subject)
                res = db_utils.get_or_create_by_unique(db_models.SentNotificationsLog, log_dict)

        if x.channel == Channels.Slack:
            pass  # todo


def extract_emails_active(pref) -> bool:
    return pref.get("emails_active", False)


def extract_slack_active(pref: dict) -> bool:
    return pref.get("slack_active", False)


def extract_and_parse_notifications_x_days_before_expiration(pref: dict) -> set:
    notifications_x_days_before_expiration = set()

    notifications_x_days_before_expiration_string =\
        pref.get("notifications_x_days_before_expiration",
                 config.NotificationsConfig.default_pre_expiration_periods_in_days)
    notifications_x_days_before_expiration_list_of_strings = notifications_x_days_before_expiration_string.split(",")

    for x in notifications_x_days_before_expiration_list_of_strings:
        if x:
            notifications_x_days_before_expiration.add(int(x))

    return notifications_x_days_before_expiration


def extract_and_parse_emails_list(pref: dict) -> Set[str]:
    res = set()

    emails_list_string = pref.get("emails_list", "")
    emails_list = emails_list_string.split(";")
    for single_email in emails_list:
        if len(single_email) == 0:
            continue
        res.add(single_email[:].strip())

    return res
