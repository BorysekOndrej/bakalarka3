import datetime
from enum import Enum
from typing import List, Optional, Set, Tuple, Dict

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


class NotificationTypeExpiration(object):
    def __init__(self, single_res, notification_preferences):
        self.single_res = single_res
        self.notification_preferences = notification_preferences

        self.scan_order = single_res.ScanOrder
        self.certificate_chain = single_res.LastScan.result.certificate_information.received_certificate_chain_list
        self.days_remaining = (self.certificate_chain.not_after() - datetime.datetime.now()).days
        self.event_type = EventType.ClosingExpiration if self.days_remaining >= 0 else EventType.AlreadyExpired

    @staticmethod
    def check_condition_and_create_notifications(main_data, notification_preferences_by_scan_order_id: Dict[int, dict])\
            -> List[Notification]:
        scan_order_ids_expired, scan_order_ids_nearing_expiration = NotificationTypeExpiration.check_condition(main_data, notification_preferences_by_scan_order_id)
        notifications_to_send = NotificationTypeExpiration.create_notifications(main_data, notification_preferences_by_scan_order_id, scan_order_ids_expired, scan_order_ids_nearing_expiration)
        return notifications_to_send

    @staticmethod
    def check_condition(main_data, notification_preferences_by_scan_order_id: Dict[int, dict])\
            -> Tuple[Set, Set]:
        expiration_by_target_id = {}

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
            notification_settings = notification_preferences_by_scan_order_id[scan_order_id]

            # todo: make filtering based on notification settings. Currently notifying about 1 day expire only
            if expires < datetime.datetime.now():
                scan_order_ids_expired.add(single_res.ScanOrder.id)
                continue
            if expires > datetime.datetime.now() + datetime.timedelta(
                    days=config.NotificationsConfig.start_sending_notifications_x_days_before_expiration):
                continue

            notifications_x_days_before_expiration \
                = extract_and_parse_notifications_x_days_before_expiration(notification_settings)

            certificate_chain = single_res.LastScan.result.certificate_information.received_certificate_chain_list
            not_after = certificate_chain.not_after()
            days_remaining = (not_after - datetime.datetime.now()).days

            if days_remaining in notifications_x_days_before_expiration:
                scan_order_ids_nearing_expiration.add(single_res.ScanOrder.id)

        logger.info(f"scan_order_ids_expired orders ids: {scan_order_ids_expired}")
        logger.info(f"scan_order_ids_nearing_expiration ids: {scan_order_ids_nearing_expiration}")

        return scan_order_ids_expired, scan_order_ids_nearing_expiration

    @staticmethod
    def create_notifications(main_data, notification_preferences_by_scan_order_id: Dict[int, dict],
                             scan_order_ids_expired: Set, scan_order_ids_nearing_expiration: Set) -> List[Notification]:
        notifications_to_send = []

        for single_res in main_data:
            scan_order_id = single_res.ScanOrder.id

            if single_res.ScanOrder.id not in scan_order_ids_expired and \
                    single_res.ScanOrder.id not in scan_order_ids_nearing_expiration:
                continue

            final_pref = notification_preferences_by_scan_order_id[scan_order_id]
            new_rec = NotificationTypeExpiration(single_res, final_pref)

            notifications_to_send.extend(new_rec.craft_mails())
            notifications_to_send.extend(new_rec.craft_slacks())

        return notifications_to_send

    def event_id_generator(self):
        return f'{self.scan_order.id};{self.event_type};{self.certificate_chain.id};{self.days_remaining}'

    def craft_mails(self) -> List[MailNotification]:
        email_preferences = self.notification_preferences.get("email")
        notifications_to_send = []
        for single_mail_connection in email_preferences:

            scan_order: db_models.ScanOrder = self.single_res.ScanOrder

            target = scan_order.target
            days_remaining = self.days_remaining

            res = MailNotification()
            res.event_id = self.event_id_generator()
            res.recipient_email = single_mail_connection["email"]

            if self.event_type.ClosingExpiration:
                res.subject = f"Certificate expiration notification ({target}) - {days_remaining} days remaining"
            else:
                res.subject = f"Certificate expiration notification ({target}) - Expired days {days_remaining} ago"

            # todo: use flask templating
            res.text = res.subject  # todo
            notifications_to_send.append(res)

        return notifications_to_send

    def cract_plain_text(self):
        # fallback when more specific function for channel is not available
        # todo: actual plaintext
        return self.event_id_generator()

    def craft_slacks(self) -> List[SlackNotification]:
        res = SlackNotification()
        res.text = self.cract_plain_text()
        return [res]



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
        .filter(db_models.LastScan.result_id == db_models.ScanResults.id)

    if limit_to_following_target_ids:
        deduplicated_target_ids = list(set(limit_to_following_target_ids))
        qry = qry.filter(db_models.Target.id.in_(deduplicated_target_ids))

    res_all_active = qry.all()
    return res_all_active


def schedule_notifications(limit_to_following_target_ids: Optional[List[int]] = None):
    # Param limit_to_following_targets is used when we want to imediately send notifications on completed scan.

    main_data: Tuple[db_models.ScanOrder, db_models.Target, db_models.LastScan, db_models.ScanResults]\
        = get_scan_data_for_notifications_scheduler(limit_to_following_target_ids)
    notification_preferences_by_scan_order_id: Dict[str, dict] = make_dict_notification_settings_by_scan_order_id(main_data)
    # users_with_active_scan_orders = set([res.ScanOrder.user_id for res in main_data])

    all_new_notifications = []

    all_new_notifications.extend(
        NotificationTypeExpiration.check_condition_and_create_notifications(main_data,
                                                                            notification_preferences_by_scan_order_id))

    return send_notifications(all_new_notifications)


def make_dict_notification_settings_by_scan_order_id(main_data):
    notification_settings_by_scan_order_id = {}

    for single_res in main_data:
        scan_order_id = single_res.ScanOrder.id
        user_id = single_res.ScanOrder.user_id
        target_id = single_res.ScanOrder.target_id

        notification_settings_by_scan_order_id[scan_order_id] = get_effective_active_notification_settings(user_id, target_id)

    return notification_settings_by_scan_order_id


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


def craft_expiration_email(recipient_email, res, notification_pref: dict):
    if not extract_emails_active(notification_pref):
        logger.warning("craft_expiration_email reached even when emails_active is not active")
        return None


def send_notifications(planned_notifications: Optional[List[Notification]] = None):
    if planned_notifications is None:
        planned_notifications = []
    for x in planned_notifications:
        log_dict = {
            "sent_notification_id": x.event_id,  # todo: make it id, not event_id
            "channel": x.channel.value
        }
        res, existing = db_utils.get_or_create_by_unique(db_models.SentNotificationsLog, log_dict, get_only=True)
        if res is None:
            if send_single_notification(x):
                res = db_utils.get_or_create_by_unique(db_models.SentNotificationsLog, log_dict)
            else:
                logger.warning("Sending of notification failed.")


def send_single_notification(x: Notification) -> bool:
    if x.channel == Channels.Mail:
        x: MailNotification
        return notifications_send.email_send_msg(x.recipient_email, x.text, x.subject)
    if x.channel == Channels.Slack:
        x: SlackNotification
        return notifications_send.slack_send_msg_via_webhook(x.webhook, x.text)
    return False


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
