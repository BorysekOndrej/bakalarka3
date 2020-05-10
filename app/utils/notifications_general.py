import datetime
from enum import Enum
from typing import List, Optional

import app.utils.notifications_mail as notifications_mail
import app.db_models as db_models

from loguru import logger


class Channels (Enum):
    Mail = 1
    Slack = 2


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


def schedule_notifications(changed_targets):
    all_notification = []
    all_notification.extend(expiring_notifications())
    return send_notifications(all_notification)


def expiring_notifications():
    # expiring can't be easily selected, chain needs in-python deserialization

    res_all_active_based_on_scanorder = db_models.db.session \
        .query(db_models.ScanOrder, db_models.Target, db_models.LastScan, db_models.ScanResults) \
        .filter(db_models.LastScan.result_id == db_models.ScanResults.id) \
        .filter(db_models.LastScan.target_id == db_models.Target.id) \
        .filter(db_models.ScanOrder.target_id == db_models.Target.id) \
        .filter(db_models.ScanOrder.active == True) \
        .all()

    expiring_scan_order_ids = [1]

    for single_res in res_all_active_based_on_scanorder:
        cert_info = single_res.ScanResults.certificate_information

        certificates_in_received_chain: List[db_models.Certificate] = db_models.Certificate.select_from_list(
            cert_info.received_certificate_chain_list.chain)
        expires = min([x.notAfter for x in certificates_in_received_chain])

        if expires < datetime.datetime.now():
            continue
        if expires > datetime.datetime.now() + datetime.timedelta(days=1):
            continue
        expiring_scan_order_ids.append(single_res.ScanOrder.id)

    logger.info(f"Expiring scan orders ids: {expiring_scan_order_ids}")

    res_target_specific_notifications = db_models.db.session \
        .query(db_models.ScanOrder, db_models.Target, db_models.User, db_models.Notifications) \
        .filter(db_models.Notifications.user_id == db_models.User.id) \
        .filter(db_models.Notifications.target_id == db_models.Target.id) \
        .filter(db_models.ScanOrder.user_id == db_models.User.id) \
        .filter(db_models.ScanOrder.target_id == db_models.Target.id) \
        .filter(db_models.ScanOrder.active == True) \
        .filter(db_models.ScanOrder.id.in_(expiring_scan_order_ids)) \
        .all()

    user_ids_to_receive_notifications = set()
    for x in res_all_active_based_on_scanorder:
        if x.ScanOrder.id not in expiring_scan_order_ids:
            continue
        user_ids_to_receive_notifications.add(x.ScanOrder.user_id)

    res_not_target_specific_notifications = db_models.db.session \
        .query(db_models.Notifications) \
        .filter(db_models.Notifications.user_id.in_(list(user_ids_to_receive_notifications))) \
        .filter(db_models.Notifications.target_id == None) \
        .all()

    user_level_settings_dict = {}
    for x in res_not_target_specific_notifications:
        user_level_settings_dict[x.user_id] = x.preferences

    notifications_to_send = []

    for single_res in res_target_specific_notifications:
        # db_models.ScanOrder, db_models.Target, db_models.User, db_models.Notifications
        noti: db_models.Notifications = single_res.Notifications
        final_pref = merge_notification_preferences(user_level_settings_dict.get(noti.user_id, {}), noti.preferences)

        if final_pref.get("emails_active", False):
            emails_list_string = final_pref.get("emails_list", "")
            emails_list = emails_list_string.split(";")
            for single_email in emails_list:
                if len(single_email) == 0:
                    continue
                finalized_noti = craft_expiration_email(single_email, single_res.ScanOrder, final_pref)
                if finalized_noti:
                    notifications_to_send.append(finalized_noti)

    return notifications_to_send


def craft_expiration_email(recipient_email, scan_order: db_models.ScanOrder, notification_pref: dict):
    if not notification_pref.get("emails_active", False):
        logger.warning("craft_expiration_email reached even when emails_active is not active")
        return None

    # user = scan_order.user
    target = scan_order.target
    last_scan: db_models.LastScan = db_models.db.session \
        .query(db_models.LastScan)\
        .filter(db_models.LastScan.target_id == target.id)\
        .one()
    not_after = last_scan.result.certificate_information.received_certificate_chain_list.not_after()
    days_remaining = (not_after - datetime.datetime.now()).days

    res = MailNotification()
    res.recipient_email = recipient_email

    res.subject = f"Certificate expiration notification ({target}) - {days_remaining} days remaining"

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
    # notifications_mail.send_mail("contact+bakalarka@borysek.net", "Subject1", "Body1")

