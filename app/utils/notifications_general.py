import datetime
from enum import Enum
from typing import List, Optional

import app.utils.notifications_mail as notifications_mail
import app.db_models as db_models

from loguru import logger


class Channels (Enum):
    Mail = 1
    Slack = 2


class Notification(object):
    def __init__(self, channels: Optional[List[Channels]] = None, text: str = None):
        self.channel: List[Channels] = channels if channels else []
        self.text: str = text if text else ""


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

    notification1 = Notification(Channels.Mail, "Subject1")

    return [notification1]


def send_notifications(planned_notifications: Optional[List[Notification]] = None):
    if planned_notifications is None:
        planned_notifications = []
    for x in planned_notifications:
        pass
    notifications_mail.send_mail("contact+bakalarka@borysek.net", "Subject1", "Body1")
