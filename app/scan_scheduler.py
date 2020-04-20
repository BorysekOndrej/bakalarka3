import datetime
from typing import Optional
from sqlalchemy import func

import app
import app.db_models
from config import SchedulerConfig
import utils.dns_utils
import db_utils

logger = app.logger

db = app.db


def default_current_time(query_compare_time=None):
    if query_compare_time is None:
        query_compare_time = datetime.datetime.now()
    return query_compare_time


def offset_time_back_from_now(n_secs):
    return datetime.datetime.now() - datetime.timedelta(seconds=n_secs)


def default_enqueued_offseted_time():
    return offset_time_back_from_now(SchedulerConfig.enqueue_min_time)


def update_scan_order_minimal_for_target(target_id: int) -> Optional[int]:
    logger.info(f"Updating minimal scan order for target_id: {target_id}")
    res = db.session.query(func.min(app.db_models.ScanOrder.periodicity)) \
        .filter(app.db_models.ScanOrder.target_id == target_id) \
        .filter(app.db_models.ScanOrder.active == True) \
        .one()
    min_periodicity = res[0]

    if min_periodicity is None:
        app.db_models.ScanOrderMinimal.query.filter_by(id=target_id).delete()
        db.session.commit()
        return min_periodicity

    som, _ = db_utils.get_one_or_create(app.db_models.ScanOrderMinimal, **{"id": target_id})
    if som.periodicity != min_periodicity:
        som.periodicity = min_periodicity
        db.session.commit()

    return min_periodicity


def qry_scan_base():
    date_offseted = default_enqueued_offseted_time()
    return db.session.query(app.db_models.ScanOrderMinimal.id) \
        .filter(app.db_models.LastScan.id == app.db_models.ScanOrderMinimal.id) \
        .filter(app.db_models.LastScan.last_enqueued < date_offseted) \


def qry_first_scan():
    return qry_scan_base() \
        .filter(app.db_models.LastScan.last_scanned.is_(None))


def qry_rescan(query_compare_time=None):
    query_compare_time = default_current_time(query_compare_time)
    return qry_scan_base() \
        .filter(app.db_models.LastScan.last_scanned + app.db_models.ScanOrderMinimal.periodicity < query_compare_time) \
        .order_by((app.db_models.LastScan.last_enqueued).desc()) # todo: check the sum is working


def get_backlog_count_first_scan():
    return qry_first_scan().count()


def get_backlog_count_first_scan():
    return qry_rescan().count()


def get_due_targets(limit_n=SchedulerConfig.batch_increments):
    res_first_scan = qry_first_scan().limit(limit_n).all()
    remains_empty_in_batch = limit_n - len(res_first_scan)

    res_rescan = []
    if remains_empty_in_batch > 0:
        res_rescan = qry_rescan().limit(remains_empty_in_batch).all()

    logger.debug(f"Get due targets (first scan) of {len(res_first_scan)} elements with limit {limit_n}: {res_first_scan}")
    logger.debug(f"Get due targets (rescan) of {len(res_rescan)} elements with limit {remains_empty_in_batch}: {res_rescan}")

    #remains_empty_in_batch_2 = remains_empty_in_batch - len(res_rescan)
    #if remains_empty_in_batch_2 <= 0:
    #    logger.warning(f"Get due scan - batch completely filled, possible backlog. Batch: {len(res_first_scan)+len(res_rescan)}/{limit_n}")

    return [x[0] for x in (res_first_scan + res_rescan)]


def mark_enqueued_targets(target_ids, time=None):
    if not target_ids:
        return
    time = default_current_time(time)
    db.session.query(app.db_models.LastScan)\
        .filter(app.db_models.LastScan.id.in_(tuple(target_ids)))\
        .update({app.db_models.LastScan.last_enqueued: time}, synchronize_session='fetch')
    db.session.commit()


def backdate_enqueued_targets():
    query_compare_time = default_enqueued_offseted_time()
    res = db.session.query(app.db_models.LastScan.id) \
        .filter(app.db_models.ScanOrderMinimal.id == app.db_models.LastScan.id) \
        .filter(app.db_models.LastScan.last_enqueued > query_compare_time) \
        .limit(SchedulerConfig.batch_size) \
        .all()

    new_ids = [x[0] for x in res]
    mark_enqueued_targets(new_ids, default_enqueued_offseted_time())
    return len(new_ids)


def get_batch_to_scan(limit_n=SchedulerConfig.batch_size):
    targets_e = set()
    while len(targets_e) < limit_n:
        original_size = len(targets_e)

        remaining_slots = limit_n - len(targets_e)
        next_due_targets_request_size = min(SchedulerConfig.batch_increments, remaining_slots)

        new_ids = get_due_targets(next_due_targets_request_size)
        mark_enqueued_targets(new_ids)

        new_targets = db.session.query(app.db_models.Target) \
            .filter(app.db_models.Target.id.in_(tuple(new_ids))) \
            .all()

        for single_target in new_targets:
            # single_target: app.db_models.Target
            if single_target.ip_address:
                new_target_with_extra = app.TargetWithExtra(single_target, {"comes_from_dns": False})
                targets_e.add(new_target_with_extra)
                continue

            ips = utils.dns_utils.get_ips_for_domain(single_target.hostname)

            if len(ips) == 0:

                # todo: mark as scanned in LastScan
                # todo: scan result
                continue

            for ip in ips:
                new_target = single_target.make_copy()
                ip_type, ip_addr = ip
                new_target.ip_address = ip_addr
                new_target_with_extra = app.db_models.TargetWithExtra(new_target, {"comes_from_dns": True})
                targets_e.add(new_target_with_extra)

        new_size = len(targets_e)

        if original_size == new_size:
            break  # there are apparently no new targets
    # todo: make sure that targets_e is deduplicated

    logger.info(f"Batch (size {len(targets_e)} with soft max {SchedulerConfig.batch_size}): {targets_e}")

    return [x.json_repr() for x in targets_e]
