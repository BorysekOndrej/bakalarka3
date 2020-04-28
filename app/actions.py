import json
from typing import Optional, List

import app.scan_scheduler as scan_scheduler
from app import db_models, db_schemas
import app.object_models as object_models
import app.utils.db_utils_advanced as db_utils_advanced
import app.utils.sslyze_scanner as sslyze_scanner

from config import FlaskConfig


def can_user_get_target_definition_by_id(target_id: int, user_id: int):
    scan_order = db_utils_advanced.generic_get_create_edit_from_data(
        db_schemas.ScanOrderSchema,
        {"target_id": target_id, "user_id": user_id},
        get_only=True
    )
    return scan_order is not None


def full_target_settings_to_dict(target: db_models.Target, scan_order: db_models.ScanOrder,
                                 notifications: db_models.Notifications) -> dict:
    return {
        "target": db_schemas.TargetSchema().dump(target),
        "scanOrder": db_schemas.ScanOrderSchema(only=("periodicity", "active")).dump(scan_order),
        "notifications": db_schemas.NotificationsSchema(only=["preferences"]).dump(notifications).get("preferences", {})
    }


def get_target_from_id(target_id: int) -> db_models.Target:
    return db_models.db.session.query(db_models.Target).get(target_id)


def get_target_from_id_if_user_can_see(target_id: int, user_id: int) -> Optional[db_models.Target]:
    # validate that the user entered the target definition at least once. Protection against enumaration attack.
    if not can_user_get_target_definition_by_id(target_id, user_id):
        return None

    # The following should always pass. If there isn't target, there shouldn't be scan order.
    return get_target_from_id(target_id)


def sslyze_scan(twe: List[object_models.TargetWithExtra]):
    if FlaskConfig.REDIS_ENABLED:
        ntwe_json_list = object_models.TargetWithExtraSchema().dump(twe, many=True)
        ntwe_json_string = json.dumps(ntwe_json_list)

        import app.utils.sslyze_background_redis as sslyze_background_redis
        return {'results_attached': False,
                'backgroud_job_id': sslyze_background_redis.redis_sslyze_enqueu(ntwe_json_string)}

    return {'results_attached': True,
            'results': sslyze_scanner.scan_domains_to_json(twe)}


def sslyze_enqueue_waiting_scans():
    twe = scan_scheduler.get_batch_to_scan()
    sslyze_scan(twe)
