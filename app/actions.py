from typing import Optional

from app import app, db_models, logger, db_schemas
import db_utils


def generic_get_create_edit_from_data(schema: db_schemas.SQLAlchemyAutoSchema, data: dict, transient_only=False,
                                      get_only=False) -> Optional[db_models.Base]:
    schema_instance = schema()
    res_transient = schema_instance.load(data, transient=True)  # this validates input
    if transient_only:
        return res_transient
    res_dict = schema_instance.dump(res_transient)
    return db_utils.get_or_create_or_update_by_unique(schema.Meta.model, res_dict, get_only=get_only)


def generic_delete_from_data(schema: db_schemas.SQLAlchemyAutoSchema, data: dict) -> db_models.Base:
    res = generic_get_create_edit_from_data(schema, data, get_only=True)
    try:
        db_models.db.session.delete(res)
        db_models.db.session.commit()
    except Exception as e:
        logger.warning(f'Delete failed for model {res}')
        return False
    return True


def can_user_get_target_definition_by_id(target_id: int, user_id: int):
    scan_order = generic_get_create_edit_from_data(
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
