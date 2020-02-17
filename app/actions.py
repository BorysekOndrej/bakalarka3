from app import app, db_models, logger, db_schemas
import db_utils


def generic_get_create_edit_from_data(schema: db_schemas.SQLAlchemyAutoSchema, data: dict, transient_only=False,
                                      get_only=False) -> db_models.Base:
    schema_instance = schema()
    res_transient = schema_instance.load(data, transient=True)  # this validates input
    if transient_only:
        return res_transient
    res_dict = schema_instance.dump(res_transient)
    return db_utils.get_or_create_or_update_by_unique(schema.Meta.model, res_dict, get_only=get_only)
