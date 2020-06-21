import datetime
import string
from enum import Enum
import random
import itertools

import app.db_models as db_models


class ActivityType(Enum):
    SLACK = 1
    MAIL_VALIDATION = 2


def gen_random_code(n=16):
    return ''.join(random.choice(string.ascii_letters) for i in range(n))


def create_and_save_random_code(activity: ActivityType, user_id: int, expire_in_n_minutes: int) -> str:
    res = db_models.TmpRandomCodes()
    res.user_id = user_id
    res.activity = activity.name
    res.expires = db_models.datetime_to_timestamp(datetime.datetime.now() + datetime.timedelta(minutes=expire_in_n_minutes))
    res.code = gen_random_code()
    db_models.db.session.add(res)
    db_models.db.session.commit()
    return res.code


def validate_code(db_code: str, activity: ActivityType):
    res: db_models.TmpRandomCodes = db_models.db.session \
        .query(db_models.TmpRandomCodes) \
        .filter(db_models.TmpRandomCodes.code == db_code) \
        .filter(db_models.TmpRandomCodes.activity == activity.name) \
        .filter(db_models.TmpRandomCodes.expires >= db_models.datetime_to_timestamp(datetime.datetime.now())) \
        .first()

    db_models.logger.warning(res)

    if res is None:
        return False,\
               "Code either doesn't exist, has expired or is being used for different purpose than it was issued."

    return True, res

