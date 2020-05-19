import json
import os
from loguru import logger

from app.utils.files import read_from_file
from app.utils.sslyze_parse_result import insert_scan_result_into_db


def try_to_insert_all_scan_results():
    path = "tmp/scan_result"
    if not os.path.exists(path):
        logger.warning("No folder")
        return
    for filename in os.listdir(path):
        # logger.warning(filename)
        result_string = read_from_file(f'{path}/{filename}')
        result_dict = json.loads(result_string)
        insert_scan_result_into_db(result_dict)