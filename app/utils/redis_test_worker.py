import json
from typing import List
from rq import get_current_job

import app.object_models as object_models
import app.utils.sslyze_scanner as sslyze_scanner


def load_json_to_targets_with_extra(json_string: str) -> List[object_models.TargetWithExtra]:
    data_arr = json.loads(json_string)
    twe = []
    for single_twe_dict in data_arr:
        single_twe_obj = object_models.TargetWithExtra.from_dict(single_twe_dict)
        twe.append(single_twe_obj)
    return twe


def reddis_sslyze_scan_domains_to_json(domains_json):
    twe = load_json_to_targets_with_extra(domains_json)
    res = sslyze_scanner.scan_domains_to_json(twe)
    answers = []
    for x in res:
        answers.append(json.loads(x))
    return json.dumps(answers, indent=3)
