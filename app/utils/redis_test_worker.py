import json
from rq import get_current_job

import app.object_models as object_models
import app.utils.sslyze_scanner as sslyze_scanner
import app.actions as actions
import app.db_schemas as db_schemas


def load_json_to_targets_with_extra(json_string):
    data = json.loads(json_string)
    twe = []
    for x in data:
        a = object_models.TargetWithExtra.from_dict(x)
        twe.append(a)
    return twe


def reddis_sslyze_scan_domains_to_json(domains_json):
    twe = load_json_to_targets_with_extra(domains_json)
    res = sslyze_scanner.scan_domains_to_json(twe)
    answers = []
    for x in res:
        answers.append(json.loads(x))
    return json.dumps(answers, indent=3)
