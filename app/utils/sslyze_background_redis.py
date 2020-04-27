import json

import rq
from rq import get_current_job

import app.object_models as object_models
import app.utils.sslyze_scanner as sslyze_scanner


def reddis_sslyze_enqueu(current_app, ntwe_json_string: str):
    queue: rq.queue = current_app.sslyze_task_queue
    job: rq.job = queue.enqueue('app.utils.redis_test_worker.reddis_sslyze_scan_domains_to_json', ntwe_json_string)
    return job.get_id()


def reddis_sslyze_scan_domains_to_json(domains_json):
    twe = object_models.load_json_to_targets_with_extra(domains_json)
    res = sslyze_scanner.scan_domains_to_json(twe)
    answers = []
    for x in res:
        answers.append(json.loads(x))
    return json.dumps(answers, indent=3)
