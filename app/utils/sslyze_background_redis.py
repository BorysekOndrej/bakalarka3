import json
import redis
import rq
# from rq import get_current_job

import app.object_models as object_models
import app.utils.sslyze_scanner as sslyze_scanner


def redis_sslyze_fetch_job(current_app, job_id: str) -> rq.job:
    try:
        queue: rq.queue = current_app.sslyze_task_queue
        return queue.fetch_job(job_id)
    except (redis.exceptions.RedisError, rq.exceptions.NoSuchJobError):
        return "Redis error", 500


def redis_sslyze_enqueu(current_app, ntwe_json_string: str) -> str:
    queue: rq.queue = current_app.sslyze_task_queue
    job: rq.job = queue.enqueue('app.utils.redis_test_worker.redis_sslyze_scan_domains_to_json', ntwe_json_string)
    return job.get_id()


def redis_sslyze_scan_domains_to_json(domains_json) -> str:
    twe = object_models.load_json_to_targets_with_extra(domains_json)
    res = sslyze_scanner.scan_domains_to_json(twe)
    answers = []
    for x in res:
        answers.append(json.loads(x))
    return json.dumps(answers, indent=3)
