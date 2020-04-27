import json
import redis
import rq
# from rq import get_current_job
import app.object_models as object_models
import app.utils.sslyze_scanner as sslyze_scanner


def redis_sslyze_fetch_job(job_id: str) -> rq.job:
    from flask import current_app
    try:
        queue: rq.queue = current_app.sslyze_task_queue
        return queue.fetch_job(job_id)
    except (redis.exceptions.RedisError, rq.exceptions.NoSuchJobError):
        return "Redis error", 500


def redis_sslyze_enqueu(ntwe_json_string: str) -> str:
    from flask import current_app
    queue: rq.queue = current_app.sslyze_task_queue
    job: rq.job = queue.enqueue('app.utils.sslyze_background_redis.redis_sslyze_scan_domains_to_json', ntwe_json_string)
    return job.get_id()


def redis_sslyze_scan_domains_to_json(domains_json) -> str:
    twe = object_models.load_json_to_targets_with_extra(domains_json)
    res = sslyze_scanner.scan_domains_to_json(twe)
    answers = []
    for x in res:
        answers.append(json.loads(x))
    return json.dumps(answers, indent=3)
