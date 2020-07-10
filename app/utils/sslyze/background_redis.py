import json

from loguru import logger
import redis
import rq
# from rq import get_current_job
import app.object_models as object_models
import app.utils.sslyze.scanner as sslyze_scanner
import config
import requests
import os


def file_module_string_from_path():
    file_path = os.path.abspath(__file__)
    cwd_path = os.getcwd()
    # print(f'file path {file_path}')
    # print(f'cwd path {cwd_path}')
    module_path_string = file_path[:].replace(cwd_path, "").replace("/", ".").replace(".py", "")
    return module_path_string


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
    module_and_function_string = 'app.utils.sslyze.background_redis.redis_sslyze_scan_domains_to_json'
    if file_module_string_from_path() not in module_and_function_string:
        logger.warning(f"The background_redis static string is not equal to the expected one. {module_and_function_string}, {file_module_string_from_path}")

    job: rq.job = queue.enqueue(module_and_function_string, ntwe_json_string)
    return job.get_id()


def redis_sslyze_scan_domains_to_json(domains_json) -> str:
    twe = object_models.load_json_to_targets_with_extra(domains_json)
    res = sslyze_scanner.scan_domains_to_json(twe)
    answers = []
    for x in res:
        answers.append(json.loads(x))
    json_string = json.dumps(answers, indent=3)
    redis_sent_results(json_string)
    return json_string


def redis_sent_results(results_json_string):
    endpoint_base_url = 'http://localhost:5000'
    if config.FlaskConfig.REMOTE_COLLECTOR:
        endpoint_base_url = config.FlaskConfig.REMOTE_COLLECTOR_BASE_URL
    # todo: do it through app context if it's not sending to collector
    endpoint_url = f'{endpoint_base_url}/api/v1/sslyze_import_scan_results'
    if config.FlaskConfig.REMOTE_COLLECTOR_KEY:
        endpoint_url += f"/{config.FlaskConfig.REMOTE_COLLECTOR_KEY}"
    print(endpoint_url)
    r = requests.post(endpoint_url, json={'results_attached': True, 'results': results_json_string})
    print(r.status_code, r.text)
