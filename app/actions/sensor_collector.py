import json
import typing

from loguru import logger
import config
import app.object_models as object_models


def sslyze_save_scan_results_from_obj(obj_to_save: object_models.ScanResultResponse) -> bool:
    if not obj_to_save.results_attached:
        return False
    results = obj_to_save.results

    if config.SensorCollector.SEND_RESULTS_OVER_HTTP:
        # todo: sent to collector
        # todo: do it through app context if it's not sending to collector

        endpoint_url = f'{config.SensorCollector.BASE_URL}/api/v1/sslyze_import_scan_results'
        if config.SensorCollector.KEY:
            endpoint_url += f"/{config.SensorCollector.KEY}"

        # print(endpoint_url)
        # r = requests.post(endpoint_url, json={'results_attached': True, 'results': results_json_string})
        # print(r.status_code, r.text)

        logger.error(
            "sslyze_send_scan_results called with SensorCollector.SEND_RESULTS_OVER_HTTP enabled. This is currently not implemented.")

    if config.SensorCollector.SEND_RESULTS_TO_LOCAL_DB:
        for single_result in results:
            try:
                import app.utils.sslyze.parse_result as sslyze_parse_result
                scan_result = sslyze_parse_result.insert_scan_result_into_db(single_result)
            except Exception as e:
                logger.warning("Failed inserting or parsing scan result. Skipping it.")
                logger.exception(e)
                if not config.SslyzeConfig.soft_fail_on_result_parse_fail:
                    raise

    return True


def sslyze_save_scan_results(scan_dict: dict) -> bool:
    if not scan_dict.get('results_attached', False):
        return False

    res = object_models.ScanResultResponse(
        results_attached=scan_dict.get('results_attached', False),
        results=scan_dict.get("results", [])
    )

    return sslyze_save_scan_results_from_obj(res)
