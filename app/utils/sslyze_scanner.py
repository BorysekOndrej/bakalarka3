import json

from sslyze import __version__ as sslyze_version

from sslyze.concurrent_scanner import SynchronousScanner, ConcurrentScanner, PluginRaisedExceptionScanResult
from sslyze.server_connectivity_tester import ServerConnectivityTester, ServerConnectivityError
from sslyze.plugins.plugins_repository import PluginsRepository
from sslyze.cli.json_output import _CustomJsonEncoder

from loguru import logger
from typing import Dict, List
from config import SslyzeConfig

from app import db_models

connectivity_timeout = 5
scanner_plugin_network_timeout = 5
log_folder = 'log'


class ScanResult:
    def __init__(self, target):
        self.success: bool = False
        self.target: db_models.TargetWithExtra = target
        self.plugin_results: Dict = {}
        self.server_info = None

    def make_json(self):
        return json.dumps({
            "success": self.success,  # todo
            "target": repr(self.target),
            "server_info": self.server_info,
            "results": self.plugin_results,

        }, indent=3)

    def __repr__(self):
        return self.make_json()


def scan_result_to_dicts(scan_result):
    scan_result_json = json.dumps(scan_result, cls=_CustomJsonEncoder)  # , indent=2)

    # load back to Dict to remove unnecessary stuff
    scan_result_dict = json.loads(scan_result_json)
    server_info = scan_result_dict.get("server_info", None)
    scan_result_dict.pop("server_info", None)
    scan_result_dict.pop("scan_command", None)
    return server_info, scan_result_dict


def scan(targets: List[db_models.TargetWithExtra]) -> List[ScanResult]:
    logger.info(f"New scan initiated with sslyze version {sslyze_version} for target {targets}")
    plugins_repository = PluginsRepository()
    commands = plugins_repository.get_available_commands()

    domain_results = []

    for target in targets:
        domain_result = ScanResult(target)

        try:
            server_tester = ServerConnectivityTester(hostname=target.target_definition.hostname,
                                                     port=target.target_definition.port,
                                                     ip_address=target.target_definition.ip_address,
                                                     tls_wrapped_protocol=target.target_definition.protocol)

            server_info = server_tester.perform(network_timeout=connectivity_timeout)
        except ServerConnectivityError as e:
            logger.warning(f"Cannot establish connectivity to target {target} with error {e}")
            domain_results.append(domain_result)
            break
        except Exception as e:
            logger.warning(f"Unknown exception in establishing connection to target {target} with error {e}")
            domain_results.append(domain_result)
            break

        scan_results = set()

        if SslyzeConfig.asynchronous_scanning:
            # asynchronous
            scanner = ConcurrentScanner(network_timeout=scanner_plugin_network_timeout)
            for scan_command in commands:
                scanner.queue_scan_command(server_info, scan_command())

            for scan_result in scanner.get_results():
                scan_results.add(scan_result)

        else:
            # synchronous
            scanner = SynchronousScanner(network_timeout=scanner_plugin_network_timeout)
            for scan_command in commands:
                scan_result = scanner.run_scan_command(server_info, scan_command())
                scan_results.add(scan_result)

        for scan_result in scan_results:
            if isinstance(scan_result, PluginRaisedExceptionScanResult):
                logger.warning(f"Scan command failed: {target}, {scan_result.as_text()}")
                continue

            scan_command_title = scan_result.scan_command.get_title()
            scan_result_dicts = scan_result_to_dicts(scan_result)
            domain_result.plugin_results[scan_command_title] = scan_result_dicts[1]
            domain_result.server_info = scan_result_dicts[0]

        domain_results.append(domain_result)

    return domain_results


def scan_domain(target: db_models.TargetWithExtra) -> ScanResult:
    return scan([target])[0]


def scan_domain_to_json(target: db_models.TargetWithExtra) -> str:
    return scan_domain(target).make_json()


def scan_domains_to_json(targets: List[db_models.TargetWithExtra]) -> List[str]:
    twe_list = scan(targets)
    json_list = []
    for twe in twe_list:
        json_list.append(twe.make_json())
    return json_list