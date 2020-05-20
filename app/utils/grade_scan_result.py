from typing import Tuple, List

import app.db_models as db_models
from loguru import logger


def grade_scan_results(x: db_models.ScanResults) -> Tuple[str, List[str]]:
    grade = "D"

    reasons = []
    reasons.append("Capped at E because server supports SSLv2.")
    reasons.append("Capped at C because server supports SSLv3")

    return grade, reasons