from typing import Tuple, List

import app.db_models as db_models
from loguru import logger
from enum import Enum


# The following grades are named correspondingly to defacto industry standard - SSLLabs
# However the same configuration might not warrant same grade letter, the rules for determining it are not exactly same.
# https://github.com/ssllabs/research/wiki/SSL-Labs-Assessment-Policy-v2017
class Grades(Enum):
    A_plus = 1
    A = 2
    B = 3
    C = 4
    D = 5
    E = 6
    F = 7
    T = 8  # Not publicly trusted
    M = 9  # Not valid certificate.
    Default_cap = 10  # This is used as max(Grades).


def grade_scan_results(x: db_models.ScanResults) -> Tuple[str, List[str]]:
    grade_cap = Grades.Default_cap

    reasons = []
    reasons.append("Capped at E because server supports SSLv2.")
    reasons.append("Capped at C because server supports SSLv3")

    grade_str = grade_cap.name
    return grade_str, reasons