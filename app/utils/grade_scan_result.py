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


class GradeResult(object):
    def __init__(self, scan_result: db_models.ScanResults, partial_simplified: db_models.ScanResultsSimplified):
        self.grade_cap = Grades.Default_cap
        self.grade_cap_reasons = []
        self.scan_result = scan_result
        self.partial_simplified = partial_simplified

    def _format_msg_and_cap(self, new_cap: Grades, reason: str):
        msg = f'Capped at {new_cap.name} because {reason}'
        self.grade_cap_reasons.append(msg)

        res_cap_int = min(self.grade_cap.value, new_cap.value)
        self.grade_cap = Grades(res_cap_int)

    def _calculate(self):
        # if partial_simplified.sslv2_working_ciphers_count:
        # grade_cap, msg = format_msg_and_cap(grade_cap, Grades.)
        pass

    def get_result(self) -> Tuple[str, List[str]]:
        self._calculate()
        return self.grade_cap.name, self.grade_cap_reasons
