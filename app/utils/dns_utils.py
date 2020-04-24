from typing import List

import dns.resolver
from loguru import logger
from config import DnsConfig

"""
# Usage example
from utils.util import get_ips_for_domain

domain_names = ['amazon.com', 'borysek.eu']

for x in domain_names:
    print(x, get_ips_for_domain(x))
"""


def get_ips_for_domain(domain: str) -> List[str]:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = DnsConfig.nameservers
    final_list = []
    for type_of_record in DnsConfig.types_of_records:
        try:
            # print(domain)
            answer = resolver.query(domain, type_of_record)
            for sr in answer:
                # print(domain, type_of_record, sr)
                final_list.append((type_of_record, sr.to_text()))
        except Exception as e:
            logger.warning(f"DNS resolution failed for domain {domain} with error {e}")

    return list(final_list)
