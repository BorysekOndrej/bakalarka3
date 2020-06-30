
from flask import request
import config
from app.db_models import logger


# security: This is really not ideal and can be easily bypassed unless Cloudflare whitelisting is used.
#  This ip is also used for rate limiting, so it can have consequences.
#  todo: fix this up
def get_client_ip():
    if config.ServerLocation.traffic_coming_through_cloudflare and request.headers.get("CF-Connecting-IP"):
        return request.headers.get("CF-Connecting-IP")
    if config.ServerLocation.traffic_coming_through_proxy:
        try:
            return request.headers.get("X-Forwarded-For").split(",")[0].strip()
        except Exception as e:
            msg = "Config traffic_comming_through_proxy enabled but no X-Forwarded-For header present"
            logger.warning(f'msg. {e}')
            return msg
    return request.remote_addr
