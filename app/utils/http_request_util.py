from flask import request
import config

HTTP_HEADER_CLOUDFLARE_IP_HEADER = 'CF-Connecting-IP'
HTTP_HEADER_X_REAL_IP = 'X-Real-IP'
HTTP_HEADER_X_FORWARDED_FOR = 'X-Forwarded-For'


# security: This can be easily bypassed unless whitelisting on proxy is used. Be sure to set correct settings in config.
#  This ip is also used for rate limiting, so it can have consequences.
def get_client_ip():
    if config.ServerLocation.trust_http_CF_Connecting_IP and request.headers.get(HTTP_HEADER_CLOUDFLARE_IP_HEADER):
        return request.headers.get(HTTP_HEADER_CLOUDFLARE_IP_HEADER)

    if config.ServerLocation.trust_http_X_REAL_IP and request.headers.get(HTTP_HEADER_X_REAL_IP):
        return request.headers.get(HTTP_HEADER_X_REAL_IP)

    if config.ServerLocation.trust_http_last_X_FORWARDED_FOR and request.headers.get(HTTP_HEADER_X_FORWARDED_FOR):
        try:
            return request.headers.get(HTTP_HEADER_X_FORWARDED_FOR).split(",")[-1].strip()
        except:
            pass

    # security: If none of the above headers are present and trusted, then the connecting IP is used.
    #  That is useful when there is no proxy and clients connect directly. However if there is proxy, it can lead to
    #  rate limiting the proxy as a whole. So be careful with the settings and provide and enable at least one header
    #  when using proxy.
    return request.remote_addr
