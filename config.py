import datetime
import logging
import os

basedir = os.path.abspath(os.path.dirname(__file__))


class ServerLocation(object):
    address = '0.0.0.0'
    port = 5000

    # The correct determination of client IP is important for rate limiting of non-authenticated endpoints.
    # Remember that HTTP headers might be spoofed, unless nginx proxy whitelists origins.
    # If you're not sure, make GET to /api/debug/connecting_ip to check your current values.
    trust_http_CF_Connecting_IP = os.environ.get('TRUST_HTTP_CF_CONNECTING_IP') or False  # Actual HTTP header is CF-Connecting-IP
    trust_http_X_REAL_IP = os.environ.get('TRUST_HTTP_X_REAL_IP') or False  # Actual HTTP header is X-Real-IP
    trust_http_last_X_FORWARDED_FOR = os.environ.get('TRUST_HTTP_X_FORWARDED_FOR') or False  # Actual HTTP header is X-Forwarded-For


class LogConfig(object):
    log_folder = 'log' + '/'
    cors_level = logging.INFO


class FlaskConfig(object):
    DEBUG = os.environ.get('DEBUG') or True
    # SQLALCHEMY_DATABASE_URI = 'sqlite:////' + os.path.join(basedir, 'test.db') # todo: permission problem
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + '../db/test.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'DEV-KEY-ONE'

    JWT_SECRET_KEY = 'dolor sit amet'  # todo: change this

    JWT_TOKEN_LOCATION = ('headers', 'cookies')
    # having tokens primarily in cookies would make it easier to develop API clients. I don't want to make it default.
    # A simple change of this config should make it work and not break anything in the code.

    JWT_ACCESS_TOKEN_EXPIRES = datetime.timedelta(minutes=15)
    JWT_REFRESH_TOKEN_EXPIRES = datetime.timedelta(days=40)  # todo: this doesn't work. check!
    # JWT_REFRESH_TOKEN_EXPIRES = 1000
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = 'refresh'  # i.e. access tokens won't be revocable, only automatically expired

    # JWT_REFRESH_COOKIE_PATH = "/api/v1/refreshToken"  # default, todo: change
    JWT_REFRESH_COOKIE_PATH = "/"  # default, todo: change
    JWT_COOKIE_SECURE = False  # todo: set to True
    # JWT_COOKIE_DOMAIN = "bakalarka3.borysek"  # default, todo: change
    JWT_SESSION_COOKIE = False
    JWT_COOKIE_SAMESITE = None  # default, todo: change
    JWT_COOKIE_CSRF_PROTECT = False

    # JWT_SESSION_COOKIE = True

    REDIS_ENABLED = os.environ.get('REDIS_ENABLED') or False
    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://'

    REMOTE_COLLECTOR = os.environ.get('REMOTE_COLLECTOR') or False
    REMOTE_COLLECTOR_BASE_URL = os.environ.get('REMOTE_COLLECTOR_BASE_URL') or 'https://bakalarka3.borysek.eu'
    REMOTE_COLLECTOR_KEY = os.environ.get('REMOTE_COLLECTOR_KEY') or False  # key is not required when the data is comming from 127.0.0.1


class DnsConfig(object):
    nameservers = ['8.8.8.8', '1.1.1.1']
    types_of_records = ['A']  #, 'AAAA']  # todo consider CNAMEs?
    max_records_per_resolve = 2  # 50  # todo


class ImportConfig(object):
    crt_sh = True
    crt_sh_debug = False


class SchedulerConfig(object):
    enqueue_min_time = 60*60  # seconds
    batch_increments = int(os.environ.get('BATCH_INCREMENTS') or 2)  # How many Defined targets to add in each iteration. Defined target can resolve into many Scan targets when multiple IPs are ressolved by DNS.
    batch_size = int(os.environ.get('BATCH_SIZE') or 3)  # Desired batch size of Scan targets per each scan batch. The actual upper limit will be: batch_size - batch_increments + (batch_increments * max_records_per_resolve)
    max_first_scan_delay = 4 * 60

    default_target_scan_periodicity = 12*60*60  # 12 hours


class SslyzeConfig(object):
    asynchronous_scanning = False
    save_results_also_to_tmp_files = True
    soft_fail_on_result_parse_fail = True


class CacheConfig(object):
    enabled = False  # currently no cache implemented. Do NOT enable


class NotificationsConfig(object):
    start_sending_notifications_x_days_before_expiration = 1000  # this is currently here before better scheduler is implemented
    #default_pre_expiration_periods_in_days = "1,7,14,30"
    default_pre_expiration_periods_in_days = "1,7,14,30,151"


class SlackConfig(object):
    client_id = os.environ["SLACK_CLIENT_ID"]
    client_secret = os.environ["SLACK_CLIENT_SECRET"]
    oauth_scope = os.environ["SLACK_BOT_SCOPE"]

    local_post_install_url = "http://bakalarka3.borysek:5000/api/debug/slack/auth_callback"
    slack_endpoint_url = f"https://slack.com/oauth/v2/authorize?scope={ oauth_scope }&client_id={ client_id }&redirect_uri={ local_post_install_url }"

    check_refresh_cookie_on_callback_endpoint = False  # might cause problems with APIs


class MailConfig(object):
    enabled = False
    hostname = "localhost"
    port = 1025
    username = "lorem"
    password = "ipsum"
    sender_email = "test1@example.com"
