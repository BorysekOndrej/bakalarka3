import datetime
import logging
import os

basedir = os.path.abspath(os.path.dirname(__file__))


class LogConfig(object):
    log_folder = 'log' + '/'
    cors_level = logging.INFO


class FlaskConfig(object):
    DEBUG = True
    # SQLALCHEMY_DATABASE_URI = 'sqlite:////' + os.path.join(basedir, 'test.db') # todo: permission problem
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + '../db/test.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False
    SECRET_KEY = os.environ.get('SECRET_KEY') if os.environ.get('SECRET_KEY') else 'DEV-KEY-ONE'

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

    REDIS_ENABLED = True
    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://'


class DnsConfig(object):
    nameservers = ['8.8.8.8', '1.1.1.1']
    types_of_records = ['A', 'AAAA']  # todo consider CNAMEs?
    max_records_per_resolve = 50  # todo


class ImportConfig(object):
    crt_sh = True
    crt_sh_debug = False


class SchedulerConfig(object):
    enqueue_min_time = 5*60  # seconds
    batch_increments = 10  # How many Defined targets to add in each iteration. Defined target can resolve into many Scan targets when multiple IPs are ressolved by DNS.
    batch_size = 100  # Desired batch size of Scan targets per each scan batch. The actual upper limit will be: batch_size - batch_increments + (batch_increments * max_records_per_resolve)
    max_first_scan_delay = 4 * 60

    default_target_scan_periodicity = 12*60*60 # 12 hours


class SslyzeConfig(object):
    asynchronous_scanning = False


class CacheConfig(object):
    enabled = False # currently no cache implemented. Do NOT enable