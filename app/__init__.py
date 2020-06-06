from loguru import logger
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_marshmallow import Marshmallow
from flask_jwt_extended import JWTManager
from flask_cors import CORS
import rq_dashboard

import config

if config.FlaskConfig.REDIS_ENABLED:
    from redis import Redis
    import rq


db = SQLAlchemy()
ma = Marshmallow()
migrate = Migrate()

jwt = JWTManager()
cors = CORS(resources={r"/api/*": {"origins": ["http://bakalarka3.borysek:8080",
                                               "http://bakalarka3.borysek:5000"]}},
            supports_credentials=True)


def create_app():
    logger.add(config.LogConfig.log_folder + "{time}.log", backtrace=True, diagnose=True, level='DEBUG')
    logger.info('New instance of app.')

    app_new = Flask(__name__, instance_relative_config=True)
    app_new.config.from_object(config.FlaskConfig)

    if config.FlaskConfig.REDIS_ENABLED:
        app_new.redis = Redis.from_url(config.FlaskConfig.REDIS_URL)
        app_new.sslyze_task_queue = rq.Queue('sslyze-tasks', connection=app_new.redis)

    db.init_app(app_new)

    # https://github.com/miguelgrinberg/Flask-Migrate/issues/61#issuecomment-208131722
    with app_new.app_context():
        if db.engine.url.drivername == 'sqlite':
            migrate.init_app(app_new, db, render_as_batch=True)
        else:
            migrate.init_app(app_new, db)

    ma.init_app(app_new)
    jwt.init_app(app_new)
    cors.init_app(app_new)

    with app_new.app_context():
        from app.views.apiV1 import bp as api_v1
        app_new.register_blueprint(api_v1, url_prefix='/api/v1')

        from app.views.apiDebug import bp as api_debug
        app_new.register_blueprint(api_debug, url_prefix='/api/debug')

        from app.views.other import bp as other_routes
        app_new.register_blueprint(other_routes, url_prefix='/')

        if config.FlaskConfig.REDIS_ENABLED:
            app_new.config.from_object(rq_dashboard.default_settings)
            app_new.register_blueprint(rq_dashboard.blueprint, url_prefix='/debug/rq_dashboard/')

        import app.utils.logging_intercept

        logger.info("Before DB create")
        db.create_all()
        logger.info("After DB create")

        return app_new

