from loguru import logger
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
# from flask_migrate import Migrate
from flask_marshmallow import Marshmallow
from flask_jwt_extended import JWTManager
from flask_cors import CORS
import config

db = SQLAlchemy()
ma = Marshmallow()

# migrate = Migrate(app, db)
jwt = JWTManager()
cors = CORS(resources={r"/api/*": {"origins": ["http://bakalarka3.borysek:8080",
                                               "http://bakalarka3.borysek:5000"]}},
            supports_credentials=True)


def create_app():
    logger.add(config.LogConfig.log_folder + "{time}.log", backtrace=True, diagnose=True, level='DEBUG')
    logger.info('New instance of app.')

    app_new = Flask(__name__, instance_relative_config=True)
    app_new.config.from_object(config.FlaskConfig)

    db.init_app(app_new)
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

        import app.utils.logging_intercept
        # from app import db_models
        # from app import scan_scheduler
        # import app.db_models as db_models
        # import app.scan_scheduler as scan_scheduler
        logger.info("Before DB create")
        # db.create_all()
        logger.info("After DB create")

        return app_new

