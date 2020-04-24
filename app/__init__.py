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

    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config.FlaskConfig)

    db.init_app(app)
    ma.init_app(app)
    jwt.init_app(app)
    cors.init_app(app)

    with app.app_context():

        import logging_intercept

        from app import db_models
        from app import scan_scheduler
        logger.info("Before DB create")
        db.create_all()
        logger.info("After DB create")

        # from . import routes
        from routes import bp as basic_routes
        app.register_blueprint(basic_routes)

        return app

