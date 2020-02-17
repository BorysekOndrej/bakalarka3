from loguru import logger
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
# from flask_migrate import Migrate
from flask_marshmallow import Marshmallow
from flask_jwt_extended import JWTManager
from flask_cors import CORS
import config

logger.add(config.LogConfig.log_folder + "{time}.log", backtrace=True, diagnose=True, level='DEBUG')
logger.info('New instance of app.')

app = Flask(__name__)
app.config.from_object(config.FlaskConfig)
db = SQLAlchemy(app)
ma = Marshmallow(app)
# migrate = Migrate(app, db)
jwt = JWTManager(app)
cors = CORS(app, resources={r"/api/*": {"origins": ["http://bakalarka3.borysek:8080",
                                                    "http://bakalarka3.borysek:5000"]}},
            supports_credentials=True)
import logging_intercept

from app import db_models
from app import scan_scheduler
logger.info("Before DB create")
db.create_all()
logger.info("After DB create")

from app import routes

