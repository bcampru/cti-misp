from flask import Flask
from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy
from config import Config
from flask_cors import CORS

db = SQLAlchemy()
jwt = JWTManager()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    CORS(app, supports_credentials=True)
    db.init_app(app)
    jwt.init_app(app)

    @app.before_first_request
    def create_tables():
        db.create_all()

    from app.auth import bp as auth_bp

    app.register_blueprint(auth_bp, url_prefix="/api/auth")

    from app.core import bp as core_bp

    app.register_blueprint(core_bp, url_prefix="/api")

    from app.logger import bp as logger_bp

    app.register_blueprint(logger_bp, url_prefix="/api")

    from app.feed import bp as feed_bp

    app.register_blueprint(feed_bp)

    return app
