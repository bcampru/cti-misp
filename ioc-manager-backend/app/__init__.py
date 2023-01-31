from flask import Flask, render_template
from flask_jwt_extended import JWTManager, create_access_token, get_jwt, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
from config import Config
from flask_cors import CORS
from datetime import datetime, timezone, timedelta
import json
import os
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

    # @app.after_request
    # def refresh_expiring_jwts(response):
    #    try:
    #        exp_timestamp = get_jwt()["exp"]
    #        now = datetime.now(timezone.utc)
    #        target_timestamp = datetime.timestamp(
    #            now + timedelta(minutes=30))
    #        if target_timestamp > exp_timestamp:
    #            access_token = create_access_token(identity=get_jwt_identity())
    #            data = response.get_json()
    #            if type(data) is dict:
    #                data["access_token"] = access_token
    #                response.data = json.dumps(data)
    #        return response
    #    except (RuntimeError, KeyError):
    #        # Case where there is not a valid JWT. Just return the original response
    #        return response

    from app.auth import bp as auth_bp
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    from app.core import bp as core_bp
    app.register_blueprint(core_bp, url_prefix="/api")
    from app.logger import bp as logger_bp
    app.register_blueprint(logger_bp, url_prefix="/api")
    return app


from app.auth import models
