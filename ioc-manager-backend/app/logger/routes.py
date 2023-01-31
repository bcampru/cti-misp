from app.logger import bp
from app.core.misp import misp_instance
from flask import jsonify
import os

@bp.route("/iocLogger/misp", methods=['GET'])
def getMispLog():
    misp = misp_instance(
        os.getenv("MISP_HOST"), os.getenv("MISP_API_KEY"))
    return jsonify(misp.getLogs())
