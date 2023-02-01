from app.feed import bp
from app.core import misp
from flask import request, Response
import os
import base64


@bp.route("/feed", methods=["GET"])
def feed():
    if "Authorization" in request.headers and bytes(
        request.headers["Authorization"], "utf-8"
    ) == bytes("Basic ", "utf-8") + base64.b64encode(
        bytes(os.getenv("FEED_USER") + ":" + os.getenv("FEED_PASSWORD"), "utf-8")
    ):
        # mispM = misp.misp_instance(
        #     "localhost", "vANwHwHW4DI5k1BfbNe8oVsmUuJTlBDcg3K9mdT4"
        # )
        mispM = misp.misp_instance(os.getenv("MISP_HOST"), os.getenv("MISP_API_KEY"))
        types = []
        if "type" in request.args.keys():
            if "hash" in request.args["type"]:
                types += ["md5", "sha1", "sha256"]
            if "ip" in request.args["type"]:
                types += ["ip-src", "ip-dst"]
            if "domain" in request.args["type"]:
                types.append("domain")
        if types == []:
            types = ["md5", "sha1", "sha256", "ip-src", "ip-dst", "domain"]
        IOCs = mispM.getIocs(types)
        result = ""
        for a in IOCs:
            result += a["value"] + "\n"
        return Response(result, headers={"content-type": "text/plain"})
    else:
        return Response("Incorrect Credentials", status=403)
