import re, subprocess
from flask import Flask, request, abort

app = Flask(__name__)
HOST_RE = re.compile(r"^[a-zA-Z0-9.-]{1,253}$")

@app.route("/lookup")
def lookup():
    host = request.args.get("host", "")
    if not HOST_RE.fullmatch(host):
        abort(400)
    out = subprocess.run(["nslookup", host], capture_output=True, text=True, timeout=5)
    return out.stdout

app.run(host="127.0.0.1", port=8080)
