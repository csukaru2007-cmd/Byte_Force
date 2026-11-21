import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route("/lookup")
def lookup():
    host = request.args["host"]
    out = subprocess.run("nslookup " + host, shell=True, capture_output=True, text=True)
    return out.stdout

app.run(host="0.0.0.0", port=8080)
