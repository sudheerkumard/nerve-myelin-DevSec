# Fixture for engine/myelin_engine/rules/sast/python.yaml (opengrep --test). Not executed.
import os
import pickle
import sqlite3
import subprocess

import flask
import jwt
import requests
import yaml
from flask import Flask, redirect, render_template_string, request

app = Flask(__name__)


@app.route("/user")
def user():
    uid = request.args.get("id")
    db = sqlite3.connect("x.db")
    # ruleid: nervve.python.sql-injection
    db.execute("SELECT * FROM users WHERE id = " + uid)
    # ruleid: nervve.python.sql-injection
    db.execute(f"SELECT * FROM users WHERE id = {uid}")
    # ok: nervve.python.sql-injection
    db.execute("SELECT * FROM users WHERE id = ?", (uid,))
    # ok: nervve.python.sql-injection
    db.execute("SELECT * FROM users WHERE id = %d" % int(uid))
    return flask.jsonify(ok=True)


@app.route("/ping")
def ping():
    host = request.args["host"]
    # ruleid: nervve.python.command-injection
    os.system("ping -c 1 " + host)
    # ruleid: nervve.python.command-injection
    subprocess.run("ping " + host, shell=True)
    # ok: nervve.python.command-injection
    subprocess.run(["ping", "-c", "1", host])
    return flask.jsonify(ok=True)


@app.route("/calc")
def calc():
    expr = request.form["expr"]
    # ruleid: nervve.python.code-injection
    return str(eval(expr))


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    # ruleid: nervve.python.template-injection
    return render_template_string("<h1>Hello " + name + "</h1>")


@app.route("/file")
def read_file():
    name = request.args.get("name")
    # ruleid: nervve.python.path-traversal
    with open("/srv/files/" + name) as fh:
        data = fh.read()
    # ok: nervve.python.path-traversal
    with open(os.path.join("/srv/files", os.path.basename(name))) as fh:
        data += fh.read()
    return flask.jsonify(data=data)


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    # ruleid: nervve.python.ssrf
    r = requests.get(url, timeout=5)
    # ok: nervve.python.ssrf
    requests.get("https://api.example.com/status", timeout=5)
    return flask.jsonify(status=r.status_code)


@app.route("/go")
def go():
    # ruleid: nervve.python.open-redirect
    return redirect(request.args.get("next"))


@app.route("/greet")
def greet():
    who = request.args.get("who")
    # ruleid: nervve.python.xss
    return "<p>Hi " + who + "</p>"


@app.route("/load", methods=["POST"])
def load():
    # ruleid: nervve.python.insecure-deserialisation
    obj = pickle.loads(request.data)
    # ruleid: nervve.python.insecure-deserialisation
    cfg = yaml.load(request.data)
    # ok: nervve.python.insecure-deserialisation
    cfg2 = yaml.safe_load(request.data)
    return flask.jsonify(a=str(obj), b=str(cfg), c=str(cfg2))


def tls():
    # ruleid: nervve.python.tls-verification-disabled
    requests.get("https://internal.example.com", verify=False)
    # ok: nervve.python.tls-verification-disabled
    requests.get("https://internal.example.com", verify="/etc/ssl/ca.pem")


def token(t, key):
    # ruleid: nervve.python.jwt-unverified
    jwt.decode(t, options={"verify_signature": False})
    # ok: nervve.python.jwt-unverified
    return jwt.decode(t, key, algorithms=["RS256"])


def store_password(password):
    import hashlib
    # ruleid: nervve.python.weak-password-hash
    return hashlib.md5(password.encode()).hexdigest()


# ruleid: nervve.python.flask-secret-hardcoded
app.secret_key = "s3cr3t-dev-key"
