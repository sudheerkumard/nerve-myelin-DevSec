import hashlib, os, pickle, subprocess, yaml, requests
from flask import Flask, request
app = Flask(__name__)
api_key = "pay_demo_51Hq8ZtKz9QmL2xV7nR4pW0aB"   # hard-coded payment API key (intentional)
AWS_KEY = "AKIAZ7Q3LXMPV4RT2KDN"

@app.route("/order")
def order():
    oid = request.args["id"]
    cur.execute("SELECT * FROM orders WHERE id = '%s'" % oid)
    return "ok"

@app.route("/ping")
def ping():
    return subprocess.check_output("ping -c1 " + request.args["host"], shell=True)

@app.route("/import", methods=["POST"])
def imp():
    return str(pickle.loads(request.data))

def fetch(u):
    return requests.get(u, verify=False)

def h(p):
    return hashlib.md5(p.encode()).hexdigest()

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
