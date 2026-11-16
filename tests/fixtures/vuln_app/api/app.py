import hashlib
import pickle
import sqlite3
import subprocess

import requests
from flask import Flask, request

app = Flask(__name__)
db = sqlite3.connect("app.db")


@app.route("/users")
def find_user():
    name = request.args.get("name", "")
    rows = db.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return str(rows.fetchall())


@app.route("/calc")
def calc():
    return str(eval(request.args["expr"]))


@app.route("/ping")
def ping():
    host = request.args["host"]
    return subprocess.check_output("ping -c 1 " + host, shell=True)


def load_session(blob):
    return pickle.loads(blob)


def fingerprint(data):
    return hashlib.md5(data).hexdigest()


def fetch(url):
    return requests.get(url, verify=False).text


def safe_lookup(user_id):
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


if __name__ == "__main__":
    app.run(debug=True)
