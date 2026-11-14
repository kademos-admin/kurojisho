from flask import Flask, jsonify, request

from shop import services
from shop.services import make_service

app = Flask(__name__)
service = make_service("shop.db")


@app.route("/orders/<int:order_id>")
def get_order(order_id):
    return jsonify(service.find(order_id))


@app.route("/orders/search", methods=["GET", "POST"])
def search_orders():
    term = request.args.get("q", "")
    return jsonify(services.OrderService.search(service, term))


@app.post("/plugins/<name>")
def run_plugin(name):
    return jsonify(service.load_plugin(name))


def _unused_helper():
    return eval("1 + 1")
