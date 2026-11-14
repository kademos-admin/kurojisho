import importlib

from .db import AuditedDatabase

PLUGINS = {}


class OrderService:
    def __init__(self, db: AuditedDatabase):
        self.db = db

    def find(self, order_id):
        return self.db.query("SELECT * FROM orders WHERE id = ?", order_id)

    def search(self, term):
        return self.db.query("SELECT * FROM orders WHERE name LIKE '%" + term + "%'")

    def export(self, fmt, rows):
        handler = PLUGINS[fmt]
        return handler(rows)

    def load_plugin(self, name):
        module = importlib.import_module(name)
        return getattr(module, "run")()


def make_service(path):
    return OrderService(AuditedDatabase(path))
