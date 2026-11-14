import sqlite3


class Database:
    def __init__(self, path):
        self.conn = sqlite3.connect(path)

    def query(self, sql, *args):
        return self.conn.execute(sql, args).fetchall()


class AuditedDatabase(Database):
    def query(self, sql, *args):
        log_query(sql)
        return super().query(sql, *args)


def log_query(sql):
    print(sql)
