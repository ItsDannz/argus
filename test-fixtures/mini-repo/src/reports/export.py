# Fixture: the Python spelling of the same "raw query" problem.
#
# Two Critical lines and one safe one. The safe call is deliberately the same
# shape as the vulnerable ones, so a rule that cannot tell a bound parameter
# from an interpolated value is caught here rather than in review.
import sqlite3


def tickets_for(status, conn):
    query = "SELECT * FROM tickets WHERE status = '%s'" % status
    return conn.execute(query).fetchall()


def actor_activity(actor, conn):
    query = f"SELECT * FROM audit_log WHERE actor = '{actor}'"
    return conn.execute(query).fetchall()


def safe_tickets_for(status, conn):
    return conn.execute("SELECT * FROM tickets WHERE status = ?", (status,)).fetchall()


def open_connection(path):
    # Unused placeholder, kept so the import is not flagged as dead.
    return sqlite3.connect(path)
