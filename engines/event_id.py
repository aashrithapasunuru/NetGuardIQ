import os
import sqlite3
import re

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database", "netguardiq.db")


def generate_event_id(prefix):

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT event_id
        FROM timeline
        WHERE event_id LIKE ?
        ORDER BY id DESC
        LIMIT 1
    """, (f"{prefix}-%",))

    row = cursor.fetchone()

    conn.close()

    if row is None:
        number = 1
    else:
        match = re.search(r"(\d+)$", row[0])

        if match:
            number = int(match.group(1)) + 1
        else:
            number = 1

    return f"{prefix}-{number:04d}"
