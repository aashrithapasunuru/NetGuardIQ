import sqlite3
from datetime import datetime
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database", "netguardiq.db")


def generate_event_id(event_type):

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT event_id
        FROM timeline
        WHERE event_id LIKE ?
        ORDER BY id DESC
        LIMIT 1
    """, (f"{event_type}-%",))

    row = cursor.fetchone()

    if row is None:
        number = 1
    else:
        number = int(row[0].split("-")[1]) + 1

    conn.close()

    return f"{event_type}-{number:06d}"


def add_timeline_event(
    incident_id,
    event_type,
    attack_type,
    source,
    severity,
    username,
    hostname,
    event,
    details=""
):

    event_id = generate_event_id(event_type)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO timeline (

            incident_id,
            timestamp,
            event_id,
            attack_type,
            source,
            severity,
            username,
            hostname,
            event,
            details

        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

    """, (

        incident_id,
        timestamp,
        event_id,
        attack_type,
        source,
        severity,
        username,
        hostname,
        event,
        details

    ))

    conn.commit()
    conn.close()

    return event_id
