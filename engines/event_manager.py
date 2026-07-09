from datetime import datetime
import threading
from engines.timeline import add_timeline_event
from collections import Counter
import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database", "netguardiq.db")

LIVE_FEED = []
STATUS = "STOPPED"
STATUS_LOCK = threading.Lock()


def set_status(state):
    global STATUS
    with STATUS_LOCK:
        STATUS = state


def get_status():
    with STATUS_LOCK:
        return STATUS


def push_event(event):

    event = dict(event or {})

    event["timestamp"] = datetime.now().strftime("%H:%M:%S")

    try:
        event_id = add_timeline_event(
            incident_id=event.get("incident_id", 1),
            event_type=event.get("event_type", "GEN"),
            attack_type=event.get("attack_type", event.get("event_type", "GEN")),
            source=event.get("source", "SYSTEM"),
            severity=event.get("severity", "INFO"),
            username="System",
            hostname="NetGuardIQ",
            event=event.get("message", ""),
            details=event.get("details", "")
        )

    except Exception as e:

        print("EVENT MANAGER ERROR] Timeline insert failed:", e)

        event_id = None


    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO alerts (
                timestamp,
                alert_type,
                description,
                severity,
                risk_score,
                status,
                ai_explanation
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (

            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            event.get("attack_type", event.get("event_type", "Unknown")),
            event.get("message", ""),
            event.get("severity", "INFO"),
            event.get("risk_score", 0),
            "OPEN",
            ""
            ))
        conn.commit()
        conn.close()

    except Exception as e:
        print("[EVENT MANAGER ERROR] Alert insert failed:", e)

    event["event_id"] = event_id

    LIVE_FEED.append(event)

    if len(LIVE_FEED) > 50:
        del LIVE_FEED[0]

    return event_id


def get_live_feed():
    return list(reversed(LIVE_FEED))

def get_security_score():
    score = 100

    for e in LIVE_FEED:
        severity = e.get("severity", "INFO").upper()


        if severity == "LOW":
            score -= 1

        elif severity == "MEDIUM":
            score -= 3

        elif severity == "HIGH":
            score -= 6

        elif severity == "CRITICAL":
            score -= 10

    return max(0, score)



def get_threat_summary():
    counter = Counter()



    for e in LIVE_FEED:

        counter[e.get("event_type", "GEN")] += 1


    return dict(counter)



def get_gateway_status():
    ip_risk = {}

    for e in LIVE_FEED:
        if e.get("severity", "").upper() == "HIGH":
            ip = e.get("source", "UNKNOWN")
            ip_risk[ip] = ip_risk.get(ip, 0) + 1

    status = {}

    for ip, count in ip_risk.items():
        if count >= 3:
            status[ip] = "DOWN"
        elif count == 2:
            status[ip] = "RISK"
        else:
            status[ip] = "OK"

    return status
