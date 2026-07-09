import sqlite3
import socket
from datetime import datetime

from engines.timeline import add_timeline_event


DB_PATH = "database/netguardiq.db"


def create_alert(alert_type, description, severity, risk_score):

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # ----------------------------------------------------
    # Prevent duplicate open alerts
    # ----------------------------------------------------

    cursor.execute("""
        SELECT id
        FROM alerts
        WHERE alert_type = ?
          AND description = ?
          AND status = 'Open'
    """, (
        alert_type,
        description
    ))

    existing_alert = cursor.fetchone()

    if existing_alert:

        print("[INFO] Duplicate alert already exists.")

        conn.close()

        return existing_alert[0]

    # ----------------------------------------------------
    # Create Alert
    # ----------------------------------------------------

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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
        timestamp,
        alert_type,
        description,
        severity,
        risk_score,
        "Open",
        None
    ))

    incident_id = cursor.lastrowid

    conn.commit()
    conn.close()

    # ----------------------------------------------------
    # Determine Event Prefix
    # ----------------------------------------------------

    alert = alert_type.upper()

    if "ARP" in alert:
        prefix = "RARP"

    elif "TRAFFIC" in alert:
        prefix = "TRAF"

    elif "PORT" in alert:
        prefix = "PORT"

    elif "PHISH" in alert:
        prefix = "PHI"

    elif "MALWARE" in alert:
        prefix = "MAL"

    elif "BRUTE" in alert:
        prefix = "BRUTE"

    elif "LOGIN" in alert:
        prefix = "AUTH"

    elif "AI" in alert:
        prefix = "AI"

    elif "DNS" in alert:
        prefix = "DNS"

    elif "DHCP" in alert:
        prefix = "DHCP"
    

    else:
        prefix = "SOC"


    # ----------------------------------------------------
    # Timeline
    # ----------------------------------------------------

    event_id = add_timeline_event(
        incident_id=incident_id,
        event_type=prefix,
        attack_type=alert_type,
        source="NetGuardIQ",
        severity=severity,
        username="System",
        hostname=socket.gethostname(),
        event=alert_type,
        details=description
    )

    print("=" * 50)
    print("[+] Alert Created Successfully")
    print("=" * 50)
    print(f"Incident ID : {incident_id}")
    print(f"Event ID    : {event_id}")
    print(f"Alert Type  : {alert_type}")
    print(f"Severity    : {severity}")
    print(f"Risk Score  : {risk_score}")
    print("=" * 50)

    return incident_id
