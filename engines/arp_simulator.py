import sqlite3

from engines.alert_engine import create_alert
from engines.event_manager import push_event

DB_PATH = "database/netguardiq.db"


def simulate_attack():

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT ip_address, mac_address
        FROM devices
        LIMIT 1
    """)

    row = cursor.fetchone()

    conn.close()

    if row is None:
        print("[SIMULATOR] No devices found.")
        return

    ip_address = row[0]
    original_mac = row[1]

    fake_mac = "AA:BB:CC:DD:EE:FF"

    description = (
        f"Possible ARP spoofing detected. "
        f"IP Address: {ip_address}, "
        f"Stored MAC: {original_mac}, "
        f"Observed MAC: {fake_mac}."
    )

    print("[SIMULATOR] Generating fake ARP attack...")

    incident_id = create_alert(
        alert_type="ARP Spoofing Suspected",
        description=description,
        severity="Critical",
        risk_score=100
    )

    push_event({
        "incident_id": incident_id,
        "event_type": "ARP",
        "attack_type": "ARP SPOOFING SIMULATION",
        "severity": "CRITICAL",
        "message": f"Simulated Fake ARP Spoofing Attack on {ip_address}",
        "source": "SIMULATOR",
        "details": description
    })

    print("[SIMULATOR] Fake attack completed.")
