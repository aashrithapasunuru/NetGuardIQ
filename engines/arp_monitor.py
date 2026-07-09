import os
import sqlite3
import time
from scapy.all import AsyncSniffer, ARP
from engines.alert_engine import create_alert
from engines.event_manager import push_event

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database", "netguardiq.db")

sniffer = None

def process_packet(packet):

    if not packet.haslayer(ARP):
        return

    if packet[ARP].op != 2:
        return

    ip_address = packet[ARP].psrc
    mac_address = packet[ARP].hwsrc

    print("\n========================================")
    print("        Live ARP Packet Received")
    print("========================================")
    print(f"IP Address : {ip_address}")
    print(f"MAC Address: {mac_address}")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Check whether the device exists in inventory
    cursor.execute("""
        SELECT mac_address
        FROM devices
        WHERE ip_address = ?
    """, (ip_address,))

    result = cursor.fetchone()

    if result is None:

        push_event({
            "event_type": "ARP",
            "severity": "INFO",
            "message": f"Ignoring unmanaged device: {ip_address}",
            "source": "ARP_MONITOR",
            "incident_id": 1
            })

        conn.close()
        return

    stored_mac = result[0]

    # -------------------------------------------------
    # MAC Address Matches
    # -------------------------------------------------

    if stored_mac == mac_address:

        cursor.execute("""
            UPDATE devices
            SET last_seen = CURRENT_TIMESTAMP
            WHERE ip_address = ?
        """, (ip_address,))

        conn.commit()
        conn.close()

        push_event({
            "event_type": "ARP",
            "severity": "INFO",
            "message": f"Device verified: {ip_address}",
            "source": "ARP_MONITOR",
            "incident_id": 1
            })
        return

    # -------------------------------------------------
    # MAC Address Changed
    # -------------------------------------------------

    description = (
        f"Possible ARP spoofing detected. "
        f"IP Address: {ip_address}, "
        f"Stored MAC: {stored_mac}, "
        f"Observed MAC: {mac_address}."
    )

    push_event({
        "event_type": "ARP",
        "attack_type": "ARP SPOOFING",
        "severity": "CRITICAL",
        "message": (
            f"Possible ARP spoofing detected: "
            f"IP {ip_address}, "
            f"Old MAC {stored_mac}, "
            f"New MAC {mac_addres}"
            ),
        "source": "ARP_MONITOR",
        "details": description,
        "incident_id": 1
        })

    incident_id = create_alert(
        alert_type="ARP Spoofing Suspected",
        description=description,
        severity="Critical",
        risk_score=100
    )

    # Update inventory AFTER alert creation
    cursor.execute("""
        UPDATE devices
        SET
            mac_address = ?,
            last_seen = CURRENT_TIMESTAMP,
            last_mac_change = CURRENT_TIMESTAMP
        WHERE ip_address = ?
    """, (
        mac_address,
        ip_address
    ))

    conn.commit()
    conn.close()

    print(f"[+] Incident #{incident_id} created.")
    print("[+] Device inventory updated.")


def start_arp_monitor():

    global sniffer

    print("========================================")
    print("      NetGuardIQ ARP Monitor Started")
    print("========================================")
    print("[INFO] Waiting for live ARP packets...\n")


    sniffer = AsyncSniffer(
        filter="arp",
        prn=process_packet,
        store=False
    )

    sniffer.start()


def stop_arp_monitor():

    global sniffer

    if sniffer is not None:

        print("[INFO] Stopping ARP Monitor...")

        sniffer.stop()

        sniffer = None

        print("[INFO] ARP Monitor stopper.")


if __name__ == "__main__":

    start_arp_monitor()

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        stop_arp_monitor()
