import sqlite3
from datetime import datetime
import os

from os_fingerprint import fingerprint_device

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database", "netguardiq.db")


def save_device(ip_address, mac_address):

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Fingerprint the device
    device = fingerprint_device(ip_address, mac_address)

    cursor.execute("""
        SELECT mac_address
        FROM devices
        WHERE ip_address = ?
    """, (ip_address,))

    result = cursor.fetchone()

    # ----------------------------------
    # New Device
    # ----------------------------------

    if result is None:

        cursor.execute("""
            INSERT INTO devices (

                ip_address,
                mac_address,
                hostname,
                vendor,
                operating_system,
                device_type,
                criticality,
                status,
                first_seen,
                last_seen,
                last_mac_change

            )

            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

        """, (

            ip_address,
            mac_address,
            device["hostname"],
            device["vendor"],
            device["operating_system"],
            device["device_type"],
            device["criticality"],
            "Active",
            current_time,
            current_time,
            current_time

        ))

        print(f"[+] New Device : {ip_address}")
        print(f"    Hostname : {device['hostname']}")
        print(f"    Vendor   : {device['vendor']}")
        print(f"    OS       : {device['operating_system']}")
        print(f"    Type     : {device['device_type']}")

    # ----------------------------------
    # Existing Device
    # ----------------------------------

    else:

        stored_mac = result[0]

        if stored_mac != mac_address:

            cursor.execute("""
                UPDATE devices

                SET

                    mac_address = ?,
                    hostname = ?,
                    vendor = ?,
                    operating_system = ?,
                    device_type = ?,
                    criticality = ?,
                    last_seen = ?,
                    last_mac_change = ?

                WHERE ip_address = ?

            """, (

                mac_address,
                device["hostname"],
                device["vendor"],
                device["operating_system"],
                device["device_type"],
                device["criticality"],
                current_time,
                current_time,
                ip_address

            ))

            print(f"[!] MAC Changed : {ip_address}")

        else:

            cursor.execute("""
                UPDATE devices

                SET

                    hostname = ?,
                    vendor = ?,
                    operating_system = ?,
                    device_type = ?,
                    criticality = ?,
                    last_seen = ?

                WHERE ip_address = ?

            """, (

                device["hostname"],
                device["vendor"],
                device["operating_system"],
                device["device_type"],
                device["criticality"],
                current_time,
                ip_address

            ))

            print(f"[*] Updated : {ip_address}")

    conn.commit()
    conn.close()
