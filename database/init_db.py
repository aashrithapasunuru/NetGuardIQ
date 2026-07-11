import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database", "netguardiq.db")

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# --------------------------------------------------
# Devices
# --------------------------------------------------

cursor.execute("""
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE,
    mac_address TEXT,
    hostname TEXT,
    vendor TEXT,
    operating_system TEXT,
    device_type TEXT,
    criticality TEXT,
    status TEXT,
    first_seen TEXT,
    last_seen TEXT,
    last_mac_change TEXT
)
""")

# --------------------------------------------------
# Alerts
# --------------------------------------------------

cursor.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    alert_type TEXT,
    description TEXT,
    severity TEXT,
    risk_score INTEGER,
    status TEXT,
    ai_explanation TEXT
)
""")

# --------------------------------------------------
# Timeline
# --------------------------------------------------

cursor.execute("""
CREATE TABLE IF NOT EXISTS timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER,
    timestamp TEXT,
    event_id TEXT,
    attack_type TEXT,
    source TEXT,
    severity TEXT,
    username TEXT,
    hostname TEXT,
    event TEXT,
    details TEXT
)
""")

# --------------------------------------------------
# Analyst Notes
# --------------------------------------------------

cursor.execute("""
CREATE TABLE IF NOT EXISTS analyst_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER,
    note TEXT,
    created_at TEXT
)
""")

conn.commit()
conn.close()

print("======================================")
print(" NetGuardIQ Database Initialized")
print("======================================")
print(f"Database: {DB_PATH}")
print("Tables created:")
print(" - devices")
print(" - alerts")
print(" - timeline")
print(" - analyst_notes")
print("======================================")
