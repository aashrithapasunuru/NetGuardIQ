import sqlite3

conn = sqlite3.connect("netguardiq.db")
cursor = conn.cursor()

cursor.execute("""
               CREATE TABLE IF NOT EXISTS devices (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               ip_address TEXT UNIQUE,
               mac_address TEXT,
               device_type TEXT,
               criticality TEXT,
               status TEXT,
               first_seen TEXT,
               last_seen TEXT
               )
               """)

cursor.execute("""
               CREATE TABLE IF NOT EXISTS alerts (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               timestamp TEXT,
               alert_type TEXT,
               description TEXT,
               severity TEXT,
               risk_score INTEGER,
               status TEXT
               )
               """)

cursor.execute("""
               CREATE TABLE IF NOT EXISTS timeline (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               incident_id INTEGER,
               timestamp TEXT,
               event TEXT
               )
               """)

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

print("Database initialized successfully.")
