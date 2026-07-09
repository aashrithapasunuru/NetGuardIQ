import sqlite3
import os

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

DB_PATH = os.path.join(
    BASE_DIR,
    "database",
    "netguardiq.db"
)


def calculate_risk_score(ip_address):

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT criticality
        FROM devices
        WHERE ip_address = ?
        """,
        (ip_address,)
    )

    result = cursor.fetchone()

    conn.close()

    if result is None:
        return 50

    criticality = result[0]

    if criticality == "High":
        return 90

    elif criticality == "Medium":
        return 75

    elif criticality == "Low":
        return 60

    return 50


def get_severity(risk_score):

    if risk_score >= 90:
        return "Critical"

    elif risk_score >= 70:
        return "High"

    elif risk_score >= 50:
        return "Medium"

    return "Low"

if __name__ == "__main__":

    ip_address = "192.168.1.1"

    risk_score = calculate_risk_score(
        ip_address
    )

    severity = get_severity(
        risk_score
    )

    print("Risk Score:", risk_score)
    print("Severity:", severity)
