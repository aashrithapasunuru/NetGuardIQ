import sqlite3
import os
from openai import OpenAI

DB_PATH = "database/netguardiq.db"


def analyze_alert(alert_id):

    conn = sqlite3.connect(DB_PATH)

    try:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id,
                   timestamp,
                   alert_type,
                   description,
                   severity,
                   risk_score
            FROM alerts
            WHERE id = ?
        """, (alert_id,))

        alert = cursor.fetchone()

        if not alert:
            print(f"Alert {alert_id} not found.")
            return False

        alert_id = alert[0]
        timestamp = alert[1]
        alert_type = alert[2]
        description = alert[3]
        severity = alert[4]
        risk_score = alert[5]

        print(f"Alert ID     : {alert_id}")
        print(f"Timestamp    : {timestamp}")
        print(f"Alert Type   : {alert_type}")
        print(f"Description  : {description}")
        print(f"Severity     : {severity}")
        print(f"Risk Score   : {risk_score}")

        api_key = os.getenv("OPENAI_API_KEY")

        if not api_key:
            print("ERROR: OPENAI_API_KEY is not set.")
            return False

        client = OpenAI(
            api_key=api_key,
            timeout=30.0
        )

        prompt = f"""
You are a SOC Analyst performing security alert triage.

Analyze the following cybersecurity alert.

Alert ID: {alert_id}
Timestamp: {timestamp}
Alert Type: {alert_type}
Description: {description}
Severity: {severity}
Risk Score: {risk_score}

Provide a concise professional SOC analysis using these headings:

## Summary
## What Happened?
## Why Is It Dangerous?
## Possible Causes
## Investigation Steps
## Mitigation

Focus on practical SOC investigation and response actions.
"""

        print("\nSending alert to AI for analysis...")

        response = client.responses.create(
            model="gpt-4.1-mini",
            input=prompt
        )

        ai_explanation = response.output_text

        if not ai_explanation:
            print("ERROR: AI returned an empty response.")
            return False

        cursor.execute("""
            UPDATE alerts
            SET ai_explanation = ?,
                status = 'processed'
            WHERE id = ?
        """, (ai_explanation, alert_id))

        conn.commit()

        print("AI explanation saved to database.")

        print("\n===== AI Explanation =====")
        print(ai_explanation)

        return True

    except Exception as e:

        print("\n===== AI Error =====")
        print("AI analysis failed.")
        print(f"{type(e).__name__}: {e}")

        return False

    finally:
        conn.close()
