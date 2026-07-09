import sqlite3
import os
from openai import OpenAI

DB_PATH = "database/netguardiq.db"

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.execute("""
SELECT id,
       timestamp,
       alert_type,
       description,
       severity,
       risk_score
FROM alerts
WHERE status = 'open'
ORDER BY id DESC
LIMIT 1
""")

alert = cursor.fetchone()


if alert:
    
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

    client = OpenAI(
            api_key=os.getenv("OPENAI_API_KEY")
            )

    try:  

      response = client.responses.create(
      model="gpt-4.1-mini",
      input=f"""
      You are a SOC Analyst.

      Analyze the following cybersecurity alert.

      Alert Type: {alert_type}
      Description: {description}
      Severity: {severity}
      Risk Score: {risk_score}

      Provide your response using these headings:

      ## Summary
      ## What Happened?
      ## Why Is It Dangerous?
      ## Possible Causes
      ## Investigation Steps
      ## Mitigation
      """
      )

      ai_explanation = response.output_text

  
      

      cursor.execute("""
      UPDATE alerts
      SET ai_explanation = ?, status = 'processed'
      WHERE id = ?
      """, (ai_explanation, alert_id))

      conn.commit()

      print("AI explanation saved to database.")

    

    except Exception as e:
      print("\n===== AI Error =====")  
      print("AI analysis failed.")
      print(e)

else:
    print("No alerts pending AI analysis.")




conn.close()
