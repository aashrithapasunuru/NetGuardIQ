from flask import Flask, render_template, redirect, url_for, request
import subprocess
import sqlite3
import time
from engines.timeline import add_timeline_event
from engines.arp_monitor import start_arp_monitor, stop_arp_monitor
import socket
import sys
import os
from engines.event_manager import get_status, set_status
from engines.event_manager import ( 
                                   get_live_feed,
                                   get_security_score,
                                   get_threat_summary,
                                   get_gateway_status
                                   )
from engines.arp_simulator import simulate_attack
from engines.url_analyzer import analyze_url
from flask import jsonify
from flask_cors import CORS



print(sys.executable)

app = Flask(__name__)
CORS(app)

HOSTNAME = socket.gethostname()

monitoring = False
monitor_process = None


@app.route("/")
def dashboard():

    live_feed = get_live_feed()
    score = get_security_score()
    gateways = get_gateway_status()

    conn = sqlite3.connect("database/netguardiq.db")
    cursor = conn.cursor()


    cursor.execute("SELECT COUNT(*) FROM devices")
    device_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT ip_address,
               mac_address,
               status
        FROM devices
    """)

    devices = cursor.fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        device_count=device_count,
        devices=devices,
        monitoring_status=get_status(),
        live_feed=live_feed,
        threat_count=len(live_feed),
        security_score=score,
        gateway_status=gateways
    )



@app.route("/scan", methods=["POST"])
def scan(): 

    add_timeline_event(
            incident_id=1,
            event_type="DISC",
            attack_type="DISCOVERY",
            source="NetGuardIQ",
            severity="INFO",
            username="System",
            hostname=HOSTNAME,
            event="User initiated network asset discovery",
            details="Discovery started from dashboard"
  )

    subprocess.run(
            ["sudo", sys.executable, "-m", "engines.discovery"],
            cwd=os.path.dirname(os.path.abspath(__file__))
            )
    return redirect(url_for("dashboard"))




@app.route("/start_monitoring", methods=["POST"])
def start_monitoring():

    global monitoring
    global monitor_process

    if not monitoring:

        monitor_process = subprocess.Popen([
            "sudo",
            sys.executable,
            "-m",
            "engines.arp_monitor"
            ], cwd=os.path.dirname(os.path.abspath(__file__)))

        monitoring = True

        set_status("ACTIVE")

        add_timeline_event(
                incident_id=1,
                event_type="MON",
                attack_type="MONITORING",
                source="NetGuardIQ",
                severity="INFO",
                username="System",
                hostname=HOSTNAME,
                event="Network Monitoring Started",
                details="User clicked Start Monitoring"
                )


    return redirect(url_for("dashboard"))   



@app.route("/stop_monitoring", methods=["POST"])
def stop_monitoring():

    global monitoring
    global monitor_process

    if monitor_process is not None:

        subprocess.run([
            "sudo",
            "pkill",
            "-f",
            "engines.arp_monitor"
            ])

        monitor_process = None

        monitoring = False
        set_status("STOPPED")

        add_timeline_event(
            incident_id=1,
            event_type="MON",
            attack_type="MONITORING",
            source="NetGuardIQ",
            severity="INFO",
            username="System",
            hostname=HOSTNAME,
            event="Network Monitoring stopped",
            details="User clicked Stop Monitoring"
            )

    return redirect(url_for("dashboard"))


@app.route("/sync", methods=["POST"])
def sync_dashboard():

    # Refresh device inventory
    subprocess.run([sys.executable, "-m", "engines.discovery"])

    # Run ARP analysis once
    subprocess.run([sys.executable, "-m", "engines.arp_monitor"])

    return redirect(url_for("dashboard"))


@app.route("/analyze", methods=["POST"])
def analyze():

    subprocess.run([sys.executable, "engines/ai_analyzer.py"])

    return redirect(url_for("dashboard"))


@app.route("/analyze-alert/<int:alert_id>", methods=["POST"])
def analyze_alert_route(alert_id):

    from engines.ai_analyzer import analyze_alert

    success = analyze_alert(alert_id)

    if success:
        return redirect(
            url_for("ai_analyst", alert_id=alert_id)
        )

    return redirect(url_for("alerts"))



@app.route("/network_inventory")
def network_inventory():

    conn = sqlite3.connect("database/netguardiq.db")
    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM devices
        ORDER BY last_seen DESC
    """)

    rows = cursor.fetchall()

    devices = []

    for row in rows:

        device = dict(row)

        if ":" in device["ip_address"]:
            device["ip_version"] = "IPv6"

        else:
            device["ip_version"] = "IPv4"

        devices.append(device)

    conn.close()


    return render_template(
        "network_inventory.html",
        devices=devices
    )

 
@app.route("/alerts")
def alerts():

    conn = sqlite3.connect("database/netguardiq.db")
    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM alerts
        ORDER BY timestamp DESC
    """)

    alerts = cursor.fetchall()

    conn.close()

    return render_template(
        "alerts.html",
        alerts=alerts
    )    

@app.route("/timeline")
def timeline():

    conn = sqlite3.connect("database/netguardiq.db")
    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM timeline
        ORDER BY timestamp DESC
    """)

    events = cursor.fetchall()

    conn.close()

    return render_template(
        "timeline.html",
        events=events
    )



@app.route("/ai-analyst")
def ai_analyst():

    conn = sqlite3.connect("database/netguardiq.db")
    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM alerts
        ORDER BY timestamp DESC
    """)

    alerts = cursor.fetchall()

    selected_alert = None

    alert_id = request.args.get("alert_id")

    if alert_id:
        cursor.execute("""
           SELECT *
           FROM alerts
           WHERE id = ?
           """, (alert_id,))

        selected_alert = cursor.fetchone()

    elif alerts:
        selected_alert = alerts[0]


    conn.close()

    return render_template(
        "ai_analyst.html",
        alerts=alerts,
        selected_alert=selected_alert
    )


@app.route("/reports")
def reports():

    conn = sqlite3.connect("database/netguardiq.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # ----------------------------------------------------
    # Overall counts
    # ----------------------------------------------------

    cursor.execute("SELECT COUNT(*) FROM alerts")
    alert_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM timeline")
    event_count = cursor.fetchone()[0]

    # ----------------------------------------------------
    # Severity counts
    # ----------------------------------------------------

    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE UPPER(severity) = 'CRITICAL'
    """)
    critical_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE UPPER(severity) = 'HIGH'
    """)
    high_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE UPPER(severity) = 'MEDIUM'
    """)
    medium_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE UPPER(severity) = 'LOW'
    """)
    low_count = cursor.fetchone()[0]

    # ----------------------------------------------------
    # Status counts
    # ----------------------------------------------------

    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE UPPER(status) = 'OPEN'
    """)
    open_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE UPPER(status) = 'PROCESSED'
    """)
    processed_count = cursor.fetchone()[0]

    # ----------------------------------------------------
    # Risk score statistics
    # ----------------------------------------------------

    cursor.execute("""
        SELECT
            COALESCE(AVG(risk_score), 0),
            COALESCE(MAX(risk_score), 0)
        FROM alerts
    """)

    average_risk, maximum_risk = cursor.fetchone()

    # ----------------------------------------------------
    # Alert type summary
    # ----------------------------------------------------

    cursor.execute("""
        SELECT
            alert_type,
            COUNT(*) AS count
        FROM alerts
        GROUP BY alert_type
        ORDER BY count DESC
    """)

    alert_types = cursor.fetchall()

    # ----------------------------------------------------
    # Recent alerts
    # ----------------------------------------------------

    cursor.execute("""
        SELECT
            id,
            timestamp,
            alert_type,
            severity,
            risk_score,
            status
        FROM alerts
        ORDER BY id DESC
        LIMIT 10
    """)

    recent_alerts = cursor.fetchall()

    conn.close()

    return render_template(
        "reports.html",
        alert_count=alert_count,
        event_count=event_count,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        open_count=open_count,
        processed_count=processed_count,
        average_risk=round(average_risk, 1),
        maximum_risk=maximum_risk,
        alert_types=alert_types,
        recent_alerts=recent_alerts
    )



@app.route("/simulate_attack", methods=["POST"])
def simulate_attack_route():

    simulate_attack()

    return redirect(url_for("dashboard"))



@app.route("/url-analyzer")
def url_analyzer():
    return render_template("url_analyzer.html")


@app.route("/analyze-url", methods=["POST"])
def analyze_url_route():
    url = request.form["url"]

    result = analyze_url(url)

    print(result)

    return render_template(
            "url_analyzer.html",
            result=result
            )


@app.route("/api/analyze-url", methods=["POST"])
def api_analyze_url():

    url = request.form.get("url", "").strip()

    if not url:
        return jsonify({
            "success": False,
            "message": "URL is required"
        }), 400

    result = analyze_url(url)

    return jsonify({
        "success": True,
        "result": result
    })




if __name__ == "__main__":
    app.run(
            host="0.0.0.0",
            port=5001,
            debug=False,
            use_reloader=False
            )
