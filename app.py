from flask import Flask, render_template, redirect, url_for, request
import subprocess
import sqlite3
import time
from engines.timeline import add_timeline_event
from engines.arp_monitor import start_arp_monitor, stop_arp_monitor
import socket
import sys
from engines.event_manager import get_status, set_status
from engines.event_manager import ( 
                                   get_live_feed,
                                   get_security_score,
                                   get_threat_summary,
                                   get_gateway_status
                                   )
from engines.arp_simulator import simulate_attack
from engines.url_analyzer import analyze_url


print(sys.executable)

app = Flask(__name__)

HOSTNAME = socket.gethostname()

monitoring = False


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
            [sys.executable, "engines/discovery.py"]
            )
    return redirect(url_for("dashboard"))




@app.route("/start_monitoring", methods=["POST"])
def start_monitoring():

    global monitoring
    global monitor_thread

    if not monitoring:

        monitoring = True

        set_status("ACTIVE")

        start_arp_monitor()

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

    monitoring = False

    set_status("STOPPED")

    stop_arp_monitor()

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
    subprocess.run([sys.executable, "engines/discovery.py"])

    # Run ARP analysis once
    subprocess.run([sys.executable, "engines/arp_monitor.py"])

    return redirect(url_for("dashboard"))


@app.route("/analyze", methods=["POST"])
def analyze():

    subprocess.run([sys.executable, "engines/ai_analyzer.py"])

    return redirect(url_for("dashboard"))



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




if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
