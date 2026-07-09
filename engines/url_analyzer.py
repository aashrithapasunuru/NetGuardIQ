import re
import ipaddress
import requests
import base64

from urllib.parse import urlparse

from config import VT_API_KEY
from engines.event_manager import push_event


def check_virustotal(url):
    """
    Query VirusTotal for URL reputation.
    """

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    headers = {
        "x-apikey": VT_API_KEY
    }

    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    try:
        response = requests.get(endpoint, headers=headers, timeout=10)

        if response.status_code == 200:
            return response.json()

    except Exception as e:
        print("[VirusTotal Error]", e)

    return None


def analyze_url(url):
    """
    Analyze URL using:
    - Local phishing rules
    - VirusTotal Threat Intelligence
    """

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    result = {
        "url": url,
        "status": "Safe",
        "risk_score": 0,
        "severity": "LOW",
        "reasons": []
    }

    # --------------------------------------------------
    # Basic Validation
    # --------------------------------------------------

    if not parsed.netloc:
        result["status"] = "Invalid URL"
        result["severity"] = "INFO"
        result["reasons"].append("Invalid URL format.")
        return result

    hostname = parsed.hostname or ""

    try:
        ipaddress.ip_address(hostname)

    except ValueError:

        domain_pattern = r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"

        if not re.match(domain_pattern, hostname):
            result["status"] = "Invalid URL"
            result["severity"] = "INFO"
            result["reasons"].append("Invalid domain name.")
            return result

    # --------------------------------------------------
    # Rule 1 - IP Address
    # --------------------------------------------------

    try:
        ipaddress.ip_address(hostname)

        result["risk_score"] += 40
        result["reasons"].append(
            "URL uses an IP address instead of a domain."
        )

    except ValueError:
        pass

    # --------------------------------------------------
    # Rule 2 - HTTP
    # --------------------------------------------------

    if parsed.scheme == "http":

        result["risk_score"] += 10

        result["reasons"].append(
            "Website is using HTTP instead of HTTPS."
        )

    # --------------------------------------------------
    # Rule 3 - Suspicious Keywords
    # --------------------------------------------------

    keywords = [
        "login",
        "verify",
        "update",
        "secure",
        "password",
        "bank",
        "signin"
    ]

    full_url = url.lower()

    for word in keywords:

        if word in full_url:

            result["risk_score"] += 15

            result["reasons"].append(
                f"Suspicious keyword detected: {word}"
            )

    # --------------------------------------------------
    # Rule 4 - URL Shorteners
    # --------------------------------------------------

    shorteners = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "buff.ly",
        "cutt.ly",
        "rebrand.ly",
        "rb.gy",
        "is.gd"
    }

    if hostname.lower() in shorteners:

        result["risk_score"] += 20

        result["reasons"].append(
            "URL uses a shortening service which may hide the real destination."
        )

    # --------------------------------------------------
    # VirusTotal Lookup
    # --------------------------------------------------

    vt_result = check_virustotal(url)

    if vt_result:

        try:

            stats = vt_result["data"]["attributes"]["last_analysis_stats"]

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)

            if malicious >= 10:
                result["risk_score"] += 80
            elif malicious >= 5:
                result["risk_score"] += 60
            elif malicious >= 1:
                result["risk_score"] += 40

            if suspicious >= 3:
                result["risk_score"] += 20

            if malicious > 0:
                result["reasons"].append(
                    f"VirusTotal: {malicious} security vendor(s) flagged this URL as malicious."
                )

            elif suspicious > 0:
                result["reasons"].append(
                    f"VirusTotal: {suspicious} security vendor(s) marked this URL as suspicious."
                )

            elif harmless > 0:
                result["reasons"].append(
                    f"VirusTotal: {harmless} vendors reported the URL as clean."
                )

        except Exception as e:
            print("[VirusTotal Parse Error]", e)

    # --------------------------------------------------
    # Final Verdict
    # --------------------------------------------------

    if result["risk_score"] >= 70:

        result["status"] = "Malicious"
        result["severity"] = "HIGH"

    elif result["risk_score"] >= 30:

        result["status"] = "Suspicious"
        result["severity"] = "MEDIUM"

    else:

        result["status"] = "Safe"
        result["severity"] = "LOW"

    result["create_alert"] = result["severity"] in ("MEDIUM", "HIGH")

    # --------------------------------------------------
    # Threat Center Integration
    # --------------------------------------------------

    if result["create_alert"]:

        print("[DEBUG] Creating Threat Center event...")
        print(result)

        event_id = push_event({
            "incident_id": 1,
            "event_type": "PHISH",
            "attack_type": "URL Analysis",
            "source": hostname,
            "severity": result["severity"],
            "risk_score": result["risk_score"],
            "message": f"{result['status']} URL Detected",
            "details":
                f"URL: {url}\n"
                f"Risk Score: {result['risk_score']}\n"
                f"Reasons: {', '.join(result['reasons'])}"
        })

        print("[DEBUG] Event ID:", event_id)

    return result
