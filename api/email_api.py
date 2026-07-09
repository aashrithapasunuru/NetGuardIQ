from flask import Flask, request, jsonify

from email_engine.scanner import scan_email

app = Flask(__name__)

# Dummy threat services (replace later with real ones)
def blacklist_checker(url):
    return "fake" in url

def domain_age_checker(url):
    return 5

def redirect_checker(url):
    return False


@app.route("/api/scan-email", methods=["POST"])
def scan_email_api():

    data = request.json

    email_body = data.get("email_body", "")
    sender = data.get("sender", "unknown")

    result = scan_email(
        email_body,
        sender,
        blacklist_checker,
        domain_age_checker,
        redirect_checker
    )

    return jsonify({
        "status": "success",
        "sender": sender,
        "scan_result": result
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
