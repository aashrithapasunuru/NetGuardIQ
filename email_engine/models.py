def phishing_ai_score(email_text: str):
    keywords = [
        "urgent",
        "verify account",
        "password expired",
        "login immediately",
        "security alert",
        "suspended"
    ]

    matches = sum(1 for k in keywords if k in email_text.lower())

    return min(matches / len(keywords), 1.0)
