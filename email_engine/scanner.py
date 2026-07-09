from email_engine.parser import extract_links
from email_engine.risker_engine import calculate_risk_score, get_label
from email_engine.models import phishing_ai_score


def scan_email(email_body, sender_email, blacklist_checker, domain_age_checker, redirect_checker):

    links = extract_links(email_body)
    ai_score = phishing_ai_score(email_body)

    results = []

    for link in links:
        domain_age = domain_age_checker(link)
        is_blacklisted = blacklist_checker(link)
        has_redirects = redirect_checker(link)

        score = calculate_risk_score(
            is_blacklisted,
            domain_age,
            has_redirects,
            ai_score
        )

        results.append({
            "url": link,
            "risk_score": score,
            "label": get_label(score),
            "ai_score": ai_score
        })

    return results
