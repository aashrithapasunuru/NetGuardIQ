def calculate_risk_score(is_blacklisted, domain_age_days, has_redirects, ai_score):
    score = 0

    # blacklist = highest severity
    if is_blacklisted:
        score += 60

    # domain age risk
    if domain_age_days < 7:
        score += 30
    elif domain_age_days < 30:
        score += 15

    # redirect chain risk
    if has_redirects:
        score += 15

    # AI phishing probability (0–1)
    score += int(ai_score * 40)

    return min(score, 100)


def get_label(score):
    if score >= 80:
        return "DANGEROUS"
    elif score >= 50:
        return "SUSPICIOUS"
    return "SAFE"
