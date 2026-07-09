import re

def extract_links(email_body: str):
    """
    Extract all URLs from email body
    """
    url_pattern = r'https?://[^\s"\'>]+'
    return re.findall(url_pattern, email_body)


def extract_sender_domain(sender_email: str):
    """
    Get domain from sender email
    """
    if "@" in sender_email:
        return sender_email.split("@")[1].lower()
    return None
