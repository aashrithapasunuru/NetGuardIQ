from email_engine.scanner import scan_email


def dummy_blacklist(url):
    return "fake" in url


def dummy_domain_age(url):
    return 5  # simulate new domain


def dummy_redirect(url):
    return False


email_body = """
Hello user,

Please verify your account:
http://fake-airport-login.com/login

Thank you
"""

sender = "security@airport.com"


result = scan_email(
    email_body,
    sender,
    dummy_blacklist,
    dummy_domain_age,
    dummy_redirect
)

print(result)
