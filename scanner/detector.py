# File Purpose: Analyzes HTTP responses to identify suspicious behavior that may indicate SQL injection vulnerabilities.

# Checks whether the server redirected the user to the dashboard.
def is_login_successful(response):
    return (
        response.status_code == 302
        and response.headers.get("Location") == "/dashboard"
    )

# Detects a potential authentication bypass by comparing dashboard access.
def detect_sql_injection(baseline_access, payload_access):
    return not baseline_access and payload_access

# Checks whether the scanner successfully accessed protected dashboard content.
def is_dashboard_accessible(response):
    return (
        response.status_code == 200
        and "alex@example.com" in response.text
    )