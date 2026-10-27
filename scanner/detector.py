# File Purpose: Analyzes HTTP responses to identify suspicious behavior that may indicate SQL injection vulnerabilities.

# Checks whether the server redirected the user to the dashboard.
def is_login_successful(response):
    return (
        response.status_code == 302
        and response.headers.get("Location") == "/dashboard"
    )

# Compares normal login behavior with a payload test to detect a possible authentication bypass.
def detect_sql_injection(baseline_success, payload_success):
    return not baseline_success and payload_success