# File Purpose: Coordinates the scanning process by sending test inputs and collecting responses for vulnerability detection.

from scanner.http_client import send_request, send_post_request
from scanner.detector import is_login_successful
from scanner.payloads import SQL_INJECTION_PAYLOADS
from scanner.detector import is_login_successful, detect_sql_injection


# Return status code for URL
def scan(url):
    response = send_request(url)
    print("Status Code:", response.status_code)

# Tests a login endpoint using a baseline and SQL injection payloads.
def scan_login(url):
    print("\nTesting URL:", url)

    # Test an ordinary invalid login to establish baseline behavior.
    baseline_data = {
        "username": "admin",
        "password": "wrongpassword123"
    }

    baseline_response = send_post_request(url, baseline_data)
    baseline_success = is_login_successful(baseline_response)

    print("Baseline Login Successful:", baseline_success)

    for payload in SQL_INJECTION_PAYLOADS:
        data = {
            "username": payload,
            "password": "wrongpassword123"
        }

        response = send_post_request(url, data)
        login_success = is_login_successful(response)

        vulnerability_detected = detect_sql_injection(
            baseline_success, login_success
        )

        print("Payload:", payload)
        print("Status Code:", response.status_code)
        print("Login Successful:", login_success)

        if vulnerability_detected:
            print("Potential SQL Injection Detected!")
        else:
            print("No authentication bypass detected.")

        print()


if __name__ == "__main__":
    urls = ["http://127.0.0.1:8000/", "http://127.0.0.1:8000/vulnerable"]

    for url in urls:
        scan_login(url)