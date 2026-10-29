# File Purpose: Coordinates the scanning process by sending test inputs and collecting responses for vulnerability detection.

from scanner.http_client import send_request, send_post_request, create_session
from scanner.payloads import SQL_INJECTION_PAYLOADS
from scanner.detector import is_login_successful, detect_sql_injection, is_dashboard_accessible
from scanner.report import display_summary, display_payload_result, display_test_url, display_baseline_result,display_security_baseline

# Return status code for URL
def scan(url):
    response = send_request(url)
    print("Status Code:", response.status_code)

# Tests a login endpoint using a baseline and SQL injection payloads.
def scan_login(url, baseline_access):
    display_test_url(url)
    results = [] # Stores results of payload test for later AI analysis

    # Test an ordinary invalid login to establish baseline behavior.
    baseline_data = {
        "username": "admin",
        "password": "wrongpassword123"
    }

    baseline_response = send_post_request(url, baseline_data)
    baseline_success = is_login_successful(baseline_response)

    display_baseline_result(baseline_success)

    for payload in SQL_INJECTION_PAYLOADS:
        data = {
            "username": payload,
            "password": "wrongpassword123"
        }

        with create_session() as session:
            response = send_post_request(url, data, session)
            login_success = is_login_successful(response)

            # Request the protected dashboard using the same session.
            dashboard_url = "http://127.0.0.1:8000/dashboard"
            dashboard_response = send_request(dashboard_url, session)
            
            # Check whether protected dashboard content was retrieved.
            dashboard_access = is_dashboard_accessible(dashboard_response)

        # Detect a potential vulnerability by comparing dashboard access.
        vulnerability_detected = detect_sql_injection(
            baseline_access, dashboard_access
        )

        # Store the findings from this payload test.
        result = {
            "url": url,
            "payload": payload,
            "status_code": response.status_code,
            "baseline_success": baseline_success,
            "login_success": login_success,
            "vulnerability_detected": vulnerability_detected,
            "dashboard_access": dashboard_access,
        }

        results.append(result)

        display_payload_result(result)

    return results



if __name__ == "__main__":
    urls = ["http://127.0.0.1:8000/", "http://127.0.0.1:8000/vulnerable"]

    dashboard_url = "http://127.0.0.1:8000/dashboard"

    with create_session() as session:
        dashboard_response = send_request(dashboard_url, session)

    # Display the unauthenticated dashboard test results.
    display_security_baseline(dashboard_response)
    
    # Check whether the dashboard is accessible without logging in.
    baseline_access = is_dashboard_accessible(dashboard_response)
    
    # Stores results from both URLs
    all_results = []

    for url in urls:
        scan_results = scan_login(url,baseline_access)
        all_results.extend(scan_results)

    display_summary(all_results)