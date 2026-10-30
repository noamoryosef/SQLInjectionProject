# File Purpose: Coordinates the scanning process by sending test inputs and collecting responses for vulnerability detection.

from scanner.http_client import send_request, send_post_request, create_session
from scanner.payloads import SQL_INJECTION_PAYLOADS
from scanner.detector import is_login_successful, detect_sql_injection, is_dashboard_accessible
from scanner.report import display_report

# Return status code for URL
def scan(url):
    response = send_request(url)
    print("Status Code:", response.status_code)

# Tests a login endpoint using a baseline and SQL injection payloads.
def scan_login(url, baseline_access, dashboard_url):
    results = [] # Stores results of payload test for later AI analysis

    # Test an ordinary invalid login to establish baseline behavior.
    baseline_data = {
        "username": "admin",
        "password": "wrongpassword123"
    }

    # Test an invalid login and check whether it grants dashboard access.
    with create_session() as session:
        baseline_response = send_post_request(url, baseline_data, session)
        baseline_success = is_login_successful(baseline_response)

        baseline_dashboard_response = send_request(dashboard_url, session)

        baseline_dashboard_access = is_dashboard_accessible(
            baseline_dashboard_response
        )

    for payload in SQL_INJECTION_PAYLOADS:
        data = {
            "username": payload,
            "password": "wrongpassword123"
        }

        with create_session() as session:
            response = send_post_request(url, data, session)
            login_success = is_login_successful(response)

            # Request the protected dashboard using the same session.
            dashboard_response = send_request(dashboard_url, session)
            
            # Check whether protected dashboard content was retrieved.
            dashboard_access = is_dashboard_accessible(dashboard_response)

        # Compare dashboard access before and after the SQL injection test.
        vulnerability_detected = detect_sql_injection(
            baseline_access,                                # accessing dashboard w/o login
            baseline_dashboard_access,                      # access dashboard with invalid login
            dashboard_access                                # access dashboad with SQL Injection
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

    return results, baseline_success, baseline_dashboard_access



# Runs the complete SQL injection scan and returns the collected results.
def run_scan():
    urls = ["http://127.0.0.1:8000/", "http://127.0.0.1:8000/vulnerable"]

    dashboard_url = "http://127.0.0.1:8000/dashboard"

    with create_session() as session:
        dashboard_response = send_request(dashboard_url, session)

    
    # Check whether the dashboard is accessible without logging in.
    baseline_access = is_dashboard_accessible(dashboard_response)
    
    # Stores results from both URLs (list)
    all_results = []

    # Store the invalid-login baseline results for each URL. (dictionary)
    baseline_results = {}

    for url in urls:
        scan_results, baseline_success, baseline_dashboard_access = scan_login(url,baseline_access, dashboard_url)
        all_results.extend(scan_results)
        baseline_results[url] = {
            "login_success": baseline_success,
            "dashboard_access": baseline_dashboard_access
        }

    return baseline_access, baseline_results, all_results


if __name__ == "__main__":
    baseline_access, baseline_results, all_results = run_scan()

    display_report(baseline_access, baseline_results, all_results)