# File Purpose: Displays the results of the SQL injection vulnerability scanner.


def display_report(baseline_access, baseline_results, all_results):

    # Display security baseline
    print("\n========== SECURITY BASELINE ==========")
    print("Dashboard Access Without Login:", baseline_access)

    for url, baseline in baseline_results.items():
        print("\nLogin URL:", url)
        print("Invalid Login Successful:", baseline["login_success"])
        print("Dashboard Access After Invalid Login:", baseline["dashboard_access"])

    # Display individual payload test results
    print("\n========== SCANNING LOGIN PAGES ==========")

    for result in all_results:
        print("\nTesting URL:", result["url"])
        print("Payload:", result["payload"])
        print("Status Code:", result["status_code"])
        print("Login Successful:", result["login_success"])
        print("Dashboard Access:", result["dashboard_access"])

        if result["vulnerability_detected"]:
            print("Potential SQL Injection Detected!")
        else:
            print("No authentication bypass detected.")

    # Calculate scan summary
    positive_results = sum(
        1 for result in all_results if result["vulnerability_detected"]
    )

    vulnerable_urls = {
        result["url"]
        for result in all_results
        if result["vulnerability_detected"]
    }

    # Display scan summary
    print("\n========== SCAN SUMMARY ==========")
    print("Total Payload Tests:", len(all_results))
    print("Positive Detection Results:", positive_results)
    print("Web Pages with Potential Vulnerabilities:", len(vulnerable_urls))