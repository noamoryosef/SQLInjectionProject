#File Purpose: Display results of findings 

# Displays a summary of the SQL injection scan results.
def display_summary(all_results):

    # Count the total number of payload tests.
    total_tests = len(all_results)

    # Count how many payload tests detected a potential vulnerability.
    positive_results = sum(
        1 for result in all_results if result["vulnerability_detected"]
    )

    # Collect unique URLs where vulnerabilities were detected.
    vulnerable_urls = {
        result["url"]
        for result in all_results
        if result["vulnerability_detected"]
    }

    print("\n========== SCAN SUMMARY ==========")
    print("Total Payload Tests:", total_tests)
    print("Positive Detection Results:", positive_results)
    print("Web Pages with Potential Vulnerabilities:", len(vulnerable_urls))

# Displays the results of an individual SQL injection payload test.
def display_payload_result(result):
    print("Payload:", result["payload"])
    print("Status Code:", result["status_code"])
    print("Login Successful:", result["login_success"])

    if result["vulnerability_detected"]:
        print("Potential SQL Injection Detected!")
    else:
        print("No authentication bypass detected.")

    print()

# Displays which URL is currently being tested.
def display_test_url(url):
    print("\nTesting URL:", url)


# Displays the result of the normal invalid login test.
def display_baseline_result(baseline_success):
    print("Baseline Login Successful:", baseline_success)