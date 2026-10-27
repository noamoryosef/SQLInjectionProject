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