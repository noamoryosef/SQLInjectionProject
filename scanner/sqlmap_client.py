# File Purpose: Handles communication with SQLmap and collects scan results.

import os
import subprocess  # allows program to launch another program
import sys
import requests
import time
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from the project's .env file.
load_dotenv()


# Retrieves the SQLmap installation path and verifies that it exists.
def get_sqlmap_path():
    sqlmap_path = os.getenv("SQLMAP_PATH")

    if not sqlmap_path:
        raise ValueError("SQLMAP_PATH is not configured in the .env file.")

    if not Path(sqlmap_path).is_file():
        raise FileNotFoundError("SQLmap file not found: " + sqlmap_path)

    return sqlmap_path


# Login endpoints authorized for SQL injection testing.
ALLOWED_URLS = {"http://127.0.0.1:8000/", "http://127.0.0.1:8000/vulnerable"}


# Runs SQLmap against an authorized local login endpoint.
def run_sqlmap(url):

    if url not in ALLOWED_URLS:
        raise ValueError("This URL is not authorized for scanning")

    sqlmap_path = get_sqlmap_path()

    command = [
        sys.executable,
        sqlmap_path,
        "-u",
        url,
        "--data=username=admin&password=wrongpassword123",
        "-p",
        "username",
        "--batch",
        "--level=1",
        "--risk=1",
    ]

    result = subprocess.run(command, capture_output=True, text=True, timeout=120)

    return result


# Checks whether SQLmap reported any SQL injection vulnerabilities.
def is_sql_injection_detected(result):
    output = result.stdout

    return "Parameter: username (POST)" in output and "Type:" in output


# Connects to the SQLmap API and retrieves its version.
def check_sqlmap_api():
    api_url = os.getenv("SQLMAP_API_URL")
    username = os.getenv("SQLMAP_API_USERNAME")
    password = os.getenv("SQLMAP_API_PASSWORD")

    if not api_url or not username or not password:
        raise ValueError("SQLmap API configuration is missing.")

    response = requests.get(f"{api_url}/version", auth=(username, password), timeout=5)

    response.raise_for_status()

    return response.json()


# Creates a new SQLmap API task and returns its task ID - This is how we are able to keep track of seperate scans
def create_sqlmap_task():
    api_url = os.getenv("SQLMAP_API_URL")
    username = os.getenv("SQLMAP_API_USERNAME")
    password = os.getenv("SQLMAP_API_PASSWORD")

    response = requests.get(f"{api_url}/task/new", auth=(username, password), timeout=5)

    response.raise_for_status()

    data = response.json()

    if not data.get("success"):
        raise RuntimeError("Failed to create SQLmap task.")

    return data["taskid"]


# Starts an SQLmap scan for an authorized login URL.
def start_sqlmap_scan(task_id, url):
    if url not in ALLOWED_URLS:
        raise ValueError("This URL is not authorized for scanning.")

    api_url = os.getenv("SQLMAP_API_URL")
    username = os.getenv("SQLMAP_API_USERNAME")
    password = os.getenv("SQLMAP_API_PASSWORD")

    options = {
        "url": url,
        "data": "username=admin&password=wrongpassword123",
        "testParameter": "username",
        "batch": True,
        "level": 1,
        "risk": 1,
    }

    response = requests.post(
        f"{api_url}/scan/{task_id}/start",
        json=options,
        auth=(username, password),
        timeout=10,
    )

    response.raise_for_status()

    result = response.json()

    if not result.get("success"):
        raise RuntimeError("Failed to start SQLmap scan.")

    return result


# Checks the current status of an SQLmap scanning task.
def get_scan_status(task_id):
    api_url = os.getenv("SQLMAP_API_URL")
    username = os.getenv("SQLMAP_API_USERNAME")
    password = os.getenv("SQLMAP_API_PASSWORD")

    response = requests.get(
        f"{api_url}/scan/{task_id}/status", auth=(username, password), timeout=5
    )

    response.raise_for_status()

    result = response.json()

    if not result.get("success"):
        raise RuntimeError("Failed to retrieve SQLmap scan status.")

    return result["status"]


# Retrieves the results of an SQLmap scanning task.
def get_scan_results(task_id):
    api_url = os.getenv("SQLMAP_API_URL")
    username = os.getenv("SQLMAP_API_USERNAME")
    password = os.getenv("SQLMAP_API_PASSWORD")

    response = requests.get(
        f"{api_url}/scan/{task_id}/data", auth=(username, password), timeout=10
    )

    response.raise_for_status()

    result = response.json()

    if not result.get("success"):
        raise RuntimeError("Failed to retrieve SQLmap scan results.")

    return result["data"]


# Waits for an SQLmap scan to finish and retrieves its results.
def wait_for_scan(task_id, timeout=180):
    start_time = time.monotonic()

    while time.monotonic() - start_time < timeout:
        status = get_scan_status(task_id)

        if status == "terminated":
            return get_scan_results(task_id)

        if status != "running":
            raise RuntimeError("SQLmap scan stopped unexpectedly.")

        time.sleep(2)

    raise TimeoutError("SQLmap scan exceeded the time limit.")


# Displays the structure of SQLmap results without exposing payloads.
def inspect_scan_results(results):
    for entry in results:
        print("Entry Type:", entry.get("type"))
        print("Category:", entry.get("type_name"))
        print("Available Fields:", list(entry.keys()))
        value = entry.get("value")

        print("Value Type:", type(value).__name__) # data type of value

        if isinstance(value, dict): # check if value is of datatype dict
            print("Value Fields:", list(value.keys()))

        elif isinstance(value, list):
            print("Number of Items:", len(value))

            if value and isinstance(value[0], dict):
                print("First Item Fields:", list(value[0].keys()))

        if entry.get("type_name") == "TECHNIQUES":

            for finding in entry.get("value", []): #looping through the dictionaries in 'value' to understand how info is being stored
                technique_data = finding.get("data", {}) #returns sql injection technique from the current dict we are on in the iteration

                print("Technique Data Type:", type(technique_data).__name__)

                if isinstance(technique_data, dict):
                    print("Technique Identifiers:", list(technique_data.keys()))

                elif isinstance(technique_data, list):
                    print("Number of Techniques:", len(technique_data))

                    if technique_data and isinstance(technique_data[0], dict):
                        print("Technique Fields:", list(technique_data[0].keys()))

                    # Loop through each detected technique and display its description.
                    for technique in technique_data:
                        if isinstance(technique, dict):
                            print("Detected Technique:", technique.get("title"))
        print()

# Extracts SQL injection findings from SQLmap's JSON results.
def extract_scan_findings(results):
    findings = []

    for entry in results:
        if entry.get("type_name") == "TECHNIQUES":
            for finding in entry.get("value", []):
                findings.append(finding)

    return findings

# Organizes SQLmap findings into a simpler format for reporting.
def format_scan_findings(findings, url):
    formatted_findings = []

    for finding in findings:
        result = {
            "url": url,
            "parameter": finding.get("parameter"),
            "database": finding.get("dbms"),
            "techniques": []
        }

        # collect the names of the SQL injection techniques detected.
        for technique in finding.get("data", []):
            result["techniques"].append(technique.get("title"))

        formatted_findings.append(result)

    return formatted_findings

# Deletes an SQLmap task after the scan is finished.
def delete_sqlmap_task(task_id):
    api_url = os.getenv("SQLMAP_API_URL")
    username = os.getenv("SQLMAP_API_USERNAME")
    password = os.getenv("SQLMAP_API_PASSWORD")

    response = requests.get(
        f"{api_url}/task/{task_id}/delete",
        auth=(username, password),
        timeout=5
    )

    response.raise_for_status()

    result = response.json()

    if not result.get("success"):
        raise RuntimeError("Failed to delete SQLmap task.")


# Stops a running SQLmap scanning task if it timesout
def stop_sqlmap_scan(task_id):
    api_url = os.getenv("SQLMAP_API_URL")
    username = os.getenv("SQLMAP_API_USERNAME")
    password = os.getenv("SQLMAP_API_PASSWORD")

    response = requests.get(
        f"{api_url}/scan/{task_id}/stop",
        auth=(username, password),
        timeout=5
    )

    response.raise_for_status()

    result = response.json()

    if not result.get("success"):
        raise RuntimeError("Failed to stop SQLmap scan.")

    
# Runs an SQLmap scan and cleans up its task afterward.
def run_sqlmap_scan(url):
    if url not in ALLOWED_URLS:
        raise ValueError("This URL is not authorized for scanning.")

    task_id = create_sqlmap_task()

    try:
        start_sqlmap_scan(task_id, url)

        results = wait_for_scan(task_id)

        findings = extract_scan_findings(results)

        formatted_findings = format_scan_findings(findings, url)

        return formatted_findings

    finally:
        try: # stop the scan if it is still running.
            if get_scan_status(task_id) == "running":
                stop_sqlmap_scan(task_id)

        except Exception as error:
            print("Error stopping SQLmap scan:", error)

        try: # attempt to delete task
            delete_sqlmap_task(task_id)

        except Exception as error:
            print("Error deleting SQLmap task:", error)