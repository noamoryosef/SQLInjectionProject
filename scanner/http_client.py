# File Purpose: Handles sending HTTP requests to the web application and returning responses for analysis.
import requests

# Sends a GET request to a URL and returns the server's response for the scanner to analyze.
def send_request(url):
    response = requests.get(url, timeout=5)
    return response

# Sends a POST request with form data and returns the server's response.
def send_post_request(url, data):
    response = requests.post(url, data=data, timeout=5, allow_redirects=False)
    return response