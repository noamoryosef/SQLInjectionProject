import requests

# Sends a GET request to a URL and returns the server's response for the scanner to analyze.
def send_request(url):
    response = requests.get(url, timeout=5)
    return response