# File Purpose: Handles HTTP requests, manages sessions, and returns responses for analysis.
import requests

# Sends a GET request using an optional session and returns the response.
def send_request(url, session=None):
    client = session if session is not None else requests

    response = client.get(
        url,
        timeout=5,
        allow_redirects=False
    )

    return response

# Sends a POST request using a session and returns the server's response.
def send_post_request(url, data, session=None):
    client = session if session is not None else requests

    response = client.post(
        url,
        data=data,
        timeout=5,
        allow_redirects=False
    )

    return response

# Creates a session that preserves cookies between HTTP requests.
def create_session():
    return requests.Session()