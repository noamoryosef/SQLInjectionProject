from scanner.http_client import send_request

# Return status code for URL
def scan(url):
    response = send_request(url)
    print("Status Code:", response.status_code)

if __name__ == "__main__":
    scan("http://127.0.0.1:8000/")