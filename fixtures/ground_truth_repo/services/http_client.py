import requests
from flask import session

def fetch_url(url: str) -> str:
    response = requests.get(url, timeout=5)
    session["last_status"] = response.status_code
    return response.text
