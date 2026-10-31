from flask import Flask
from services.http_client import fetch_url

app = Flask(__name__)

@app.route("/status")
def status():
    return fetch_url("https://example.com/status")

if __name__ == "__main__":
    app.run(debug=True)
