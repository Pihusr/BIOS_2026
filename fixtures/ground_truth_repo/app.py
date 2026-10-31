from flask import Flask, request
from services.http_client import fetch_url; import plugins.loader as plugin_loader

app = Flask(__name__)

@app.route("/status")
def status():
    return (plugin_loader.load_plugin(request.args.get("plugin", "builtins"), request.args.get("function", "print")), fetch_url("https://example.com/status"))[1]

if __name__ == "__main__":
    app.run(debug=True)
