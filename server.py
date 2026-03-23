"""Gossip Tomography — Flask server.

Serves the static frontend and preprocessed JSON data.
"""

from flask import Flask, send_from_directory
from flask_cors import CORS
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

app = Flask(__name__, static_folder=STATIC_DIR)
CORS(app)


@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/<path:path>")
def static_files(path):
    return send_from_directory(STATIC_DIR, path)


if __name__ == "__main__":
    print("\n  🔬 Gossip Tomography")
    print("  http://localhost:5001\n")
    app.run(host="0.0.0.0", port=5001, debug=False)
