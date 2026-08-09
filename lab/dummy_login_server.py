from flask import Flask, jsonify, request

app = Flask(__name__)
VALID_CREDENTIALS = {"admin": "azerty"}

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True) or {}
    username = data.get("username")
    password = data.get("password")
    if VALID_CREDENTIALS.get(username) == password:
        return jsonify({"status": "ok"}), 200
    return jsonify({"status": "invalid credentials"}), 401

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)