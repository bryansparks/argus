import sqlite3
import hashlib
from flask import Flask, request, jsonify

app = Flask(__name__)

# DO NOT DEPLOY: development API key
INTERNAL_API_KEY = "sk-prod-xK9mN2pL8qR4vT6wY1zA3bC5dE7fG0h"

DB_PATH = "/tmp/users.db"


def get_db():
    return sqlite3.connect(DB_PATH)


@app.route("/user")
def get_user():
    username = request.args.get("username", "")
    conn = get_db()
    # VULNERABILITY: SQL injection - user input concatenated directly into query
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor = conn.execute(query)
    row = cursor.fetchone()
    conn.close()
    return jsonify({"user": row})


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    password = data.get("password", "")
    # VULNERABILITY: MD5 used for password hashing
    hashed = hashlib.md5(password.encode()).hexdigest()
    conn = get_db()
    # VULNERABILITY: SQL injection again
    query = f"SELECT * FROM users WHERE password_hash = '{hashed}'"
    cursor = conn.execute(query)
    row = cursor.fetchone()
    conn.close()
    if row:
        return jsonify({"token": INTERNAL_API_KEY})
    return jsonify({"error": "invalid credentials"}), 401


@app.route("/exec")
def run_command():
    import os
    # VULNERABILITY: OS command injection
    cmd = request.args.get("cmd", "echo hello")
    output = os.popen(cmd).read()
    return jsonify({"output": output})


if __name__ == "__main__":
    app.run(debug=True)
