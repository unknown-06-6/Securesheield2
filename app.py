import os
import json
import logging
from datetime import datetime, timezone, timedelta
from functools import wraps

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

from flask import Flask, request, jsonify, g
from flask_bcrypt import Bcrypt
import jwt

app = Flask(__name__)
bcrypt = Bcrypt(app)

SECRET_KEY = os.environ.get("JWT_SECRET", "secureshield-secret-key")
JWT_EXPIRY_MINUTES = 30
DB_FILE = os.path.join(BASE_DIR, "users.json")
token_blacklist = set()

logging.basicConfig()
security_logger = logging.getLogger("security")
security_logger.setLevel(logging.WARNING)
security_logger.propagate = False
log_handler = logging.StreamHandler()
log_handler.setLevel(logging.WARNING)
log_handler.setFormatter(logging.Formatter("%(asctime)s | %(message)s"))
security_logger.addHandler(log_handler)


def load_db():
    if not os.path.exists(DB_FILE):
        return {"users": {}}
    with open(DB_FILE) as f:
        return json.load(f)


def save_db(data):
    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=2)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401
        token = auth.split(" ", 1)[1]
        if token in token_blacklist:
            return jsonify({"error": "Token has been revoked"}), 401
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        g.current_user = payload["username"]
        g.current_role = payload["role"]
        g.current_token = token
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        if g.current_role != "admin":
            security_logger.warning(
                f"403 FORBIDDEN | user={g.current_user} | ip={request.remote_addr} | action={request.path}"
            )
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated


@app.route("/register", methods=["POST"])
def register():
    body = request.get_json(silent=True) or {}
    username = body.get("username", "").strip()
    password = body.get("password", "")
    role = body.get("role", "user").lower()

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400
    if role not in ("user", "admin"):
        return jsonify({"error": "role must be 'user' or 'admin'"}), 400

    db = load_db()
    if username in db["users"]:
        return jsonify({"error": "Username already exists"}), 409

    db["users"][username] = {
        "id": len(db["users"]) + 1,
        "password_hash": bcrypt.generate_password_hash(password).decode("utf-8"),
        "role": role
    }
    save_db(db)
    return jsonify({"message": f"User '{username}' registered", "role": role}), 201


@app.route("/login", methods=["POST"])
def login():
    body = request.get_json(silent=True) or {}
    username = body.get("username", "").strip()
    password = body.get("password", "")

    db = load_db()
    user = db["users"].get(username)
    if not user or not bcrypt.check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    token = jwt.encode({
        "username": username,
        "role": user["role"],
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRY_MINUTES),
        "iat": datetime.now(timezone.utc)
    }, SECRET_KEY, algorithm="HS256")

    return jsonify({"message": "Login successful", "token": token, "role": user["role"]}), 200


@app.route("/logout", methods=["POST"])
@token_required
def logout():
    token_blacklist.add(g.current_token)
    return jsonify({"message": f"User '{g.current_user}' logged out. Token revoked."}), 200


@app.route("/profile", methods=["GET"])
@token_required
def profile():
    db = load_db()
    user_data = db["users"].get(g.current_user, {})
    return jsonify({
        "username": g.current_user,
        "role": g.current_role,
        "user_id": user_data.get("id")
    }), 200


@app.route("/user/<int:user_id>", methods=["DELETE"])
@admin_required
def delete_user(user_id):
    db = load_db()
    target = next((u for u, d in db["users"].items() if d["id"] == user_id), None)
    if not target:
        return jsonify({"error": f"User {user_id} not found"}), 404
    if target == g.current_user:
        return jsonify({"error": "Admins cannot delete themselves"}), 400
    del db["users"][target]
    save_db(db)
    return jsonify({"message": f"User '{target}' deleted by admin '{g.current_user}'"}), 200


@app.route("/users", methods=["GET"])
@admin_required
def list_users():
    db = load_db()
    return jsonify({"users": [
        {"id": v["id"], "username": k, "role": v["role"]}
        for k, v in db["users"].items()
    ]}), 200


@app.route("/")
def index():
    return jsonify({
        "service": "SecureShield RBAC API",
        "endpoints": {
            "POST /register": "Create account",
            "POST /login": "Login and get JWT",
            "POST /logout": "Revoke token [auth required]",
            "GET /profile": "View profile [user or admin]",
            "DELETE /user/<id>": "Delete user [admin only]",
            "GET /users": "List all users [admin only]"
        }
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
