from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from datetime import datetime, timedelta
import bcrypt
import os
from dotenv import load_dotenv
import jwt

from google.oauth2 import id_token
from google.auth.transport import requests

load_dotenv()
app = Flask(__name__)
CORS(app, origins=[
    "http://localhost:3000",
    "https://greenknowledgeglobal.com"
], supports_credentials=True)

# ✅ COOP/COEP headers
@app.after_request
def add_security_headers(response):
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin-allow-popups'
    response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    return response

# ---------- CONFIG ----------
JWT_SECRET = os.getenv("JWT_SECRET", "supersecretkey")
JWT_EXP_DAYS = 7

# ---------- DATABASE ----------
client = MongoClient(os.getenv("MONGO_URI"))
db = client["jobportal"]
users = db["users"]
applications = db["applications"]

# ---------- GOOGLE ----------
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

# ======================================================
# HELPER: CREATE TOKEN
# ======================================================
def create_token(user):
    payload = {
        "email": user["email"],
        "provider": user["provider"],
        "exp": datetime.utcnow() + timedelta(days=JWT_EXP_DAYS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

# ======================================================
# REGISTER (NORMAL)
# ======================================================
@app.route("/api/register", methods=["POST"])
def register():
    data = request.json

    if users.find_one({"email": data.get("email")}):
        return jsonify({"success": False, "error": "User already exists"}), 400

    hashed_pw = bcrypt.hashpw(data["password"].encode(), bcrypt.gensalt())

    users.insert_one({
        "name": data["name"],
        "gender": data["gender"],
        "age": data["age"],
        "email": data["email"],
        "password": hashed_pw,
        "provider": "local",
        "createdAt": datetime.utcnow()
    })

    return jsonify({"success": True})

# ======================================================
# LOGIN (NORMAL)
# ======================================================
@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    user = users.find_one({"email": data.get("email"), "provider": "local"})

    if not user:
        return jsonify({"success": False, "error": "User not found"}), 404

    if not bcrypt.checkpw(data["password"].encode(), user["password"]):
        return jsonify({"success": False, "error": "Invalid password"}), 401

    token = create_token(user)

    return jsonify({
        "success": True,
        "token": token,
        "user": {
            "name": user["name"],
            "email": user["email"],
            "gender": user.get("gender"),
            "age": user.get("age"),
            "provider": user["provider"]
        }
    })

# ======================================================
# GOOGLE LOGIN / REGISTER
# ======================================================
@app.route("/api/auth/google", methods=["POST"])
def google_auth():
    data = request.json

    try:
        idinfo = id_token.verify_oauth2_token(
            data.get("token"),
            requests.Request(),
            GOOGLE_CLIENT_ID
        )

        email = idinfo["email"]
        user = users.find_one({"email": email})

        if not user:
            user = {
                "name": idinfo.get("name"),
                "email": email,
                "gender": data.get("gender"),
                "age": data.get("age"),
                "picture": idinfo.get("picture"),
                "provider": "google",
                "createdAt": datetime.utcnow()
            }
            users.insert_one(user)

        token = create_token(user)

        return jsonify({
            "success": True,
            "token": token,
            "user": {
                "name": user.get("name"),
                "email": user.get("email"),
                "gender": user.get("gender"),
                "age": user.get("age"),
                "provider": user.get("provider"),
                "picture": user.get("picture")
            }
        })

    except Exception as e:
        print(e)
        return jsonify({"success": False}), 401

# ======================================================
# VERIFY USER (AUTO LOGIN AFTER REFRESH)
# ======================================================
@app.route("/api/me", methods=["GET"])
def get_me():
    token = request.headers.get("Authorization")

    if not token:
        return jsonify({"success": False}), 401

    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user = users.find_one({"email": decoded["email"]}, {"password": 0})

        if not user:
            return jsonify({"success": False}), 401

        return jsonify({"success": True, "user": user})

    except jwt.ExpiredSignatureError:
        return jsonify({"success": False, "error": "Token expired"}), 401
    except:
        return jsonify({"success": False}), 401


@app.route("/api/job/apply", methods=["POST"])
def apply_job():
    data = request.json

    application = {
        "name": data.get("name"),
        "email": data.get("email"),
        "phone": data.get("phone"),
        "job": data.get("job"),
        "experience": data.get("experience"),
        "message": data.get("message"),
        "createdAt": datetime.utcnow()
    }

    applications.insert_one(application)

    # ---------- SEND EMAIL ----------
    from email.mime.text import MIMEText
    import smtplib

    msg = MIMEText(f"""
New Job Application Received

Name: {application['name']}
Email: {application['email']}
Phone: {application['phone']}
Job: {application['job']}
Experience: {application['experience']}

Message:
{application['message']}
""")

    msg["Subject"] = f"New Job Application - {application['job']}"
    msg["From"] = ADMIN_EMAIL
    msg["To"] = ADMIN_EMAIL

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(ADMIN_EMAIL, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
    except Exception as e:
        print("Email error:", e)

    return jsonify({"success": True})

# ======================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)