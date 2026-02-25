from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from datetime import datetime, timedelta
import bcrypt
import os
from dotenv import load_dotenv
import jwt
import smtplib
from email.mime.text import MIMEText

from google.oauth2 import id_token
from google.auth.transport import requests

# ======================================================
# LOAD ENV VARIABLES
# ======================================================
load_dotenv()

app = Flask(__name__)
CORS(app, supports_credentials=True)

# ======================================================
# ENV VARIABLES
# ======================================================
MONGO_URI = os.getenv("MONGO_URI")
JWT_SECRET = os.getenv("JWT_SECRET")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

if not MONGO_URI:
    raise Exception("❌ MONGO_URI not set")

if not JWT_SECRET:
    raise Exception("❌ JWT_SECRET not set")

JWT_EXP_DAYS = 7

# ======================================================
# DATABASE CONNECTION (with timeout protection)
# ======================================================
client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
db = client["jobportal"]
users = db["users"]
applications = db["applications"]

# ======================================================
# HEALTH CHECK (REQUIRED FOR RAILWAY)
# ======================================================
@app.route("/")
def health():
    return "API Running", 200

# ======================================================
# HELPER: SERIALIZE USER
# ======================================================
def serialize_user(user):
    return {
        "id": str(user["_id"]),
        "name": user.get("name"),
        "email": user.get("email"),
        "gender": user.get("gender"),
        "age": user.get("age"),
        "provider": user.get("provider"),
        "picture": user.get("picture"),
    }

# ======================================================
# HELPER: CREATE JWT
# ======================================================
def create_token(user):
    payload = {
        "email": user["email"],
        "provider": user["provider"],
        "exp": datetime.utcnow() + timedelta(days=JWT_EXP_DAYS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

# ======================================================
# REGISTER
# ======================================================
@app.route("/api/register", methods=["POST"])
def register():
    data = request.json

    if not data:
        return jsonify({"success": False, "error": "No data provided"}), 400

    if users.find_one({"email": data.get("email")}):
        return jsonify({"success": False, "error": "User already exists"}), 400

    hashed_pw = bcrypt.hashpw(data["password"].encode(), bcrypt.gensalt())

    users.insert_one({
        "name": data.get("name"),
        "gender": data.get("gender"),
        "age": data.get("age"),
        "email": data.get("email"),
        "password": hashed_pw,
        "provider": "local",
        "createdAt": datetime.utcnow()
    })

    return jsonify({"success": True})

# ======================================================
# LOGIN
# ======================================================
@app.route("/api/login", methods=["POST"])
def login():
    data = request.json

    if not data:
        return jsonify({"success": False}), 400

    user = users.find_one({"email": data.get("email"), "provider": "local"})

    if not user:
        return jsonify({"success": False, "error": "User not found"}), 404

    if not bcrypt.checkpw(data["password"].encode(), user["password"]):
        return jsonify({"success": False, "error": "Invalid password"}), 401

    token = create_token(user)

    return jsonify({
        "success": True,
        "token": token,
        "user": serialize_user(user)
    })

# ======================================================
# GOOGLE LOGIN
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
            new_user = {
                "name": idinfo.get("name"),
                "email": email,
                "gender": data.get("gender"),
                "age": data.get("age"),
                "picture": idinfo.get("picture"),
                "provider": "google",
                "createdAt": datetime.utcnow()
            }
            users.insert_one(new_user)
            user = users.find_one({"email": email})

        token = create_token(user)

        return jsonify({
            "success": True,
            "token": token,
            "user": serialize_user(user)
        })

    except Exception as e:
        print("Google Auth Error:", e)
        return jsonify({"success": False}), 401

# ======================================================
# VERIFY TOKEN
# ======================================================
@app.route("/api/me", methods=["GET"])
def get_me():
    token = request.headers.get("Authorization")

    if not token:
        return jsonify({"success": False}), 401

    if token.startswith("Bearer "):
        token = token.split(" ")[1]

    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user = users.find_one({"email": decoded["email"]})

        if not user:
            return jsonify({"success": False}), 401

        return jsonify({
            "success": True,
            "user": serialize_user(user)
        })

    except jwt.ExpiredSignatureError:
        return jsonify({"success": False, "error": "Token expired"}), 401
    except Exception as e:
        print("JWT Error:", e)
        return jsonify({"success": False}), 401

# ======================================================
# APPLY JOB + EMAIL
# ======================================================
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

    # SEND EMAIL SAFELY
    if ADMIN_EMAIL and EMAIL_PASSWORD:
        try:
            msg = MIMEText(f"""
New Job Application

Name: {application['name']}
Email: {application['email']}
Phone: {application['phone']}
Job: {application['job']}
Experience: {application['experience']}

Message:
{application['message']}
""")

            msg["Subject"] = f"New Application - {application['job']}"
            msg["From"] = ADMIN_EMAIL
            msg["To"] = ADMIN_EMAIL

            server = smtplib.SMTP("smtp.gmail.com", 587, timeout=10)
            server.starttls()
            server.login(ADMIN_EMAIL, EMAIL_PASSWORD)
            server.send_message(msg)
            server.quit()

        except Exception as e:
            print("Email error:", e)

    return jsonify({"success": True})