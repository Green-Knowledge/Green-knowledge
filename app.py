from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from datetime import datetime, timedelta, timezone
import bcrypt
import os
from dotenv import load_dotenv
import jwt
import smtplib
import requests
from email.mime.text import MIMEText
from user_agents import parse
from google.oauth2 import id_token
from google.auth.transport import requests as grequests
from bson import ObjectId

# ==============================
# LOAD ENV
# ==============================

load_dotenv()

app = Flask(__name__)

CORS(app, origins=[
    "http://localhost:3000",
    "https://greenknowledgeglobal.com"
], supports_credentials=True)

# ==============================
# SECURITY HEADERS
# ==============================

@app.after_request
def add_security_headers(response):
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin-allow-popups'
    response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    return response

# ==============================
# CONFIG
# ==============================

JWT_SECRET = os.getenv("JWT_SECRET_KEY")
JWT_EXP_DAYS = 7

FROM_EMAIL = os.getenv("FROM_EMAIL")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")

MONGO_URI = os.getenv("MONGO_URI")

if not MONGO_URI:
    raise Exception("MONGO_URI not set")

if not JWT_SECRET:
    raise Exception("JWT_SECRET not set")

# ==============================
# DATABASE
# ==============================

client = MongoClient(MONGO_URI)
db = client["jobportal"]

users = db["users"]
applications = db["applications"]
print("file load")
# ==============================
# TOKEN
# ==============================

def create_token(user):

    payload = {
        "email": user["email"],
        "provider": user["provider"],
        "exp": datetime.now(timezone.utc) + timedelta(days=JWT_EXP_DAYS)
    }

    token = jwt.encode(payload, str(JWT_SECRET), algorithm="HS256")

    return token

# ==============================
# USER TRACKING
# ==============================

def get_user_details():

    ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
        country = response.get("country", "Unknown")
        city = response.get("city", "Unknown")
    except:
        country = "Unknown"
        city = "Unknown"

    ua_string = request.headers.get("User-Agent", "")
    user_agent = parse(ua_string)

    device = "Mobile" if user_agent.is_mobile else "Desktop"

    return {
        "ip": ip,
        "country": country,
        "city": city,
        "device": device,
        "browser": user_agent.browser.family,
        "os": user_agent.os.family
    }

# ==============================
# EMAIL FUNCTION
# ==============================

def send_email(subject, body):

    try:
        print("EMAIL START")

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = FROM_EMAIL
        msg["To"] = ADMIN_EMAIL

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.ehlo()

        server.starttls()
        server.ehlo()

        server.login(FROM_EMAIL, EMAIL_PASSWORD)

        server.sendmail(
            FROM_EMAIL,
            ADMIN_EMAIL,
            msg.as_string()
        )

        print("EMAIL SENT")

        server.quit()

    except Exception as e:
        print("EMAIL FAILED:", str(e))
        

    print("🔥 API HIT /test-email")

    try:
        data = request.get_json()

        subject = data.get("subject")
        message = data.get("message")

        send_email(subject, message)

        return jsonify({
            "success": True,
            "msg": "Email bhej di gayi"
        })

    except Exception as e:
        print("❌ ERROR:", str(e))
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# ==============================
# REGISTER
# ==============================

@app.route("/api/register", methods=["POST"])
def register():
    try:
        print("🔥 REGISTER API HIT")

        data = request.get_json()

        name = data.get("name")
        email = data.get("email")
        password = data.get("password")

        # 🔹 check existing
        if users.find_one({"email": email}):
            return jsonify({
                "success": False,
                "error": "User already exists"
            }), 400

        # 🔹 hash password
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        # 🔹 save user
        users.insert_one({
            "name": name,
            "email": email,
            "password": hashed_password,
            "provider": "local",
            "createdAt": datetime.utcnow()
        })

        print("✅ USER SAVED")

        # 🔥 ADMIN EMAIL SEND
        subject = "🚀 New User Registered"
        body = f"""
New user registered on your platform:

Name: {name}
Email: {email}

Check admin panel for more details.
"""

        send_email(subject, body)

        print("📨 EMAIL SENT TO ADMIN")

        return jsonify({
            "success": True,
            "message": "User registered successfully"
        })

    except Exception as e:
        print("❌ REGISTER ERROR:", str(e))
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

    try:

        data = request.json

        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"success": False}), 400

        if users.find_one({"email": email}):
            return jsonify({"success": False, "error": "User exists"}), 400

        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        user = {
            "name": data.get("name"),
            "gender": data.get("gender"),
            "age": data.get("age"),
            "email": email,
            "password": hashed_pw,
            "provider": "local",
            "createdAt": datetime.now(timezone.utc)
        }

        users.insert_one(user)

        details = get_user_details()

        send_email(
            "New User Registered",
            f"""
Name: {user['name']}
Email: {user['email']}
Gender: {user['gender']}
Age: {user['age']}
IP: {details['ip']}
Country: {details['country']}
City: {details['city']}
Device: {details['device']}
Browser: {details['browser']}
OS: {details['os']}
"""
        )

        return jsonify({"success": True})

    except Exception as e:
        print("Register error:", e)
        return jsonify({"success": False}), 500

# ==============================
# LOGIN
# ==============================

@app.route("/api/login", methods=["POST"])
def login():

    data = request.json

    email = data.get("email")
    password = data.get("password")

    user = users.find_one({
        "email": email,
        "provider": "local"
    })

    if not user:
        return jsonify({"success": False}), 404

    if not bcrypt.checkpw(password.encode(), user["password"]):
        return jsonify({"success": False}), 401

    token = create_token(user)

    return jsonify({
        "success": True,
        "token": token,
        "user": {
            "name": user.get("name"),
            "email": user.get("email"),
            "gender": user.get("gender"),
            "age": user.get("age"),
            "provider": user.get("provider")
        }
    })

# ==============================
# GOOGLE LOGIN
# ==============================

@app.route("/api/auth/google", methods=["POST"])
def google_auth():

    data = request.json

    try:

        idinfo = id_token.verify_oauth2_token(
            data.get("token"),
            grequests.Request(),
            GOOGLE_CLIENT_ID
        )

        email = idinfo["email"]

        user = users.find_one({"email": email})

        if not user:

            user = {
                "name": idinfo.get("name"),
                "email": email,
                "picture": idinfo.get("picture"),
                "provider": "google",
                "createdAt": datetime.now(timezone.utc)
            }

            users.insert_one(user)

        token = create_token(user)

        return jsonify({
            "success": True,
            "token": token,
            "user": {
                "name": user.get("name"),
                "email": user.get("email"),
                "provider": user.get("provider")
            }
        })

    except Exception as e:
        print("Google error:", e)
        return jsonify({"success": False}), 401

# ==============================
# VERIFY USER
# ==============================

@app.route("/api/me")
def get_me():

    auth = request.headers.get("Authorization")

    if not auth:
        return jsonify({"success": False}), 401

    try:

        token = auth.split(" ")[1]

        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])

        user = users.find_one(
            {"email": decoded["email"]},
            {"password": 0}
        )

        if user:
            user["_id"] = str(user["_id"])

        return jsonify({
            "success": True,
            "user": user
        })

    except Exception as e:
        print("JWT error:", e)
        return jsonify({"success": False}), 401

# ==============================
# JOB APPLICATION
# ==============================

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
        "createdAt": datetime.now(timezone.utc)
    }

    applications.insert_one(application)

    send_email(
        "New Job Application",
        f"""
Name: {application['name']}
Email: {application['email']}
Phone: {application['phone']}
Job: {application['job']}
Experience: {application['experience']}

Message:
{application['message']}
"""
    )

    return jsonify({"success": True})

# ==============================
# RUN SERVER
# ==============================

if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5000))

    app.run(host="0.0.0.0", port=port)