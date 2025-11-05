import os
from datetime import datetime, timedelta
from dotenv import load_dotenv
from flask import Flask, jsonify, request, redirect
from flask_cors import CORS
from authlib.integrations.flask_client import OAuth
from pymongo import MongoClient
import jwt, json
from bson import ObjectId
from urllib.parse import quote_plus

load_dotenv()
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "supersecretkey123")

# Fixed CORS configuration
CORS(app, 
     resources={r"/*": {"origins": "*"}},
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://127.0.0.1:27017/")
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:5000")

client = MongoClient(MONGO_URI)
db = client["revision_app"]

oauth = OAuth(app)
oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

def create_access_token(user_id, email):
    payload = {
        "sub": str(user_id),
        "email": email,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=24)  # Extended to 24 hours
    }
    return jwt.encode(payload, app.secret_key, algorithm=JWT_ALGORITHM)

def get_current_user():
    auth_header = request.headers.get("Authorization", "")
    print(f"[DEBUG] Authorization header: {auth_header[:50]}..." if len(auth_header) > 50 else f"[DEBUG] Authorization header: {auth_header}")
    
    if not auth_header.startswith("Bearer "):
        print("[DEBUG] Missing or invalid authorization header format")
        return None, {"error": "missing_or_invalid_authorization_header"}, 401
    
    token = auth_header.split(" ", 1)[1]
    print(f"[DEBUG] Extracted token: {token[:20]}...")
    
    try:
        decoded = jwt.decode(token, app.secret_key, algorithms=[JWT_ALGORITHM])
        print(f"[DEBUG] Decoded JWT: {decoded}")
        
        user = db.users.find_one({"_id": ObjectId(decoded["sub"])})
        if not user:
            print(f"[DEBUG] User not found for ID: {decoded['sub']}")
            return None, {"error": "user_not_found"}, 404
        
        print(f"[DEBUG] User found: {user['email']}")
        return user, None, 200
    except jwt.ExpiredSignatureError as e:
        print(f"[DEBUG] Token expired: {e}")
        return None, {"error": "token_expired"}, 401
    except jwt.InvalidTokenError as e:
        print(f"[DEBUG] Invalid token: {e}")
        return None, {"error": "invalid_token"}, 401
    except Exception as e:
        print(f"[DEBUG] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return None, {"error": "authentication_failed"}, 401

# --- OAuth ---
@app.route("/auth/google/login")
def google_login():
    redirect_uri = f"{BASE_URL}/auth/google/callback"
    return oauth.google.authorize_redirect(redirect_uri)

@app.route("/auth/google/signup")
def google_signup():
    redirect_uri = f"{BASE_URL}/auth/google/callback"
    return oauth.google.authorize_redirect(redirect_uri)

@app.route("/auth/google/callback")
def google_callback():
    try:
        token = oauth.google.authorize_access_token()
        userinfo = token.get('userinfo')
        if not userinfo:
            resp = oauth.google.get('userinfo')
            userinfo = resp.json()
        
        if not userinfo or 'email' not in userinfo or 'sub' not in userinfo:
            return redirect("http://localhost:8080/index.html?error=oauthfail")
        
        user = db.users.find_one({"google_id": userinfo['sub']})
        if not user:
            user = {
                "email": userinfo["email"], 
                "google_id": userinfo["sub"], 
                "name": userinfo.get("name", ""),
                "picture": userinfo.get("picture", ""), 
                "email_verified": userinfo.get("email_verified", False),
                "created_at": datetime.utcnow(), 
                "last_login": datetime.utcnow()
            }
            ins = db.users.insert_one(user)
            user["_id"] = ins.inserted_id
        else:
            db.users.update_one(
                {"_id": user["_id"]}, 
                {"$set": {
                    "last_login": datetime.utcnow(), 
                    "picture": userinfo.get("picture", ""),
                    "name": userinfo.get("name", user.get("name", ""))
                }}
            )
        
        user_data = {
            "id": str(user["_id"]), 
            "email": user["email"], 
            "name": user.get("name", ""),
            "picture": user.get("picture", ""), 
            "email_verified": user.get("email_verified", False)
        }
        access_token = create_access_token(user["_id"], user["email"])
        user_blob = quote_plus(json.dumps(user_data))
        return redirect(f"http://localhost:8080/dashboard.html?user={user_blob}&token={access_token}")
    except Exception as e:
        print(f"OAuth callback error: {e}")
        return redirect("http://localhost:8080/index.html?error=oauthfail")

# --- Subjects ---
@app.route("/api/subjects", methods=["POST"])
def add_subject():
    print(f"[DEBUG] POST /api/subjects - Headers: {dict(request.headers)}")
    user, error, status = get_current_user()
    if error: 
        print(f"[DEBUG] Auth failed: {error}")
        return jsonify(error), status
    
    data = request.get_json()
    if not data or not data.get("name"):
        return jsonify({"error": "name is required"}), 400
    
    subject = {
        "user_id": user["_id"], 
        "name": data.get("name"), 
        "color": data.get("color", "#CCCCCC"), 
        "created_at": datetime.utcnow()
    }
    ins = db.subjects.insert_one(subject)
    subject["_id"] = str(ins.inserted_id)
    subject["user_id"] = str(subject["user_id"])
    return jsonify({"subject": subject})

@app.route("/api/subjects", methods=["GET"])
def get_subjects():
    print(f"[DEBUG] GET /api/subjects - Headers: {dict(request.headers)}")
    user, error, status = get_current_user()
    if error: 
        print(f"[DEBUG] Auth failed: {error}")
        return jsonify(error), status
    
    subjects = list(db.subjects.find({"user_id": user["_id"]}))
    for s in subjects: 
        s["_id"] = str(s["_id"])
        s["user_id"] = str(s["user_id"])
    return jsonify({"subjects": subjects})

# --- Topics ---
@app.route("/api/topics", methods=["POST"])
def add_topic():
    user, error, status = get_current_user()
    if error: 
        return jsonify(error), status
    
    data = request.get_json()
    try:
        day0_date = datetime.fromisoformat(data.get("day0_date"))
    except:
        day0_date = datetime.utcnow()
    
    topic = {
        "user_id": user["_id"], 
        "subject_id": ObjectId(data.get("subject_id")),
        "title": data.get("title"), 
        "summary": data.get("summary", ""),
        "day0_date": day0_date, 
        "tags": data.get("tags", []), 
        "created_at": datetime.utcnow()
    }
    ins = db.topics.insert_one(topic)
    topic_id = ins.inserted_id
    topic["_id"] = str(topic_id)
    topic["user_id"] = str(topic["user_id"])
    topic["subject_id"] = str(topic["subject_id"])
    
    repetition = {
        "user_id": user["_id"], 
        "topic_id": topic_id, 
        "repetition_count": 0,
        "interval_days": 1, 
        "ease_factor": 2.5, 
        "last_reviewed_at": day0_date,
        "next_review_at": (day0_date + timedelta(days=1)).date(), 
        "performance": []
    }
    db.repetition.insert_one(repetition)
    return jsonify({"topic": topic})

@app.route("/api/topics/<subject_id>", methods=["GET"])
def get_topics(subject_id):
    user, error, status = get_current_user()
    if error: 
        return jsonify(error), status
    
    topics = list(db.topics.find({"user_id": user["_id"], "subject_id": ObjectId(subject_id)}))
    for t in topics:
        t["_id"] = str(t["_id"])
        t["subject_id"] = str(t["subject_id"])
        t["user_id"] = str(t["user_id"])
    return jsonify({"topics": topics})

# --- Review queue ---
@app.route("/api/reviews/queue", methods=["GET"])
def review_queue():
    user, error, status = get_current_user()
    if error: 
        return jsonify(error), status
    
    today = datetime.utcnow().date()
    reps = list(db.repetition.find({"user_id": user["_id"], "next_review_at": {"$lte": today}}))
    queue = []
    for rep in reps:
        topic = db.topics.find_one({"_id": rep["topic_id"]})
        if topic:
            queue.append({
                "topic_id": str(topic["_id"]), 
                "title": topic["title"],
                "summary": topic.get("summary", ""), 
                "repetition_count": rep["repetition_count"],
                "last_reviewed_at": rep["last_reviewed_at"].isoformat(),
                "next_review_at": str(rep["next_review_at"])
            })
    return jsonify({"queue": queue})

# --- Review submit ---
@app.route("/api/reviews/<topic_id>", methods=["POST"])
def review_topic(topic_id):
    user, error, status = get_current_user()
    if error: 
        return jsonify(error), status
    
    data = request.get_json()
    quality = int(data.get("quality"))
    rep = db.repetition.find_one({"user_id": user["_id"], "topic_id": ObjectId(topic_id)})
    if not rep: 
        return jsonify({"error": "repetition not found"}), 404
    
    # SM-2 logic
    if quality < 3:
        rep["repetition_count"] = 0
        interval = 1
    else:
        interval = 1 if rep["repetition_count"] == 0 else 3 if rep["repetition_count"] == 1 else round(rep["interval_days"] * rep["ease_factor"])
        rep["repetition_count"] += 1
        ef = rep["ease_factor"] + 0.1 - (5 - quality) * (0.08 + (5 - quality) * 0.02)
        rep["ease_factor"] = max(ef, 1.3)
    
    rep["interval_days"] = interval
    rep["last_reviewed_at"] = datetime.utcnow()
    rep["next_review_at"] = (datetime.utcnow().date() + timedelta(days=interval))
    rep.setdefault("performance", []).append(quality)
    db.repetition.update_one({"_id": rep["_id"]}, {"$set": rep})
    
    review = {
        "user_id": user["_id"], 
        "topic_id": ObjectId(topic_id),
        "quality": quality, 
        "response_time_ms": data.get("response_time_ms", None),
        "created_at": datetime.utcnow()
    }
    db.review.insert_one(review)
    return jsonify({"success": True, "next_review_at": str(rep["next_review_at"])})

@app.route("/")
def index():
    return jsonify({"message": "Revision App Backend Working"})

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "endpoint_not_found"}), 404

if __name__ == "__main__":
    app.run(debug=True, port=5000)