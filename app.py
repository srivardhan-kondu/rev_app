import os
from datetime import datetime
from dotenv import load_dotenv
from flask import Flask, jsonify, request, redirect
from flask_cors import CORS
from authlib.integrations.flask_client import OAuth
from pymongo import MongoClient
import jwt, json
from bson import ObjectId
from urllib.parse import quote_plus

# load local .env in development only
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "supersecretkey123")
CORS(app, supports_credentials=True)

# CONFIG from environment
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://127.0.0.1:27017/")
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:5000")

client = MongoClient(MONGO_URI)
db = client["revision_app"]
users_collection = db["users"]

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
        "iat": datetime.utcnow().timestamp(),
        "exp": datetime.utcnow().timestamp() + 60 * 60
    }
    return jwt.encode(payload, app.secret_key, algorithm=JWT_ALGORITHM)

@app.route("/")
def index():
    return jsonify({"message": "Google OAuth Backend Working"})

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
    token = oauth.google.authorize_access_token()
    userinfo = token.get('userinfo')
    if not userinfo:
        userinfo = oauth.google.get('userinfo').json()
    google_id = userinfo.get("sub")
    email = userinfo.get("email")
    name = userinfo.get("name")
    picture = userinfo.get("picture", "")
    email_verified = userinfo.get("email_verified", False)

    if not email or not google_id:
        return redirect("http://localhost:8080/index.html?error=oauthfail")

    user = users_collection.find_one({"google_id": google_id})
    if not user:
        user = {
            "email": email, "google_id": google_id, "name": name,
            "picture": picture, "email_verified": email_verified,
            "created_at": datetime.utcnow(), "last_login": datetime.utcnow()
        }
        ins = users_collection.insert_one(user)
        user["_id"] = ins.inserted_id
    else:
        users_collection.update_one({"_id": user["_id"]},{"$set":{"last_login": datetime.utcnow(), "picture": picture}})
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

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "endpoint_not_found"}), 404

if __name__ == "__main__":
    app.run(debug=True, port=5000)
