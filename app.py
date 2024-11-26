# Python standard libraries
import json
import os
import json
from google.oauth2 import id_token
from google.auth.transport import requests as req
from verify_token import verify_google_access_token

# Third-party libraries
from flask import Flask, redirect, request, url_for, session
from oauthlib.oauth2 import WebApplicationClient
import requests

# Configuration
GOOGLE_CLIENT_ID = os.environ.get("CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)


# Flask app setup
app = Flask(__name__)
app.secret_key = os.urandom(24)


# OAuth 2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)


@app.route("/")
def index():
    user_session = session.get("user")
    if not user_session:
        return '<a class="button" href="/login">Google Login</a>'
    else:
        user= User(user_session)
        return user_session
        return (
            "<p>Hello, {}! You're logged in! Email: {}</p>"
            "<div><p>Google Profile Picture:</p>"
            '<img src="{}" alt="Google profile pic"></img></div>'
            '<a class="button" href="/logout">Logout</a>'.format(
                user.name, user.email, user.profile_pict
            )
        )
        
    
def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

@app.route("/login/google")
def login():
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)


class user_obj:
    def __init__(self, dict):
        self.__dict__.update(dict)

def User(dict):
    return json.loads(json.dumps(dict), object_hook=user_obj)

@app.route("/login/google/callback")
def callback():
    code = request.args.get("code")
    
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    client.parse_request_body_response(json.dumps(token_response.json()))
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)
    access_token = token_response.json()["access_token"]

    print(verify_google_access_token(access_token))
    user = {}
    if userinfo_response.json().get("email_verified"):
        user["id"] = userinfo_response.json()["sub"]
        user["email"] = userinfo_response.json()["email"]
        user["profile_pict"] = userinfo_response.json()["picture"]
        user["given_name"] = userinfo_response.json()["given_name"]
        user["name"] = userinfo_response.json()["given_name"]
        session["user"] = user
    else:
        return "User email not available or not verified by Google.", 400
    return json.dumps(token_response.json())
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(ssl_context="adhoc", debug=True)