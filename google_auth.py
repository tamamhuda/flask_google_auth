import os
from flask import Flask, redirect, url_for, session, request
import requests
from flask.json import jsonify
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
import json
from googleapiclient.discovery import build
from verify_token import verify_google_access_token
from google.oauth2.credentials import Credentials

app = Flask(__name__)

# The secret key is used by Flask for sessions
app.secret_key = os.urandom(24)

# The path to your OAuth 2.0 credentials file
CLIENT_SECRET_FILE = 'client_secret.json'

# The OAuth 2.0 redirect URI
REDIRECT_URI = 'https://127.0.0.1:5000/login/google/callback'

# Fetch the Google OAuth2 provider configuration (metadata)
def get_google_provider_cfg():
    return requests.get("https://accounts.google.com/.well-known/openid-configuration").json()

# Initialize OAuth flow
flow = Flow.from_client_secrets_file(
    CLIENT_SECRET_FILE,
    scopes=["https://www.googleapis.com/auth/userinfo.email", "openid", "https://www.googleapis.com/auth/userinfo.profile"],
    redirect_uri=REDIRECT_URI
)

def profile(access_token):
        google_provider_cfg = get_google_provider_cfg()
        userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
        # Use the credentials to fetch user info from Google
        headers = {
            'Authorization': f'Bearer {access_token}'
        }
        
        userinfo_response = requests.get(userinfo_endpoint, headers=headers)

        if userinfo_response.status_code == 200:
            user_info = userinfo_response.json()
            session['user_info'] = user_info
            return user_info
        else:
            return "Failed to retrieve user info"

def refresh_access_token(credentials):
    """
    Refresh the access token using the stored refresh token if expired.
    """
    if credentials and credentials.expired and credentials.refresh_token:
        # Refresh the access token if expired
        credentials.refresh(Request())
        # After refreshing, update the credentials in your storage (session or DB)
        session['credentials'] = credentials_to_dict(credentials)
    return credentials.token  # Return the new access token

@app.route('/')
def index():
    """Home route."""
    if 'credentials' in session:
        # return redirect('login')

        # Retrieve credentials from session
        credentials = Credentials.from_authorized_user_info(session['credentials'])

        # Refresh the access token if it is expired
        access_token = refresh_access_token(credentials)

        # Now you can use the updated access token to fetch user info
        user_info = profile(access_token)

        return json.dumps(user_info)
        # return f'Hello, you are logged in as: {credentials["token"]}'
    else:
        return redirect(url_for('login'))
    

@app.route('/login/google')
def login():
    """Redirect to Google's OAuth 2.0 authorization endpoint."""
    authorization_url, state = flow.authorization_url(
        access_type='offline', 
        include_granted_scopes='true'  
    )
    session['state'] = state
    print(state)
    return redirect(authorization_url)


@app.route('/login/google/callback')
def callback():
    """Handle the OAuth 2.0 callback from Google."""
    flow.fetch_token(authorization_response=request.url)

    # Store the credentials in the session
    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)

    # if credentials and credentials.expired and credentials.refresh_token:
    #     credentials.refresh(Request())    
    return redirect(url_for("index"))

@app.route('/logout')
def logout():
    """Logout by clearing the session."""
    session.clear()
    return redirect(url_for('index'))

def credentials_to_dict(credentials):
    """Converts credentials to a dictionary."""
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

if __name__ == "__main__":
    app.run(ssl_context="adhoc", debug=True)
