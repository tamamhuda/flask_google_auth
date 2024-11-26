import requests


# Define the URL to verify the access token (Google's token info endpoint)
token_info_url = "https://www.googleapis.com/oauth2/v3/tokeninfo"

def verify_google_access_token(token):
    try:
        # Send a GET request to the tokeninfo endpoint with the access token
        response = requests.get(f"{token_info_url}?access_token={token}")
        
        # If the response status code is 200, the token is valid
        if response.status_code == 200:
            token_info = response.json()
            return token_info
        else:
            return response.json()
    
    except Exception as e:
        print(f"Error verifying token: {e}")
        return None
