import os
import time
import base64
import hashlib
import requests
import urllib3
import json
# Disable self-signed certificate warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONFIG_PATH = "/run/secrets/trembita.io/autologin.secret.json"

try:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        config = json.load(f)
except Exception as e:
    raise RuntimeError(f"Failed to load configuration from {CONFIG_PATH}: {e}")

USERNAME = config.get("USERNAME", "uxpadmin")
PASSWORD = config.get("PASSWORD", "uxpadminp")
REDIRECT_URI = config.get("REDIRECT_URI", "https://192.168.99.185:4000")
CLIENT_ID = config.get("CLIENT_ID", "uxp-ss-ui")
SECURITY_SERVER_ADDRESS = config.get("SECURITY_SERVER_ADDRESS", "https://192.168.99.185:4000")
TOKEN_CREDENTIALS = config.get("TOKEN_CREDENTIALS", "")  # Format: "0:1234,1:5678"
MAX_RETRIES = int(config.get("OAUTH_RETRIES", "3"))

AUTH_API_URL = f"{SECURITY_SERVER_ADDRESS}/auth-api/v1"
API_URL = f"{SECURITY_SERVER_ADDRESS}/api/v1"


def get_oauth_token(username, password, redirect_uri, client_id, auth_api_url):
    # Step 1: Get temporary token
    login_resp = requests.post(
        f"{auth_api_url}/login",
        json={"username": username, "password": password},
        headers={"Content-Type": "application/json"},
        verify=False
    )
    login_resp.raise_for_status()
    access_token = login_resp.json()["accessToken"]

    # Step 2: Generate code_verifier and code_challenge
    code_verifier = base64.urlsafe_b64encode(os.urandom(64)).decode("utf-8").rstrip("=")
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode("utf-8")).digest()
    ).decode("utf-8").rstrip("=")

    # Step 3: Get authorization code
    params = {
        "response_type": "code",
        "scope": "uxp_roles",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }

    auth_resp = requests.get(
        f"{auth_api_url}/oauth2/authorize",
        headers={"Authorization": f"Bearer {access_token}"},
        params=params,
        allow_redirects=False,
        verify=False
    )

    auth_data = auth_resp.json()
    authorization_code = auth_data["code"]

    # Step 4: Exchange authorization code for access token
    token_resp = requests.post(
        f"{auth_api_url}/oauth2/token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
            "code": authorization_code,
            "scope": "uxp_roles"
        },
        verify=False
    )
    token_resp.raise_for_status()
    final_access_token = token_resp.json()["access_token"]
    print("✅ Access token acquired:")
    print(final_access_token)
    return final_access_token


def get_oauth_token_with_retry(username, password, redirect_uri, client_id, auth_api_url, retries):
    last_exception = None
    for attempt in range(1, retries + 1):
        try:
            print(f"🔁 Authorization attempt {attempt}/{retries}...")
            return get_oauth_token(username, password, redirect_uri, client_id, auth_api_url)
        except Exception as e:
            print(f"⚠️ Authorization error: {e}")
            last_exception = e
            time.sleep(1)
    raise RuntimeError(f"❌ Failed to acquire token after {retries} attempts") from last_exception


def login_token(api_auth_token, api_uri, token_number, token_pass):
    token_login_resp = requests.post(
        f"{api_uri}/tokens/{token_number}/login",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_auth_token}",
            "accept": "application/json"
        },
        json={"password": token_pass},
        verify=False
    )

    try:
        result = token_login_resp.json()
    except ValueError:
        result = {"error": "Response is not valid JSON", "text": token_login_resp.text}

    if not token_login_resp.ok:
        error_message = result.get("error", result)
        raise requests.HTTPError(
            f"Token login failed: {token_login_resp.status_code} - {error_message}",
            response=token_login_resp
        )

    return result


def logout_oauth_token(api_auth_token, auth_api_url):
    token_logout_resp = requests.post(
        f"{auth_api_url}/logout",
        headers={
            "Authorization": f"Bearer {api_auth_token}",
            "accept": "*/*"
        },
        verify=False
    )

    if not token_logout_resp.ok:
        raise RuntimeError(
            f"Token logout failed: {token_logout_resp.status_code} - {token_logout_resp.text}"
        )

    return "🔒 API access token logged out successfully"


# === Main execution ===

uxp_login_token = ""

try:
    uxp_login_token = get_oauth_token_with_retry(
        USERNAME, PASSWORD, REDIRECT_URI, CLIENT_ID, AUTH_API_URL, retries=MAX_RETRIES
    )

    # Parse token credentials from environment
    token_map = {}
    for pair in TOKEN_CREDENTIALS.split(","):
        if ":" in pair:
            token_id, token_pass = pair.split(":", 1)
            token_map[int(token_id.strip())] = token_pass.strip()

    # Attempt login for each token
    for token_id, token_pass in token_map.items():
        try:
            result = login_token(uxp_login_token, API_URL, token_id, token_pass)
            print(f"✅ Token {token_id} login successful:")
            print(result)
        except Exception as err:
            print(f"❌ Token {token_id} login failed:")
            print(err)

except Exception as err:
    print(f"‼️ Error during token acquisition or login: {err}")
    exit(1)

if uxp_login_token:
    try:
        logout_result = logout_oauth_token(uxp_login_token, AUTH_API_URL)
        print(logout_result)
    except Exception as err:
        print(f"‼️ Error during logout: {err}")
        exit(2)
exit(0)