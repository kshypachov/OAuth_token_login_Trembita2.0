import requests
import hashlib
import base64
import os
import urllib.parse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==== Конфигурация ====
USERNAME = "uxpadmin"
PASSWORD = "uxpadminp"
REDIRECT_URI = "https://192.168.99.185:4000"
CLIENT_ID = "uxp-ss-ui"
SECURITY_SERVER_ADDRESS = "https://192.168.99.185:4000"

def get_oauth_token(username, password, redirect_uri, client_id, auth_api_url):
    # ==== Шаг 1: Получение временного токена ====
    login_resp = requests.post(
        f"{auth_api_url}/login",
        json={"username": username, "password": password},
        headers={"Content-Type": "application/json"}
        , verify=False
    )
    login_resp.raise_for_status()
    #print("Status code:", login_resp.status_code)
    #print("Response body:", login_resp.text)
    access_token = login_resp.json()["accessToken"]

    # ==== Шаг 2: Генерация code_verifier и code_challenge ====
    code_verifier = base64.urlsafe_b64encode(os.urandom(64)).decode("utf-8").rstrip("=")
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode("utf-8")).digest()
    ).decode("utf-8").rstrip("=")

    # ==== Шаг 3: Получение authorization code ====
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
        allow_redirects=False  # чтобы перехватить редирект с кодом
    , verify=False
    )

    #print(auth_resp.headers)
    #print(auth_resp.json())

    auth_data = auth_resp.json()
    authorization_code = auth_data["code"]

    # ==== Шаг 4: Обмен кода на access_token ====
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

    print("✅ Access token для доступа к API:")
    print(final_access_token)
    return final_access_token

def login_token(api_auth_token, api_uri, token_number, token_pass ):
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

def logout_oauth_token(api_auth_token, auth_api_url, ):
    token_login_resp = requests.post(
        f"{auth_api_url}/logout",
        headers={
            "Authorization": f"Bearer {api_auth_token}",
            "accept": "*/*"
        },
        data="",
        verify=False
    )
    token_login_resp.text
    if not token_login_resp.ok:
        #error_message = result.get("error", result)
        raise RuntimeError (
            f"Token logout failed: {token_login_resp.status_code}"
        )
    return "API auth token logged out"

AUTH_API_URL = f"{SECURITY_SERVER_ADDRESS}/auth-api/v1"
API_URL = f"{SECURITY_SERVER_ADDRESS}/api/v1"
uxp_login_token = ""

try:
    uxp_login_token = get_oauth_token(USERNAME, PASSWORD, REDIRECT_URI, CLIENT_ID, AUTH_API_URL)
    login_result = login_token(uxp_login_token, API_URL, 0, "12345")
    print(login_result)
except Exception as err:
    print(err)

if uxp_login_token:
    try:
        logout_result = logout_oauth_token(uxp_login_token, AUTH_API_URL)
        print(logout_result)
    except Exception as err:
        print(err)

