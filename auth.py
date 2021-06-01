import json

import google.oauth2.credentials
import gspread
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from google.cloud import firestore
from jose import JWTError, jwt
from pydantic import BaseModel
from requests_oauthlib import OAuth2Session

with open(".secrets/client_secret.json") as fp:
    OAUTH2_CLIENT_SECRET = json.load(fp)["web"]

with open(".secrets/jwt_secret.json") as fp:
    SECRET_KEY = json.load(fp)["secret_key"]

SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/spreadsheets",
]

router = APIRouter()
scheme = HTTPBearer()


def log_token_updated(token):
    print(f"Token updated: {token}")


def get_firestore_client():
    return firestore.Client()


def save_user_google_token(db: firestore.Client, google: OAuth2Session):
    resp = google.get("https://www.googleapis.com/oauth2/v2/userinfo")
    user = resp.json()

    doc_ref = db.collection("users").document(user["email"])
    doc_ref.set({"token": google.token}, merge=True)


def get_current_user(auth: HTTPAuthorizationCredentials = Depends(scheme)):
    try:
        return jwt.decode(auth.credentials, SECRET_KEY)
    except JWTError:
        HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_user_token(
    db: firestore.Client = Depends(get_firestore_client),
    user: str = Depends(get_current_user),
):
    doc_ref = db.collection("users").document(user["email"])
    if not doc_ref.get().exists:
        return None
    return doc_ref.get().to_dict()["token"]


def get_user_google_session(token=Depends(get_user_token)):
    if token is None:
        return None

    return OAuth2Session(
        client_id=OAUTH2_CLIENT_SECRET["client_id"],
        token=token,
        auto_refresh_url=OAUTH2_CLIENT_SECRET["token_uri"],
        auto_refresh_kwargs={
            "client_id": OAUTH2_CLIENT_SECRET["client_id"],
            "client_secret": OAUTH2_CLIENT_SECRET["client_secret"],
        },
        redirect_uri="http://localhost:8000",
        scope=SCOPES,
        token_updater=log_token_updated,
    )


def get_user_gspread_client(token=Depends(get_user_token)) -> gspread.Client:
    credentials = google.oauth2.credentials.Credentials(
        token=token["access_token"],
        refresh_token=token["refresh_token"],
        token_uri=OAUTH2_CLIENT_SECRET["token_uri"],
        client_id=OAUTH2_CLIENT_SECRET["client_id"],
        client_secret=OAUTH2_CLIENT_SECRET["client_secret"],
    )

    return gspread.authorize(credentials=credentials)


class Auth(BaseModel):
    code: str


class Token(BaseModel):
    access_token: str
    token_type: str


@router.post("/token", response_model=Token)
def login(auth: Auth, db: firestore.Client = Depends(get_firestore_client)) -> Token:
    print(auth.code)
    google = OAuth2Session(
        client_id=OAUTH2_CLIENT_SECRET["client_id"],
        auto_refresh_url=OAUTH2_CLIENT_SECRET["token_uri"],
        auto_refresh_kwargs=OAUTH2_CLIENT_SECRET,
        redirect_uri="http://localhost:8000",
        scope=SCOPES,
    )

    google.fetch_token(
        token_url=OAUTH2_CLIENT_SECRET["token_uri"],
        code=auth.code,
        client_secret=OAUTH2_CLIENT_SECRET["client_secret"],
    )

    save_user_google_token(db, google)

    resp = google.get("https://www.googleapis.com/oauth2/v2/userinfo")
    access_token = jwt.encode(resp.json(), SECRET_KEY)
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/me")
def protected(google: OAuth2Session = Depends(get_user_google_session)):
    return google.get("https://www.googleapis.com/oauth2/v2/userinfo").json()
