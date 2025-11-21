import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, EmailStr

from database import db, create_document, get_documents
from schemas import User, Session, MagicLink

app = FastAPI()

# Environment/config
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
GOOGLE_CLIENT_ID = os.getenv("OAUTH_GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("OAUTH_GOOGLE_CLIENT_SECRET")
GITHUB_CLIENT_ID = os.getenv("OAUTH_GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("OAUTH_GITHUB_CLIENT_SECRET")
SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "arcyn_session")
SESSION_DAYS = int(os.getenv("SESSION_DAYS", "7"))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true").lower() == "true"

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL, "http://localhost:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------- Models ----------------------
class EmailStartRequest(BaseModel):
    email: EmailStr

class EmailVerifyRequest(BaseModel):
    email: EmailStr
    code: str

class OAuthStartRequest(BaseModel):
    provider: str

# ---------------------- Helpers ----------------------

def issue_session(user_id: str, ua: Optional[str]) -> dict:
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)
    sess = Session(user_id=user_id, token=token, expires_at=expires_at, user_agent=ua)
    create_document("session", sess)
    return {"token": token, "expires_at": expires_at.isoformat()}


def set_session_cookie(response: JSONResponse | RedirectResponse, token: str, expires: datetime):
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        expires=int(expires.timestamp()),
        path="/",
    )


def get_session_from_cookie(request: Request) -> Optional[dict]:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None
    rec = db["session"].find_one({"token": token}) if db else None
    if not rec:
        return None
    if rec.get("expires_at") and rec["expires_at"] < datetime.now(timezone.utc):
        return None
    user = db["user"].find_one({"_id": rec.get("user_id")}) if db else None
    return {"token": token, "user_id": str(rec.get("user_id")), "expires_at": rec.get("expires_at"), "user": {"email": user.get("email") if user else None}}

# ---------------------- Routes ----------------------

@app.get("/")
def read_root():
    return {"message": "Arcyn API ready"}

@app.get("/api/hello")
def hello():
    return {"message": "Hello from the backend API!"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = os.getenv("DATABASE_NAME") or "❌ Not Set"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    return response

# -------- Session helpers --------

@app.get("/auth/session")
def get_session(request: Request):
    sess = get_session_from_cookie(request)
    if not sess:
        return JSONResponse({"ok": False, "session": None}, status_code=401)
    # convert datetime to iso
    exp = sess.get("expires_at")
    if isinstance(exp, datetime):
        sess["expires_at"] = exp.isoformat()
    return {"ok": True, "session": sess}

@app.post("/auth/signout")
def signout(request: Request):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    response = JSONResponse({"ok": True})
    if token and db:
        db["session"].delete_many({"token": token})
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return response

# -------- Email Magic Link --------

@app.post("/auth/email/start")
def start_email_auth(payload: EmailStartRequest, request: Request):
    code = f"{secrets.randbelow(1000000):06d}"
    ml = MagicLink(email=payload.email, code=code)
    create_document("magiclink", ml)

    existing = db["user"].find_one({"email": payload.email}) if db else None
    if not existing:
        create_document("user", User(email=payload.email, provider="email"))

    # In production, send the code via email provider (SES, Resend, etc.)
    return {"ok": True, "code": code}

@app.post("/auth/email/verify")
def verify_email_auth(payload: EmailVerifyRequest, request: Request):
    record = db["magiclink"].find_one({"email": payload.email, "code": payload.code, "used": False}) if db else None
    if not record:
        raise HTTPException(status_code=400, detail="Invalid or used code")

    # mark used
    db["magiclink"].update_one({"_id": record["_id"]}, {"$set": {"used": True, "used_at": datetime.now(timezone.utc)}})

    # ensure user exists
    user = db["user"].find_one({"email": payload.email}) if db else None
    if not user:
        uid = create_document("user", User(email=payload.email, provider="email"))
        user_id = uid
    else:
        user_id = str(user.get("_id")) if user.get("_id") else str(user["_id"]) if "_id" in user else None

    session = issue_session(user_id, request.headers.get("User-Agent"))
    res = JSONResponse({"ok": True})
    # set secure, httpOnly cookie
    exp_dt = datetime.fromisoformat(session["expires_at"])
    set_session_cookie(res, session["token"], exp_dt)
    return res

# -------- OAuth (Production-ready patterns) --------

def oauth_redirect_uri(provider: str) -> str:
    return f"{BACKEND_URL}/auth/oauth/callback/{provider}"

@app.get("/auth/oauth/start")
@app.post("/auth/oauth/start")
def oauth_start(request: Request, payload: Optional[OAuthStartRequest] = None):
    provider = (payload.provider if payload else request.query_params.get("provider", "")).lower()
    if provider not in ("google", "github"):
        raise HTTPException(status_code=400, detail="Unsupported provider")

    state = secrets.token_urlsafe(16)
    # Note: In production you'd persist the state tied to a nonce; keeping simple here.

    if provider == "google":
        if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET):
            raise HTTPException(status_code=500, detail="Google OAuth not configured")
        params = {
            "client_id": GOOGLE_CLIENT_ID,
            "redirect_uri": oauth_redirect_uri("google"),
            "response_type": "code",
            "scope": "openid email profile",
            "access_type": "offline",
            "include_granted_scopes": "true",
            "state": state,
            "prompt": "consent",
        }
        url = "https://accounts.google.com/o/oauth2/v2/auth"
        # redirect
        return RedirectResponse(url=f"{url}?" + "&".join([f"{k}={requests.utils.quote(str(v))}" for k, v in params.items()]))

    if provider == "github":
        if not (GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET):
            raise HTTPException(status_code=500, detail="GitHub OAuth not configured")
        params = {
            "client_id": GITHUB_CLIENT_ID,
            "redirect_uri": oauth_redirect_uri("github"),
            "scope": "read:user user:email",
            "state": state,
            "allow_signup": "true",
        }
        url = "https://github.com/login/oauth/authorize"
        return RedirectResponse(url=f"{url}?" + "&".join([f"{k}={requests.utils.quote(str(v))}" for k, v in params.items()]))


@app.get("/auth/oauth/callback/{provider}")
def oauth_callback(provider: str, request: Request):
    provider = provider.lower()
    code = request.query_params.get("code")
    if not code:
        return RedirectResponse(url=f"{FRONTEND_URL}?auth=error")

    email = None
    provider_id = None

    if provider == "google":
        if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET):
            return RedirectResponse(url=f"{FRONTEND_URL}?auth=error")
        token_res = requests.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": oauth_redirect_uri("google"),
            },
            headers={"Accept": "application/json"},
            timeout=10,
        )
        token_json = token_res.json()
        id_token = token_json.get("id_token")
        access_token = token_json.get("access_token")
        # Fetch userinfo
        uinfo = requests.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        ).json()
        email = uinfo.get("email")
        provider_id = uinfo.get("sub")

    elif provider == "github":
        if not (GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET):
            return RedirectResponse(url=f"{FRONTEND_URL}?auth=error")
        token_res = requests.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": oauth_redirect_uri("github"),
            },
            headers={"Accept": "application/json"},
            timeout=10,
        )
        token_json = token_res.json()
        access_token = token_json.get("access_token")
        uinfo = requests.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            timeout=10,
        ).json()
        email = uinfo.get("email")
        provider_id = str(uinfo.get("id")) if uinfo.get("id") else None
        # If email is private, fetch primary email
        if not email:
            emails = requests.get(
                "https://api.github.com/user/emails",
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
                timeout=10,
            ).json()
            primary = next((e for e in emails if e.get("primary")), None)
            email = primary.get("email") if primary else (emails[0]["email"] if emails else None)

    else:
        return RedirectResponse(url=f"{FRONTEND_URL}?auth=error")

    if not email:
        return RedirectResponse(url=f"{FRONTEND_URL}?auth=error")

    # Upsert user
    existing = db["user"].find_one({"email": email}) if db else None
    if not existing:
        uid = create_document("user", User(email=email, provider=provider, provider_id=provider_id or ""))
        user_id = uid
    else:
        user_id = str(existing.get("_id")) if existing.get("_id") else str(existing["_id"]) if "_id" in existing else None

    session = issue_session(user_id, request.headers.get("User-Agent"))
    res = RedirectResponse(url=f"{FRONTEND_URL}?auth=success")
    exp_dt = datetime.fromisoformat(session["expires_at"])
    set_session_cookie(res, session["token"], exp_dt)
    return res

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
