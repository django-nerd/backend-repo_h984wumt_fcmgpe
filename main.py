import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

from database import db, create_document, get_documents
from schemas import User, Session, MagicLink

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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

# ---------------------- Helpers ----------------------

def issue_session(user_id: str, ua: Optional[str]) -> dict:
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    sess = Session(user_id=user_id, token=token, expires_at=expires_at, user_agent=ua)
    create_document("session", sess)
    return {"token": token, "expires_at": expires_at.isoformat()}

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

# -------- Email Magic Link (Demo) --------

@app.post("/auth/email/start")
def start_email_auth(payload: EmailStartRequest, request: Request):
    # generate a 6-digit code and store in magiclink collection
    code = f"{secrets.randbelow(1000000):06d}"
    ml = MagicLink(email=payload.email, code=code)
    create_document("magiclink", ml)

    # upsert user skeleton
    existing = db["user"].find_one({"email": payload.email}) if db else None
    if not existing:
        create_document("user", User(email=payload.email, provider="email"))

    # NOTE: In production, send code via email provider. Here we return it for demo.
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
        user_id = str(user.get("_id"))

    session = issue_session(user_id, request.headers.get("User-Agent"))
    return {"ok": True, "session": session, "user": {"id": user_id, "email": payload.email}}

# -------- OAuth placeholders (Google/GitHub) --------
# These endpoints are simplified placeholders that mint a demo session immediately.

class OAuthStartRequest(BaseModel):
    provider: str

@app.post("/auth/oauth/start")
def oauth_start(payload: OAuthStartRequest, request: Request):
    provider = payload.provider.lower()
    if provider not in ("google", "github"):
        raise HTTPException(status_code=400, detail="Unsupported provider")

    # Demo-only: create or find a provider user and issue session
    email = f"demo@{provider}.local"
    existing = db["user"].find_one({"email": email}) if db else None
    if not existing:
        uid = create_document("user", User(email=email, provider=provider, provider_id="demo"))
        user_id = uid
    else:
        user_id = str(existing.get("_id"))

    session = issue_session(user_id, request.headers.get("User-Agent"))
    return {"ok": True, "session": session, "redirect": "/"}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
