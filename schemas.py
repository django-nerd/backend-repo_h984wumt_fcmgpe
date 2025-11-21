"""
Database Schemas

Define your MongoDB collection schemas here using Pydantic models.
Each Pydantic model represents a collection in your database.
Class name lowercased becomes the collection name.

This app uses persistent collections for auth:
- User: profiles created after signup/login
- Session: issued tokens (demo only, unsigned opaque strings)
- MagicLink: passwordless email codes (demo)
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional
from datetime import datetime

class User(BaseModel):
    email: EmailStr
    name: Optional[str] = None
    avatar_url: Optional[str] = None
    provider: Optional[str] = Field(None, description="auth provider: email|google|github")
    provider_id: Optional[str] = None
    is_active: bool = True

class Session(BaseModel):
    user_id: str
    token: str
    expires_at: Optional[datetime] = None
    user_agent: Optional[str] = None

class MagicLink(BaseModel):
    email: EmailStr
    code: str
    used: bool = False
    used_at: Optional[datetime] = None
