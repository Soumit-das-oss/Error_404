from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, ConfigDict


class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=128, description="User password (min 6 chars)")


class UserLogin(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, description="User password")


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int


class TokenPayload(BaseModel):
    sub: Optional[str] = None
    exp: Optional[int] = None


class UserOut(BaseModel):
    id: int
    email: EmailStr
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
