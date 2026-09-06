from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import settings
from app.core.database import get_db
from app.core.security import (
    verify_password,
    get_password_hash,
    create_access_token,
    decode_access_token,
    oauth2_scheme,
)
from app.models.user import User
from app.schemas.auth import UserRegister, UserLogin, Token, UserOut

router = APIRouter()


async def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Dependency to retrieve authenticated user from JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise credentials_exception

    payload = decode_access_token(token)
    if payload is None:
        raise credentials_exception

    email: Optional[str] = payload.get("sub")
    if email is None:
        raise credentials_exception

    stmt = select(User).where(User.email == email)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if user is None:
        raise credentials_exception

    return user


async def get_current_user_optional(
    token: Optional[str] = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """Dependency to retrieve user if valid bearer token is provided, or None if guest."""
    if not token:
        return None
    try:
        return await get_current_user(token, db)
    except HTTPException:
        return None


@router.post(
    "/register",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new cybersecurity investigator or analyst account"
)
async def register(user_in: UserRegister, db: AsyncSession = Depends(get_db)):
    # Check for existing user
    stmt = select(User).where(User.email == user_in.email)
    result = await db.execute(stmt)
    existing_user = result.scalar_one_or_none()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An investigator account with this email already exists."
        )

    hashed_pw = get_password_hash(user_in.password)
    new_user = User(
        email=user_in.email,
        hashed_password=hashed_pw,
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return new_user


@router.post(
    "/login",
    response_model=Token,
    summary="Authenticate and receive JWT bearer token (supports JSON & OAuth2 Form)",
    openapi_extra={
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "email": {"type": "string", "format": "email", "example": "investigator@cyberforensics.gov"},
                            "password": {"type": "string", "example": "SuperSecurePassword123!"},
                        },
                        "required": ["email", "password"],
                    }
                },
                "application/x-www-form-urlencoded": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "username": {"type": "string", "example": "investigator@cyberforensics.gov"},
                            "password": {"type": "string", "example": "SuperSecurePassword123!"},
                        },
                        "required": ["username", "password"],
                    }
                },
            }
        }
    },
)
async def login(request: Request, db: AsyncSession = Depends(get_db)):
    content_type = request.headers.get("content-type", "").lower()
    email_val = None
    password_val = None

    if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
        form = await request.form()
        email_val = form.get("username") or form.get("email")
        password_val = form.get("password")
    else:
        try:
            body = await request.json()
            if isinstance(body, dict):
                email_val = body.get("email") or body.get("username")
                password_val = body.get("password")
            else:
                raise ValueError("Expected JSON dictionary object.")
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Invalid request payload. Expected JSON with 'email' and 'password' or form-data with 'username' and 'password'.",
            )

    if not email_val or not password_val:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Both email/username and password are required.",
        )

    stmt = select(User).where(User.email == str(email_val).strip())
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not verify_password(str(password_val), user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(subject=user.email)
    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
    )


@router.get(
    "/me",
    response_model=UserOut,
    summary="Fetch profile of currently authenticated user"
)
async def read_current_user(current_user: User = Depends(get_current_user)):
    return current_user
