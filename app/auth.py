from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .database import get_db
from .deps import get_current_user
from .models import RefreshToken, User
from .ratelimit import limiter
from .schemas import (LoginRequest, Message, RefreshRequest, RegisterRequest,
                      TokenPair, UserOut)
from .security import (create_access_token, create_refresh_token, hash_password,
                       hash_token, verify_password)

router = APIRouter(prefix="/auth", tags=["auth"])


def _issue_token_pair(user: User, db: Session) -> TokenPair:
    access = create_access_token(user.id, user.role)
    refresh, expires_at = create_refresh_token(user.id)
    db.add(RefreshToken(user_id=user.id, token_hash=hash_token(refresh), expires_at=expires_at))
    db.commit()
    return TokenPair(access_token=access, refresh_token=refresh)


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
def register(request: Request, body: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")
    user = User(email=body.email, hashed_password=hash_password(body.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenPair)
@limiter.limit("5/minute")
def login(request: Request, body: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email).first()
    if user is None or not verify_password(body.password, user.hashed_password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Account is deactivated")
    return _issue_token_pair(user, db)


@router.post("/refresh", response_model=TokenPair)
def refresh(body: RefreshRequest, db: Session = Depends(get_db)):
    """Rotate: the used refresh token is revoked and a fresh pair is issued."""
    stored = db.query(RefreshToken).filter(
        RefreshToken.token_hash == hash_token(body.refresh_token)
    ).first()
    if stored is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown refresh token")
    if stored.revoked:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Refresh token already used or revoked")
    if stored.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Refresh token expired")
    stored.revoked = True  # rotation: one refresh token is usable exactly once
    user = db.get(User, stored.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or deactivated")
    return _issue_token_pair(user, db)


@router.post("/logout", response_model=Message)
def logout(body: RefreshRequest, db: Session = Depends(get_db)):
    """Revoke the caller's refresh token. Unknown tokens are treated as already logged out."""
    stored = db.query(RefreshToken).filter(
        RefreshToken.token_hash == hash_token(body.refresh_token)
    ).first()
    if stored is not None:
        stored.revoked = True
        db.commit()
    return Message(detail="Logged out")


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user
