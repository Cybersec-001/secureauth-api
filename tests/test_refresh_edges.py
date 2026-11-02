from datetime import datetime

from app.database import SessionLocal
from app.models import RefreshToken, User

from tests.conftest import login, make_user


def _set_refresh_expiry(email, when):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).one()
        token = db.query(RefreshToken).filter(RefreshToken.user_id == user.id).one()
        token.expires_at = when
        db.commit()
    finally:
        db.close()


def test_unknown_refresh_token_rejected(client):
    r = client.post("/auth/refresh", json={"refresh_token": "not-a-real-token"})
    assert r.status_code == 401
    assert r.json()["detail"] == "Unknown refresh token"


def test_expired_refresh_token_rejected(client):
    make_user(client)
    tokens = login(client)
    _set_refresh_expiry("user@example.com", datetime(2020, 1, 1))
    r = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 401
    assert "expired" in r.json()["detail"].lower()


def test_deactivated_user_cannot_refresh(client):
    make_user(client)
    tokens = login(client)
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == "user@example.com").one()
        user.is_active = False
        db.commit()
    finally:
        db.close()
    r = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 401
    assert "deactivated" in r.json()["detail"].lower()


def test_logout_with_unknown_token_is_a_no_op(client):
    r = client.post("/auth/logout", json={"refresh_token": "never-issued"})
    assert r.status_code == 200
    assert r.json()["detail"] == "Logged out"