"""Expired access tokens must be rejected exactly like any other invalid token."""
from datetime import datetime, timedelta, timezone

import jwt

from app.config import settings
from app.security import decode_access_token
from tests.conftest import login, make_user


def expired_token(user_id=1, role="user"):
    payload = {
        "sub": str(user_id),
        "role": role,
        "type": "access",
        "exp": datetime.now(timezone.utc) - timedelta(minutes=1),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def test_decode_returns_none_for_an_expired_token():
    assert decode_access_token(expired_token()) is None


def test_me_rejects_an_expired_token(client):
    make_user(client)
    r = client.get("/auth/me", headers={"Authorization": "Bearer " + expired_token()})
    assert r.status_code == 401


def test_freshly_issued_token_is_accepted(client):
    make_user(client)
    tokens = login(client)
    r = client.get("/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert r.status_code == 200
