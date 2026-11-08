import os

os.environ["DATABASE_URL"] = "sqlite:////tmp/sa-deps-test.db"
os.environ.setdefault("SECRET_KEY", "test-secret-key")

import jwt
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from app.config import settings
from app.database import Base, SessionLocal, engine
from app.deps import get_current_user, require_role
from app.models import User
from app.security import create_access_token, hash_password


@pytest.fixture()
def db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def creds(token):
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def add_user(db):
    user = User(email="a@b.co", hashed_password=hash_password("x"), role="user", is_active=True)
    db.add(user)
    db.commit()
    return user


def test_valid_token_resolves_user(db):
    user = add_user(db)
    assert get_current_user(creds(create_access_token(user.id, user.role)), db).id == user.id


def test_non_integer_sub_gets_401_not_500(db):
    add_user(db)
    token = jwt.encode({"sub": "not-a-number", "type": "access"},
                       settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    with pytest.raises(HTTPException) as exc:
        get_current_user(creds(token), db)
    assert exc.value.status_code == 401


def test_missing_sub_gets_401_not_500(db):
    token = jwt.encode({"type": "access"}, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    with pytest.raises(HTTPException) as exc:
        get_current_user(creds(token), db)
    assert exc.value.status_code == 401


def test_garbage_token_gets_401(db):
    with pytest.raises(HTTPException) as exc:
        get_current_user(creds("not-a-jwt"), db)
    assert exc.value.status_code == 401


def test_missing_credentials_get_401(db):
    with pytest.raises(HTTPException) as exc:
        get_current_user(None, db)
    assert exc.value.status_code == 401


def test_deactivated_user_gets_401(db):
    user = add_user(db)
    user.is_active = False
    db.commit()
    with pytest.raises(HTTPException) as exc:
        get_current_user(creds(create_access_token(user.id, user.role)), db)
    assert exc.value.status_code == 401


def test_require_role_passes_matching_role(db):
    user = add_user(db)
    user.role = "admin"
    db.commit()
    assert require_role("admin")(user) is user


def test_require_role_rejects_other_roles_with_403(db):
    user = add_user(db)
    with pytest.raises(HTTPException) as exc:
        require_role("admin")(user)
    assert exc.value.status_code == 403
