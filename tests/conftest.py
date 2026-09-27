import os

# Test configuration must be set before the app modules are imported.
os.environ["DATABASE_URL"] = "sqlite:///./test.db"
os.environ["SECRET_KEY"] = "test-secret-key"

import pytest
from fastapi.testclient import TestClient

from app.database import Base, engine
from app.main import create_app
from app.ratelimit import limiter


@pytest.fixture()
def client():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    limiter.reset()  # clean rate-limit buckets between tests
    with TestClient(create_app()) as c:
        yield c
    Base.metadata.drop_all(bind=engine)


def make_user(client, email="user@example.com", password="strongpass123"):
    r = client.post("/auth/register", json={"email": email, "password": password})
    assert r.status_code == 201, r.text
    return r.json()


def login(client, email="user@example.com", password="strongpass123"):
    r = client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


def make_admin(client, email="admin@example.com"):
    """Register a user and promote it to admin directly in the database."""
    from app.database import SessionLocal
    from app.models import User

    make_user(client, email=email)
    db = SessionLocal()
    user = db.query(User).filter(User.email == email).first()
    user.role = "admin"
    db.commit()
    db.close()
