from app.database import SessionLocal, get_db
from app.models import User
from tests.conftest import login, make_user

CREDENTIALS = {"email": "user@example.com", "password": "strongpass123"}


def _set_active(email, value):
    db = SessionLocal()
    try:
        db.query(User).filter(User.email == email).first().is_active = value
        db.commit()
    finally:
        db.close()


def test_register_is_rate_limited_after_five_requests(client):
    codes = [
        client.post("/auth/register", json={"email": f"user{i}@example.com", "password": "strongpass123"}).status_code
        for i in range(6)
    ]
    assert codes[:5] == [201] * 5
    assert codes[5] == 429


def test_rate_limit_response_uses_the_custom_json_body(client):
    body = {"email": "nobody@example.com", "password": "strongpass123"}
    for _ in range(5):
        client.post("/auth/login", json=body)
    response = client.post("/auth/login", json=body)
    assert response.status_code == 429
    assert response.json() == {"detail": "Rate limit exceeded. Try again later."}


def test_failed_logins_count_towards_the_limit(client):
    make_user(client)
    codes = [
        client.post("/auth/login", json={**CREDENTIALS, "password": "wrong-password"}).status_code
        for _ in range(6)
    ]
    assert codes[:5] == [401] * 5
    assert codes[5] == 429


def test_register_and_login_use_separate_buckets(client):
    for i in range(5):
        response = client.post("/auth/register", json={"email": f"u{i}@example.com", "password": "strongpass123"})
        assert response.status_code == 201
    assert client.post("/auth/login", json={"email": "u0@example.com", "password": "strongpass123"}).status_code == 200


def test_unrelated_routes_are_not_rate_limited(client):
    assert all(client.get("/health").status_code == 200 for _ in range(20))


def test_deactivated_account_cannot_log_in(client):
    make_user(client)
    _set_active(CREDENTIALS["email"], False)
    response = client.post("/auth/login", json=CREDENTIALS)
    assert response.status_code == 403
    assert "deactivated" in response.json()["detail"].lower()


def test_deactivated_account_with_wrong_password_gets_the_generic_401(client):
    make_user(client)
    _set_active(CREDENTIALS["email"], False)
    response = client.post("/auth/login", json={**CREDENTIALS, "password": "wrong-password"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password"


def test_reactivated_account_can_log_in_again(client):
    make_user(client)
    _set_active(CREDENTIALS["email"], False)
    _set_active(CREDENTIALS["email"], True)
    assert "access_token" in login(client)


def test_get_db_closes_the_session_when_the_request_ends():
    generator = get_db()
    session = next(generator)
    closed = []
    original_close = session.close

    def tracking_close():
        closed.append(True)
        original_close()

    session.close = tracking_close
    generator.close()
    assert closed == [True]
