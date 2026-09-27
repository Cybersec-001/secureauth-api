from tests.conftest import login, make_admin, make_user


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_register_and_login(client):
    make_user(client)
    tokens = login(client)
    assert tokens["token_type"] == "bearer"
    assert tokens["access_token"] and tokens["refresh_token"]


def test_register_rejects_duplicate_email(client):
    make_user(client)
    r = client.post("/auth/register", json={"email": "user@example.com", "password": "whatever123"})
    assert r.status_code == 409


def test_register_rejects_short_password(client):
    r = client.post("/auth/register", json={"email": "short@example.com", "password": "tiny"})
    assert r.status_code == 422


def test_login_rejects_wrong_password(client):
    make_user(client)
    r = client.post("/auth/login", json={"email": "user@example.com", "password": "wrongpass999"})
    assert r.status_code == 401


def test_me_requires_token(client):
    assert client.get("/auth/me").status_code == 401


def test_me_returns_current_user(client):
    make_user(client)
    tokens = login(client)
    r = client.get("/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert r.status_code == 200
    assert r.json()["email"] == "user@example.com"
    assert r.json()["role"] == "user"


def test_refresh_rotates_tokens(client):
    make_user(client)
    tokens = login(client)
    r = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 200
    new_tokens = r.json()
    assert new_tokens["refresh_token"] != tokens["refresh_token"]
    # the rotated-out token can never be used again
    r = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 401


def test_logout_revokes_refresh_token(client):
    make_user(client)
    tokens = login(client)
    assert client.post("/auth/logout", json={"refresh_token": tokens["refresh_token"]}).status_code == 200
    assert client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 401


def test_user_cannot_access_admin_routes(client):
    make_user(client)
    tokens = login(client)
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    assert client.get("/users", headers=headers).status_code == 403


def test_admin_can_list_users_and_change_roles(client):
    make_admin(client)
    make_user(client, email="member@example.com")
    tokens = login(client, email="admin@example.com")
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    users = client.get("/users", headers=headers).json()
    assert len(users) == 2
    member_id = next(u["id"] for u in users if u["email"] == "member@example.com")

    r = client.patch(f"/users/{member_id}/role", json={"role": "admin"}, headers=headers)
    assert r.status_code == 200
    assert r.json()["role"] == "admin"


def test_login_rate_limited(client):
    make_user(client)
    codes = [
        client.post("/auth/login", json={"email": "user@example.com", "password": "strongpass123"}).status_code
        for _ in range(6)
    ]
    assert codes[:5] == [200] * 5
    assert codes[5] == 429
