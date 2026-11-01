"""Tests for the admin-only /users endpoints (list and role updates)."""
from tests.conftest import login, make_admin, make_user


def _auth(tokens):
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def _admin_auth(client):
    return _auth(login(client, email="admin@example.com"))


def test_admin_lists_users(client):
    make_admin(client)
    make_user(client, email="second@example.com")
    r = client.get("/users", headers=_admin_auth(client))
    assert r.status_code == 200
    emails = [u["email"] for u in r.json()]
    assert emails == ["admin@example.com", "second@example.com"]
    assert all(set(u) == {"id", "email", "role", "is_active"} for u in r.json())


def test_list_users_forbidden_for_non_admin(client):
    make_user(client)
    r = client.get("/users", headers=_auth(login(client)))
    assert r.status_code == 403


def test_list_users_requires_auth(client):
    make_admin(client)
    assert client.get("/users").status_code == 401


def test_update_role_unknown_user_404(client):
    make_admin(client)
    r = client.patch("/users/9999/role", json={"role": "admin"},
                     headers=_admin_auth(client))
    assert r.status_code == 404


def test_update_role_rejects_invalid_role(client):
    make_admin(client)
    target = make_user(client, email="second@example.com")
    r = client.patch(f"/users/{target['id']}/role", json={"role": "superuser"},
                     headers=_admin_auth(client))
    assert r.status_code == 422


def test_promote_to_admin_grants_access(client):
    make_admin(client)
    target = make_user(client, email="second@example.com")
    r = client.patch(f"/users/{target['id']}/role", json={"role": "admin"},
                     headers=_admin_auth(client))
    assert r.status_code == 200
    assert r.json()["role"] == "admin"
    promoted = login(client, email="second@example.com")
    assert client.get("/users", headers=_auth(promoted)).status_code == 200
