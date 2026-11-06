import pytest
from pydantic import ValidationError

from app.schemas import LoginRequest, RefreshRequest, RegisterRequest, RoleUpdate, TokenPair


def test_register_password_length_bounds():
    RegisterRequest(email="a@b.co", password="x" * 8)
    RegisterRequest(email="a@b.co", password="x" * 128)
    with pytest.raises(ValidationError):
        RegisterRequest(email="a@b.co", password="x" * 7)
    with pytest.raises(ValidationError):
        RegisterRequest(email="a@b.co", password="x" * 129)


def test_register_requires_a_valid_email():
    with pytest.raises(ValidationError):
        RegisterRequest(email="not-an-email", password="long-enough-password")


def test_login_password_has_no_strength_rules():
    # Strength is enforced only at registration; login must accept any shape.
    LoginRequest(email="a@b.co", password="x")


def test_role_update_accepts_only_user_or_admin():
    assert RoleUpdate(role="user").role == "user"
    assert RoleUpdate(role="admin").role == "admin"
    with pytest.raises(ValidationError):
        RoleUpdate(role="superuser")


def test_token_pair_defaults_to_bearer():
    pair = TokenPair(access_token="a", refresh_token="r")
    assert pair.token_type == "bearer"


def test_refresh_request_requires_a_token():
    with pytest.raises(ValidationError):
        RefreshRequest()
