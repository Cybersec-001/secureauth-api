import jwt

from app.config import settings
from app.security import (
    create_access_token,
    create_refresh_token,
    decode_access_token,
    hash_password,
    hash_token,
    verify_password,
)


def test_password_hash_verifies_and_is_salted():
    first = hash_password("correct horse battery")
    second = hash_password("correct horse battery")
    assert first != second
    assert verify_password("correct horse battery", first)
    assert not verify_password("wrong password", first)


def test_access_token_round_trip():
    payload = decode_access_token(create_access_token(7, "admin"))
    assert payload["sub"] == "7"
    assert payload["role"] == "admin"


def test_decode_rejects_garbage_and_wrong_key():
    assert decode_access_token("not-a-jwt") is None
    forged = jwt.encode({"sub": "1", "role": "admin", "type": "access"}, "other-key", algorithm=settings.ALGORITHM)
    assert decode_access_token(forged) is None


def test_decode_rejects_non_access_token_type():
    token = jwt.encode({"sub": "1", "type": "refresh"}, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    assert decode_access_token(token) is None


def test_refresh_tokens_are_unique_and_stored_hashed():
    a, expires = create_refresh_token(1)
    b, _ = create_refresh_token(1)
    assert a != b
    assert len(a) >= 48
    assert hash_token(a) == hash_token(a)
    assert hash_token(a) != a and len(hash_token(a)) == 64
    assert expires.tzinfo is not None
