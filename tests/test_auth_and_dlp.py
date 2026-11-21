import datetime
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from src.models import DOCUMENT_STORE, User
from src.output_guard import OutputGuard
from src.policy_engine import PolicyEngine
from tests.test_policy_gates import InMemoryTracker, LocalPolicyEvaluator
from src.watermark_decoder import decode_watermark

# ==========================================
# OUTPUT DLP & WATERMARKING TESTS
# ==========================================

def test_output_dlp_redacts_gps_coordinates():
    guard = OutputGuard()
    raw = "Base Alpha is located at 34.0522 N, 118.2437 W. Perimeter fence is 4m high."
    sanitized, was_redacted = guard.sanitize_document("Base Alpha location", raw)

    assert was_redacted is True
    assert "34.0522 N" not in sanitized
    assert "[REDACTED]" in sanitized

def test_forensic_watermark_roundtrip():
    engine = PolicyEngine(tracker=InMemoryTracker(), opa=LocalPolicyEvaluator())
    user = User("CTR-8821", "contractor", 2, {"FACILITY_ALPHA"})
    doc = DOCUMENT_STORE["DOC-101"]

    approved, _ = engine.gate_2_post_retrieval(user, [doc])
    watermarked_text = approved[0].raw_content

    assert doc.raw_content in watermarked_text
    assert decode_watermark(watermarked_text) == "CTR-8821"

# ==========================================
# ASYMMETRIC JWT / OIDC AUTH TESTS
# ==========================================

@pytest.fixture
def jwt_test_env(tmp_path, monkeypatch):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    pub_file = tmp_path / "idp_public.pem"
    pub_file.write_bytes(pub_pem)

    monkeypatch.setenv("JWT_PUBLIC_KEY_PATH", str(pub_file))
    monkeypatch.setenv("JWT_ISSUER", "https://defense.internal")
    monkeypatch.setenv("JWT_AUDIENCE", "defense-llm-proxy")

    from src.auth import JWTAuthenticator
    return JWTAuthenticator(), priv_pem

def test_jwt_accepts_valid_signed_token(jwt_test_env):
    auth, priv_pem = jwt_test_env
    now = datetime.datetime.now(datetime.timezone.utc)

    token = jwt.encode(
        {
            "sub": "CTR-8821",
            "role": "contractor",
            "clearance": 2,
            "compartments": ["FACILITY_ALPHA"],
            "iss": "https://defense.internal",
            "aud": "defense-llm-proxy",
            "iat": now,
            "exp": now + datetime.timedelta(minutes=10),
        },
        priv_pem,
        algorithm="RS256",
    )

    user = auth.verify_token(token)
    assert user.user_id == "CTR-8821"
    assert user.clearance == 2
    assert "FACILITY_ALPHA" in user.compartments

def test_jwt_rejects_expired_token(jwt_test_env):
    auth, priv_pem = jwt_test_env
    now = datetime.datetime.now(datetime.timezone.utc)

    expired_token = jwt.encode(
        {
            "sub": "CTR-8821",
            "clearance": 2,
            "compartments": ["FACILITY_ALPHA"],
            "iss": "https://defense.internal",
            "aud": "defense-llm-proxy",
            "iat": now - datetime.timedelta(hours=2),
            "exp": now - datetime.timedelta(hours=1),
        },
        priv_pem,
        algorithm="RS256",
    )

    with pytest.raises(HTTPException) as exc:
        auth.verify_token(expired_token)
    assert exc.value.status_code == 401

def test_jwt_rejects_forged_signature(jwt_test_env):
    auth, _ = jwt_test_env
    now = datetime.datetime.now(datetime.timezone.utc)
    rogue_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    forged_token = jwt.encode(
        {
            "sub": "MIL-9001",
            "clearance": 3,
            "compartments": ["WEAPON_VALKYRIE"],
            "iss": "https://defense.internal",
            "aud": "defense-llm-proxy",
            "iat": now,
            "exp": now + datetime.timedelta(minutes=10),
        },
        rogue_key,
        algorithm="RS256",
    )

    with pytest.raises(HTTPException) as exc:
        auth.verify_token(forged_token)
    assert exc.value.status_code == 401
