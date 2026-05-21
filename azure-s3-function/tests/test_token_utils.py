import base64
import json
import pytest
import token_utils


def _make_jwt(payload: dict) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"RS256"}').rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{header}.{body}.fakesig"


APP_ONLY_CLAIMS = {
    "sub": "aaaa-1111",
    "oid": "aaaa-1111",   # sub == oid → app-only
    "aud": "api://my-app",
    "iss": "https://sts.windows.net/tenant-id/",
    "appid": "client-id",
    "azp": "client-id",
    "tid": "tenant-id",
}

DELEGATED_CLAIMS = {
    "sub": "xxxx-pairwise-hash",
    "oid": "user-oid-9999",   # sub != oid → delegated
    "aud": "api://my-app",
    "iss": "https://sts.windows.net/tenant-id/",
    "tid": "tenant-id",
}


def test_decode_claims_roundtrip():
    jwt = _make_jwt(APP_ONLY_CLAIMS)
    claims = token_utils.decode_claims(jwt)
    assert claims["sub"] == "aaaa-1111"
    assert claims["aud"] == "api://my-app"


def test_decode_claims_invalid_returns_empty():
    assert token_utils.decode_claims("not.a.jwt.with.extra") == {}
    assert token_utils.decode_claims("bad") == {}


def test_stable_subject_info_app_only():
    info = token_utils.stable_subject_info(APP_ONLY_CLAIMS)
    assert info["token_type"] == "app-only"
    assert "stable" in info["aws_trust_policy_note"]
    assert info["sub"] == info["oid"]


def test_stable_subject_info_delegated():
    info = token_utils.stable_subject_info(DELEGATED_CLAIMS)
    assert info["token_type"] == "delegated"
    assert "ClientSecretCredential" in info["aws_trust_policy_note"]


def test_build_scope_appends_default():
    assert token_utils  # module importable
    import sts_client
    assert sts_client._build_scope("api://my-app") == "api://my-app/.default"
    assert sts_client._build_scope("api://my-app/.default") == "api://my-app/.default"
