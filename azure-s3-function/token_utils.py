"""JWT claim inspection utilities (no signature verification – inspection only)."""

import base64
import json
import logging

logger = logging.getLogger(__name__)


def decode_claims(token: str) -> dict:
    """
    Base64url-decode the JWT payload and return the claims dict.
    Does NOT verify the signature – use only for debugging/logging.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("not a JWT (expected 3 dot-separated parts)")
        payload = parts[1]
        payload += "=" * (-len(payload) % 4)  # restore padding
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception as exc:
        logger.warning("JWT decode failed: %s", exc)
        return {}


def stable_subject_info(claims: dict) -> dict:
    """
    Return the subset of claims needed to configure the AWS IAM trust policy.

    For app-only tokens (client credentials / Managed Identity):
      sub == oid  →  token_type = "app-only"  →  sub is stable, use it.

    For user-delegated tokens (browser / Azure CLI as a user):
      sub != oid  →  token_type = "delegated"  →  sub changes per user,
      do NOT use it in the AWS trust policy.

    AWS trust policy conditions map:
      sts.amazonaws.com:aud  →  aud  (e.g. "api://<client-id>")
      sts.amazonaws.com:sub  →  sub  (Service Principal Object ID for app-only tokens)
    """
    sub = claims.get("sub")
    oid = claims.get("oid")
    return {
        "sub": sub,
        "oid": oid,
        "aud": claims.get("aud"),
        "iss": claims.get("iss"),
        "appid": claims.get("appid"),   # v1.0 claim – app registration client ID
        "azp": claims.get("azp"),       # v2.0 claim – same as appid
        "tid": claims.get("tid"),
        "token_type": "app-only" if sub and sub == oid else "delegated",
        "aws_trust_policy_note": (
            "sub is stable – use it in sts.amazonaws.com:sub condition"
            if sub == oid
            else "sub is user-specific – switch to ClientSecretCredential or ManagedIdentityCredential"
        ),
    }
