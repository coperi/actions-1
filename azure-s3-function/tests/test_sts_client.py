import os
import base64
import json
import pytest
from unittest.mock import MagicMock, patch

os.environ.setdefault("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/TestRole")
os.environ.setdefault("AWS_REGION", "us-east-1")
os.environ.setdefault("AWS_ROLE_SESSION_NAME", "test-session")
os.environ.setdefault("AZURE_TOKEN_AUDIENCE", "api://test-app")
os.environ.setdefault("AZURE_CLIENT_ID", "client-id")
os.environ.setdefault("AZURE_TENANT_ID", "tenant-id")
os.environ.setdefault("AZURE_CLIENT_SECRET", "client-secret")

import sts_client


STABLE_CLAIMS = {"sub": "sp-oid-1234", "oid": "sp-oid-1234", "aud": "api://test-app"}

FAKE_CREDS = {
    "AccessKeyId": "ASIA...",
    "SecretAccessKey": "secret",
    "SessionToken": "token",
    "Expiration": "2099-01-01T00:00:00Z",
}


def _make_jwt(payload: dict) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"RS256"}').rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{header}.{body}.fakesig"


@patch("sts_client.ClientSecretCredential")
def test_get_azure_token_uses_scope_with_default_suffix(mock_credential_cls):
    mock_token = MagicMock()
    mock_token.token = _make_jwt(STABLE_CLAIMS)
    mock_credential_cls.return_value.get_token.return_value = mock_token

    _, claims = sts_client.get_azure_token()

    call_args = mock_credential_cls.return_value.get_token.call_args
    scope_arg = call_args[0][0]
    assert scope_arg.endswith("/.default"), f"Expected /.default suffix, got: {scope_arg}"
    assert claims["sub"] == "sp-oid-1234"


@patch("sts_client.boto3.client")
@patch("sts_client.ClientSecretCredential")
def test_assume_role_returns_credentials(mock_credential_cls, mock_boto3_client):
    mock_token = MagicMock()
    mock_token.token = _make_jwt(STABLE_CLAIMS)
    mock_credential_cls.return_value.get_token.return_value = mock_token

    mock_sts = MagicMock()
    mock_sts.assume_role_with_web_identity.return_value = {
        "AssumedRoleUser": {"AssumedRoleId": "AROA:test-session"},
        "Credentials": FAKE_CREDS,
    }
    mock_boto3_client.return_value = mock_sts

    result = sts_client.assume_role()

    mock_sts.assume_role_with_web_identity.assert_called_once()
    assert result == FAKE_CREDS


@patch("sts_client.boto3.client")
@patch("sts_client.ClientSecretCredential")
def test_assume_role_propagates_sts_error(mock_credential_cls, mock_boto3_client):
    mock_token = MagicMock()
    mock_token.token = _make_jwt(STABLE_CLAIMS)
    mock_credential_cls.return_value.get_token.return_value = mock_token

    mock_sts = MagicMock()
    mock_sts.assume_role_with_web_identity.side_effect = Exception("AccessDenied")
    mock_boto3_client.return_value = mock_sts

    with pytest.raises(Exception, match="AccessDenied"):
        sts_client.assume_role()
