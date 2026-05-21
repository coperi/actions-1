import os
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


FAKE_CREDS = {
    "AccessKeyId": "ASIA...",
    "SecretAccessKey": "secret",
    "SessionToken": "token",
    "Expiration": "2099-01-01T00:00:00Z",
}


@patch("sts_client.boto3.client")
@patch("sts_client.ClientSecretCredential")
def test_assume_role_returns_credentials(mock_credential_cls, mock_boto3_client):
    mock_token = MagicMock()
    mock_token.token = "azure-jwt"
    mock_credential_cls.return_value.get_token.return_value = mock_token

    mock_sts = MagicMock()
    mock_sts.assume_role_with_web_identity.return_value = {
        "AssumedRoleUser": {"AssumedRoleId": "AROA:test-session"},
        "Credentials": FAKE_CREDS,
    }
    mock_boto3_client.return_value = mock_sts

    result = sts_client.assume_role()

    mock_sts.assume_role_with_web_identity.assert_called_once_with(
        RoleArn="arn:aws:iam::123456789012:role/TestRole",
        RoleSessionName="test-session",
        WebIdentityToken="azure-jwt",
        DurationSeconds=3600,
    )
    assert result == FAKE_CREDS


@patch("sts_client.boto3.client")
@patch("sts_client.ClientSecretCredential")
def test_assume_role_propagates_sts_error(mock_credential_cls, mock_boto3_client):
    mock_token = MagicMock()
    mock_token.token = "azure-jwt"
    mock_credential_cls.return_value.get_token.return_value = mock_token

    mock_sts = MagicMock()
    mock_sts.assume_role_with_web_identity.side_effect = Exception("AccessDenied")
    mock_boto3_client.return_value = mock_sts

    with pytest.raises(Exception, match="AccessDenied"):
        sts_client.assume_role()
