"""
STS AssumeRoleWithWebIdentity helper.

AWS trust policy on the IAM role must allow the Azure AD application's OIDC
issuer. Add a federated identity condition like:
  "Condition": {
    "StringEquals": {
      "sts.amazonaws.com:aud": "<AZURE_TOKEN_AUDIENCE>",
      "sts.amazonaws.com:sub": "<AZURE_APP_OBJECT_ID>"
    }
  }
"""

import os
import logging
import boto3
from azure.identity import ClientSecretCredential, ManagedIdentityCredential
from azure.core.credentials import TokenRequestOptions

logger = logging.getLogger(__name__)


def _get_azure_token(audience: str) -> str:
    """
    Obtain an Azure AD access token to use as the web identity token.

    Uses Managed Identity when AZURE_CLIENT_SECRET is absent (production),
    falls back to ClientSecretCredential for local development.
    """
    client_secret = os.environ.get("AZURE_CLIENT_SECRET")

    if client_secret:
        credential = ClientSecretCredential(
            tenant_id=os.environ["AZURE_TENANT_ID"],
            client_id=os.environ["AZURE_CLIENT_ID"],
            client_secret=client_secret,
        )
    else:
        # Managed Identity – preferred in production Azure environments
        client_id = os.environ.get("AZURE_CLIENT_ID")
        credential = ManagedIdentityCredential(client_id=client_id or None)

    token = credential.get_token(audience)
    return token.token


def assume_role() -> dict:
    """
    Call STS AssumeRoleWithWebIdentity and return the temporary credentials dict:
    {"AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"}
    """
    role_arn = os.environ["AWS_ROLE_ARN"]
    session_name = os.environ.get("AWS_ROLE_SESSION_NAME", "azure-function-session")
    duration = int(os.environ.get("AWS_SESSION_DURATION_SECONDS", "3600"))
    audience = os.environ["AZURE_TOKEN_AUDIENCE"]
    region = os.environ.get("AWS_REGION", "us-east-1")

    web_identity_token = _get_azure_token(audience)

    sts = boto3.client("sts", region_name=region)
    response = sts.assume_role_with_web_identity(
        RoleArn=role_arn,
        RoleSessionName=session_name,
        WebIdentityToken=web_identity_token,
        DurationSeconds=duration,
    )

    credentials = response["AssumedRoleUser"]
    creds = response["Credentials"]
    logger.info("Assumed role %s as session %s", role_arn, credentials["AssumedRoleId"])
    return creds
