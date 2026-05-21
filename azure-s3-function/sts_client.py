"""
STS AssumeRoleWithWebIdentity helper.

--- Stable subject claim ---
Azure AD's `sub` claim is only stable when the token is obtained via a
client-credentials (app-only) flow or Managed Identity.  User-delegated
tokens produce a pairwise pseudonymous `sub` that is different for every
user account, which is why a manually-obtained token has a different sub
than the one the function produces.

For app-only tokens: sub == oid (Service Principal Object ID). That value
never changes for a given app registration / Managed Identity.  Use it in
the AWS trust policy condition:
    "sts.amazonaws.com:sub": "<Service Principal Object ID>"

Call GET /api/token-info to read the exact claims this function generates.

--- Scope vs audience ---
`get_token()` accepts an OAuth2 *scope*, which must end with "/.default"
for app-only tokens.  The JWT `aud` (what AWS checks) is the resource URI
*without* the "/.default" suffix.

Set AZURE_TOKEN_AUDIENCE to the resource URI, e.g. "api://<client-id>".
The code appends "/.default" automatically when requesting the token.

--- AWS trust policy template ---
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/sts.windows.net/<TENANT_ID>/" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "sts.amazonaws.com:aud": "api://<APP_CLIENT_ID>",
        "sts.amazonaws.com:sub": "<SERVICE_PRINCIPAL_OBJECT_ID>"
      }
    }
  }]
}
"""

import os
import logging
import boto3
from azure.identity import ClientSecretCredential, ManagedIdentityCredential
import token_utils

logger = logging.getLogger(__name__)


def _build_scope(audience: str) -> str:
    """Append /.default if absent – required for app-only (client-credentials) tokens."""
    return audience if audience.endswith("/.default") else f"{audience}/.default"


def get_azure_token() -> tuple[str, dict]:
    """
    Obtain an Azure AD app-only access token.

    Returns (raw_jwt, decoded_claims).

    Production: attach a User-Assigned Managed Identity to the Function App
    and set AZURE_CLIENT_ID to its client ID; omit AZURE_CLIENT_SECRET.

    Development: set AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_CLIENT_SECRET
    for a ClientSecretCredential (client-credentials flow).
    """
    audience = os.environ["AZURE_TOKEN_AUDIENCE"]
    scope = _build_scope(audience)
    client_secret = os.environ.get("AZURE_CLIENT_SECRET")

    if client_secret:
        credential = ClientSecretCredential(
            tenant_id=os.environ["AZURE_TENANT_ID"],
            client_id=os.environ["AZURE_CLIENT_ID"],
            client_secret=client_secret,
        )
    else:
        client_id = os.environ.get("AZURE_CLIENT_ID")
        credential = ManagedIdentityCredential(client_id=client_id or None)

    raw_token = credential.get_token(scope).token
    claims = token_utils.decode_claims(raw_token)
    info = token_utils.stable_subject_info(claims)

    logger.info(
        "Azure token obtained: type=%s sub=%s oid=%s aud=%s",
        info["token_type"], info["sub"], info["oid"], info["aud"],
    )
    if info["token_type"] == "delegated":
        logger.warning(
            "Token is user-delegated – sub will differ per user and will not "
            "match an app-only AWS trust policy condition. "
            "Use ClientSecretCredential or ManagedIdentityCredential instead."
        )

    return raw_token, claims


def assume_role() -> dict:
    """
    Exchange the Azure AD token for temporary AWS credentials via STS.
    Returns {"AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"}.
    """
    role_arn = os.environ["AWS_ROLE_ARN"]
    session_name = os.environ.get("AWS_ROLE_SESSION_NAME", "azure-function-session")
    duration = int(os.environ.get("AWS_SESSION_DURATION_SECONDS", "3600"))
    region = os.environ.get("AWS_REGION", "us-east-1")

    web_identity_token, _ = get_azure_token()

    sts = boto3.client("sts", region_name=region)
    response = sts.assume_role_with_web_identity(
        RoleArn=role_arn,
        RoleSessionName=session_name,
        WebIdentityToken=web_identity_token,
        DurationSeconds=duration,
    )

    assumed_role_id = response["AssumedRoleUser"]["AssumedRoleId"]
    creds = response["Credentials"]
    logger.info("Assumed role %s as session %s, expires %s",
                role_arn, assumed_role_id, creds["Expiration"])
    return creds
