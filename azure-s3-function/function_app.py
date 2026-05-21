"""
Azure Function – S3 file retrieval via STS AssumeRoleWithWebIdentity.

Endpoints
---------
GET /api/token-info
    Decode and return the Azure AD token claims this function generates.
    Use this to find the stable `sub` value for the AWS trust policy.

GET /api/s3/list?prefix=<optional>
    List objects in the configured S3 bucket.

GET /api/s3/download?key=<object-key>
    Download a single S3 object and return it as binary response.

GET /api/s3/presign?key=<object-key>&expires=<seconds>
    Return a pre-signed S3 URL for the given object key.
"""

import json
import logging
import azure.functions as func
import sts_client
import s3_client
import token_utils

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Token info – call this once to find the stable `sub` for the AWS trust policy
# ---------------------------------------------------------------------------

@app.route(route="token-info", methods=["GET"])
def token_info(req: func.HttpRequest) -> func.HttpResponse:
    """
    Return the decoded Azure AD token claims produced by this function.

    The `sub` field shown here is exactly what AWS STS receives as the
    web identity token subject.  For app-only tokens (token_type == "app-only")
    sub == oid, which is the Service Principal Object ID and never changes.
    Copy that value into your AWS trust policy:
        "sts.amazonaws.com:sub": "<value of sub shown here>"
    """
    try:
        _, claims = sts_client.get_azure_token()
    except Exception as exc:
        logger.exception("Failed to obtain Azure token")
        return func.HttpResponse(
            json.dumps({"error": str(exc)}),
            status_code=502,
            mimetype="application/json",
        )

    info = token_utils.stable_subject_info(claims)
    return func.HttpResponse(
        json.dumps(info, indent=2),
        status_code=200,
        mimetype="application/json",
    )


def _assume_or_error() -> tuple[dict | None, func.HttpResponse | None]:
    """Attempt STS assume-role; return (credentials, None) or (None, error_response)."""
    try:
        creds = sts_client.assume_role()
        return creds, None
    except Exception as exc:
        logger.exception("STS AssumeRoleWithWebIdentity failed")
        return None, func.HttpResponse(
            json.dumps({"error": "Failed to assume AWS role", "detail": str(exc)}),
            status_code=502,
            mimetype="application/json",
        )


# ---------------------------------------------------------------------------
# List objects
# ---------------------------------------------------------------------------

@app.route(route="s3/list", methods=["GET"])
def list_s3_objects(req: func.HttpRequest) -> func.HttpResponse:
    prefix = req.params.get("prefix", "")
    creds, err = _assume_or_error()
    if err:
        return err

    try:
        objects = s3_client.list_objects(creds, prefix=prefix)
    except Exception as exc:
        logger.exception("S3 list failed")
        return func.HttpResponse(
            json.dumps({"error": "S3 list failed", "detail": str(exc)}),
            status_code=502,
            mimetype="application/json",
        )

    return func.HttpResponse(
        json.dumps({"count": len(objects), "objects": objects}),
        status_code=200,
        mimetype="application/json",
    )


# ---------------------------------------------------------------------------
# Download object
# ---------------------------------------------------------------------------

@app.route(route="s3/download", methods=["GET"])
def download_s3_object(req: func.HttpRequest) -> func.HttpResponse:
    key = req.params.get("key", "").strip()
    if not key:
        return func.HttpResponse(
            json.dumps({"error": "Missing required query parameter: key"}),
            status_code=400,
            mimetype="application/json",
        )

    creds, err = _assume_or_error()
    if err:
        return err

    try:
        data = s3_client.get_object(creds, key)
    except FileNotFoundError:
        return func.HttpResponse(
            json.dumps({"error": f"Object not found: {key}"}),
            status_code=404,
            mimetype="application/json",
        )
    except Exception as exc:
        logger.exception("S3 download failed for key=%s", key)
        return func.HttpResponse(
            json.dumps({"error": "S3 download failed", "detail": str(exc)}),
            status_code=502,
            mimetype="application/json",
        )

    filename = key.split("/")[-1]
    return func.HttpResponse(
        body=data,
        status_code=200,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        mimetype="application/octet-stream",
    )


# ---------------------------------------------------------------------------
# Pre-signed URL
# ---------------------------------------------------------------------------

@app.route(route="s3/presign", methods=["GET"])
def presign_s3_object(req: func.HttpRequest) -> func.HttpResponse:
    key = req.params.get("key", "").strip()
    if not key:
        return func.HttpResponse(
            json.dumps({"error": "Missing required query parameter: key"}),
            status_code=400,
            mimetype="application/json",
        )

    try:
        expires_in = int(req.params.get("expires", "900"))
        if not (60 <= expires_in <= 86400):
            raise ValueError("expires must be between 60 and 86400 seconds")
    except ValueError as exc:
        return func.HttpResponse(
            json.dumps({"error": str(exc)}),
            status_code=400,
            mimetype="application/json",
        )

    creds, err = _assume_or_error()
    if err:
        return err

    try:
        url = s3_client.get_presigned_url(creds, key, expires_in=expires_in)
    except Exception as exc:
        logger.exception("S3 presign failed for key=%s", key)
        return func.HttpResponse(
            json.dumps({"error": "Pre-sign failed", "detail": str(exc)}),
            status_code=502,
            mimetype="application/json",
        )

    return func.HttpResponse(
        json.dumps({"key": key, "url": url, "expires_in_seconds": expires_in}),
        status_code=200,
        mimetype="application/json",
    )
