"""S3 operations using temporary STS credentials."""

import os
import logging
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def _build_s3_client(credentials: dict):
    region = os.environ.get("AWS_REGION", "us-east-1")
    return boto3.client(
        "s3",
        region_name=region,
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


def list_objects(credentials: dict, prefix: str = "") -> list[dict]:
    """Return a list of object summaries under *prefix* in the configured bucket."""
    bucket = os.environ["S3_BUCKET_NAME"]
    s3 = _build_s3_client(credentials)

    paginator = s3.get_paginator("list_objects_v2")
    pages = paginator.paginate(Bucket=bucket, Prefix=prefix)

    objects = []
    for page in pages:
        for obj in page.get("Contents", []):
            objects.append(
                {
                    "key": obj["Key"],
                    "size": obj["Size"],
                    "last_modified": obj["LastModified"].isoformat(),
                    "etag": obj["ETag"].strip('"'),
                }
            )

    logger.info("Listed %d objects from s3://%s/%s", len(objects), bucket, prefix)
    return objects


def get_object(credentials: dict, key: str) -> bytes:
    """Download and return the raw bytes of a single S3 object."""
    bucket = os.environ["S3_BUCKET_NAME"]
    s3 = _build_s3_client(credentials)

    try:
        response = s3.get_object(Bucket=bucket, Key=key)
        body = response["Body"].read()
        logger.info("Downloaded s3://%s/%s (%d bytes)", bucket, key, len(body))
        return body
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        if error_code == "NoSuchKey":
            raise FileNotFoundError(f"Object not found: s3://{bucket}/{key}") from exc
        raise


def get_presigned_url(credentials: dict, key: str, expires_in: int = 900) -> str:
    """Generate a pre-signed GET URL valid for *expires_in* seconds (default 15 min)."""
    bucket = os.environ["S3_BUCKET_NAME"]
    s3 = _build_s3_client(credentials)
    url = s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket, "Key": key},
        ExpiresIn=expires_in,
    )
    return url
