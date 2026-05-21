import os
import pytest
from unittest.mock import MagicMock, patch
from io import BytesIO
from botocore.exceptions import ClientError

os.environ.setdefault("AWS_REGION", "us-east-1")
os.environ.setdefault("S3_BUCKET_NAME", "test-bucket")

import s3_client

FAKE_CREDS = {
    "AccessKeyId": "ASIA...",
    "SecretAccessKey": "secret",
    "SessionToken": "token",
}


def _make_client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, "GetObject")


@patch("s3_client.boto3.client")
def test_list_objects_returns_summaries(mock_boto3_client):
    from datetime import datetime, timezone

    mock_s3 = MagicMock()
    mock_boto3_client.return_value = mock_s3

    page = {
        "Contents": [
            {"Key": "a/b.txt", "Size": 42, "LastModified": datetime(2024, 1, 1, tzinfo=timezone.utc), "ETag": '"abc"'},
        ]
    }
    mock_s3.get_paginator.return_value.paginate.return_value = [page]

    result = s3_client.list_objects(FAKE_CREDS, prefix="a/")

    assert len(result) == 1
    assert result[0]["key"] == "a/b.txt"
    assert result[0]["size"] == 42
    assert result[0]["etag"] == "abc"


@patch("s3_client.boto3.client")
def test_get_object_returns_bytes(mock_boto3_client):
    mock_s3 = MagicMock()
    mock_boto3_client.return_value = mock_s3
    mock_s3.get_object.return_value = {"Body": BytesIO(b"hello world")}

    data = s3_client.get_object(FAKE_CREDS, "some/file.txt")

    assert data == b"hello world"
    mock_s3.get_object.assert_called_once_with(Bucket="test-bucket", Key="some/file.txt")


@patch("s3_client.boto3.client")
def test_get_object_raises_file_not_found_on_no_such_key(mock_boto3_client):
    mock_s3 = MagicMock()
    mock_boto3_client.return_value = mock_s3
    mock_s3.get_object.side_effect = _make_client_error("NoSuchKey")

    with pytest.raises(FileNotFoundError):
        s3_client.get_object(FAKE_CREDS, "missing.txt")


@patch("s3_client.boto3.client")
def test_get_presigned_url(mock_boto3_client):
    mock_s3 = MagicMock()
    mock_boto3_client.return_value = mock_s3
    mock_s3.generate_presigned_url.return_value = "https://s3.example.com/signed"

    url = s3_client.get_presigned_url(FAKE_CREDS, "docs/report.pdf", expires_in=300)

    assert url == "https://s3.example.com/signed"
    mock_s3.generate_presigned_url.assert_called_once_with(
        "get_object",
        Params={"Bucket": "test-bucket", "Key": "docs/report.pdf"},
        ExpiresIn=300,
    )
