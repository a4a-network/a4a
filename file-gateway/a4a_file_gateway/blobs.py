"""S3-compatible object storage. The only URL here is the configured endpoint."""
from __future__ import annotations

import os
import re

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from .config import Settings

_SHA256 = re.compile(r"[0-9a-f]{64}")


class BlobStoreError(RuntimeError):
    """Object storage did not complete the operation. The message has no URL or key."""


def _missing(exc: ClientError) -> bool:
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    code = str(exc.response.get("Error", {}).get("Code", ""))
    return status == 404 or code in {"404", "NoSuchKey", "NotFound"}


def client_for(settings: Settings):
    """Open an S3 client for ``settings`` and nothing a request can name.

    Instance-metadata credentials are disabled so a missing key cannot turn into a
    fetch of the link-local metadata address. Checksums stay off unless the
    operation requires them: several S3-compatible stores reject the default.
    """
    os.environ["AWS_EC2_METADATA_DISABLED"] = "true"
    config = Config(
        signature_version="s3v4",
        s3={"addressing_style": "path"},
        retries={"max_attempts": 2, "mode": "standard"},
        connect_timeout=3,
        read_timeout=20,
        request_checksum_calculation="when_required",
        response_checksum_validation="when_required",
    )
    session = boto3.session.Session(
        aws_access_key_id=settings.access_key,
        aws_secret_access_key=settings.secret_key,
        region_name=settings.region,
    )
    return session.client("s3", endpoint_url=settings.endpoint, config=config)


class S3BlobStore:
    def __init__(self, client, bucket: str):
        self.client = client
        self.bucket = bucket

    def _key(self, name: str) -> str:
        if not _SHA256.fullmatch(name):
            raise BlobStoreError("refusing an object name that is not a sha256 digest")
        return name

    def _fail(self, exc: Exception) -> None:
        code = "unavailable"
        if isinstance(exc, ClientError):
            code = str(exc.response.get("Error", {}).get("Code", "unavailable"))
        raise BlobStoreError(code) from exc

    def put(self, name: str, data: bytes) -> None:
        try:
            self.client.put_object(Bucket=self.bucket, Key=self._key(name), Body=data,
                                   ContentType="application/octet-stream")
        except (ClientError, BotoCoreError) as exc:
            self._fail(exc)

    def get(self, name: str) -> bytes | None:
        try:
            response = self.client.get_object(Bucket=self.bucket, Key=self._key(name))
        except ClientError as exc:
            if _missing(exc):
                return None
            self._fail(exc)
        except BotoCoreError as exc:
            self._fail(exc)
        body = response["Body"]
        try:
            return body.read()
        finally:
            body.close()

    def delete(self, name: str) -> None:
        try:
            self.client.delete_object(Bucket=self.bucket, Key=self._key(name))
        except (ClientError, BotoCoreError) as exc:
            self._fail(exc)

    def contains(self, name: str) -> bool:
        try:
            self.client.head_object(Bucket=self.bucket, Key=self._key(name))
        except ClientError as exc:
            if _missing(exc):
                return False
            self._fail(exc)
        except BotoCoreError as exc:
            self._fail(exc)
        return True
