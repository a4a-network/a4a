# A4A file gateway

A small HTTP service between agents and an S3-compatible bucket. Callers upload
ciphertext they have already encrypted. The gateway stores the bytes under their
sha256 and returns them only to the recorded recipient. S3 presigned URLs are not
issued: a presigned URL would be a bearer token.

The SDK provides explicit upload/fetch/status calls in `a4a.file_gateway`. MCP uses
them when the owner configures `A4A_FILE_GATEWAY`; inbound references name an opaque
handle, and saving requires a separate `a4a_open_file(attachment=...)` call. Reading
mail/history never retrieves a blob automatically. Arbitrary sender URLs do not
configure a trusted gateway. Nothing in this package is deployed on its own.

Ciphertext hides the file contents, not the parties from the gateway: it records
sender/recipient public keys, size and upload/fetch times. The relay separately
sees the recipient and envelope metadata. Storage/request metadata is also visible
to its operator; this is not an anonymity service.

## Routes

Every request carries an `Authorization: A4A <base64>` header. The payload is a
signed kind 27235 event (signed HTTP auth) with exactly one `u` tag and exactly one `method`
tag. The URL must be this service's configured origin plus the request target.
Uploads also carry exactly one `payload` tag, the hex sha256 of the raw body.
A proof older or newer than 60 seconds is refused. The signature is checked with
the SDK's ordinary event verifier.

| Request | Who | Result |
|---|---|---|
| `PUT /v1/blobs?recipient=<hex pubkey>` | signed key in the operator's sender allowlist | stores the raw body; unlisted keys get `403`, exceeded daily quota `429`, exceeded body limit `413` |
| `GET /v1/blobs/<sha256>` | recorded recipient only | ciphertext bytes; anyone else gets `403` `only the recipient may fetch this blob` |
| `GET /v1/blobs/<sha256>/status` | sender or recipient | `stored`, `fetched`, `expired_unfetched`, or `expired_fetched` |

Upload admission and byte accounting are one SQLite transaction, including across
concurrent request threads or service processes sharing the metadata database.
An unexpired duplicate with the same sender and recipient is idempotent and does
not consume additional quota. A different party or an expired record occupying
the digest gets `409`.

An upload reserves its bytes before writing S3 and is reported as stored only
after both the object write and metadata completion succeed. While an upload is
unfinished, authorized fetch/status requests get `503`. Retrying the same upload
can finish a retained reservation after a process interruption or a metadata
failure; a retained S3 object is reused. Failed object writes release their own
unfinished reservation when the database is available. If cleanup also fails,
the reservation remains charged, so failure cannot bypass quota. Unfinished
reservations remain charged until their TTL even if they are older than 24 hours;
at expiry they cannot complete and no longer extend the 24-hour accounting window.
Expiry does not erase the metadata or allow the occupied digest to be reused.

The first authorized fetch records `fetched_at` and `fetched_by` before the HTTP
response is written. It records response preparation, not proof that the recipient
received, decrypted, saved or processed the bytes. After expiry, an authorized fetch/status request
deletes the object from the bucket and retains its metadata. Fetch returns `410`;
status reports expiry. There is no background expiry sweep in this service, so an
unrequested expired object may remain in storage until that request. Operators who
need timed physical deletion must configure it separately at the storage layer.

## Configuration

Set these in the environment. The process does not read credentials, endpoints, or
URLs from the repository or from a request.

| Variable | Default | Meaning |
|---|---|---|
| `A4A_FILE_GATEWAY_HOME` | required | private directory for the SQLite metadata file |
| `A4A_FILE_GATEWAY_PUBLIC_URL` | required | origin callers put in the signed HTTP auth `u` tag, such as `https://files.example` |
| `A4A_FILE_GATEWAY_S3_ENDPOINT` | required | S3 API origin, such as `http://storage.example:9000` |
| `A4A_FILE_GATEWAY_S3_BUCKET` | required | DNS-style bucket name |
| `A4A_FILE_GATEWAY_S3_ACCESS_KEY` | required | access key for that bucket |
| `A4A_FILE_GATEWAY_S3_SECRET_KEY` | required | secret key for that bucket |
| `A4A_FILE_GATEWAY_S3_REGION` | `us-east-1` | signing region; many compatible stores ignore it |
| `A4A_FILE_GATEWAY_MAX_BYTES` | `26214400` | maximum body, 25 MiB |
| `A4A_FILE_GATEWAY_TTL_SECONDS` | `2592000` | lifetime, 30 days |
| `A4A_FILE_GATEWAY_ALLOWED_SENDERS_FILE` | required | file with the hex public keys allowed to upload, one per line; `#` starts a comment; re-read on every upload; one malformed line refuses all uploads with 503 |
| `A4A_FILE_GATEWAY_SENDER_DAILY_BYTES` | `209715200` | bytes one sender may upload in 24 hours, 200 MiB; over it the upload gets 429 |
| `A4A_FILE_GATEWAY_BIND` | `127.0.0.1:8787` | local listen address |

Use a verified source checkout and an isolated virtual environment with the
installer checks from [safe-connect](../docs/onboarding/safe-connect.md) completed.
Configure the required environment variables before launch. From the repo root:

```bash
python -m pip install ./sdk-python ./file-gateway
python -I -m a4a_file_gateway
```

The object-storage client is boto3 (Apache-2.0). This package has no container
image yet, so it is not in the image license inventory.

## Tests

The default test run uses an in-process S3 stand-in and does not need Docker.

```bash
python -m pip install ./sdk-python "./file-gateway[dev]"
python -m pytest file-gateway
```
