"""Recipient-only storage for ciphertext the client already encrypted.

S3 presigned URLs are bearer tokens, so agents never receive one. This service
authenticates each request with NIP-98, writes the object under its sha256, and
returns the bytes only to the recorded recipient.
"""

__version__ = "0.1.0"
