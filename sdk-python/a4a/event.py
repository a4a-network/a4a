"""A4A signed event structure, the base envelope for every A4A record."""
import re
import time

from pydantic import BaseModel, Field, field_validator

from . import crypto
from .keys import Keys

_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX128 = re.compile(r"[0-9a-f]{128}")
#: Up to 19 digits, fitting u64 like the relay. No leading zero: "045000" used to
#: parse as 45000 and yield the same agreement digest as "45000", while rule 7 §1.1
#: hashes the tag string exactly. Two spellings would therefore produce different
#: digests across implementations (2026-09-04 rule probe). Relay function
#: `parse_canonical_u64` uses this same grammar.
_UINT = re.compile(r"0|[1-9][0-9]{0,18}")


#: Canonical decimal: integer part plus optional dot and fractional part. No sign,
#: exponent, underscores, or whitespace. Python `float()` accepts all of those
#: ("+0.5", "5e-1", "0.5_0", " .5"), making a trust weight readable here but not in
#: a strict implementation (2026-09-04 wire probe). No leading zero is allowed.
#: Unlike integer tags, the normative decimal grammar has no digit limit.
_DECIMAL = re.compile(r"(0|[1-9][0-9]*)(\.[0-9]+)?")

# Native A4A kinds interpret these tag names under the protocol's numeric grammar.
# Other Nostr kinds retain their own tag semantics, except NIP-40 expiration.
_A4A_KINDS = frozenset({*range(31000, 31008), 31010, 31020, 31021, 31022,
                        *range(31030, 31035), 31985})
_UINT_TAGS = frozenset({"price", "deadline", "budget_min", "budget_max", "eta",
                        "rating", "progress", "amount", "since", "expiration"})


def parse_decimal(raw: str | None) -> float | None:
    """Parse a non-negative network decimal only in canonical form, else None."""
    if raw is None or not _DECIMAL.fullmatch(raw):
        return None
    return float(raw)


def format_decimal(value: float) -> str:
    """Format a canonical tag decimal without exponent notation.

    `str(1e-05)` produces "1e-05", which `parse_decimal` and any strict implementation
    reject, so exponential notation is expanded.
    """
    text = repr(float(value))
    if "e" in text or "E" in text:
        from decimal import Decimal
        text = format(Decimal(text), "f")
    return text


def parse_uint(raw: str | None) -> int | None:
    """Parse a network integer only in canonical decimal form, else None.

    Python `int()` accepts underscores ("1_0"), surrounding whitespace, a leading
    plus, and non-ASCII digits. These owner-signed fields do not create a direct attack,
    but another implementation parses them differently, making one event valid here
    and invalid there: a future protocol-consensus split (2026-08-29 audit, F17).

    Different does not mean stricter. Rust `str::parse::<u64>` ACCEPTS a leading plus.
    A 2026-09-04 wire probe produced a delegation with expiration "+N" that the relay
    treated as active while this function rejected it. The relay was aligned that day
    through `parse_canonical_u64`: this exact expression is canonical for every reader.
    """
    if raw is None or not _UINT.fullmatch(raw):
        return None
    return int(raw)


def is_canonical_pubkey(value: str) -> bool:
    """Return whether value is exactly 64 lowercase hexadecimal characters.

    Without this, one key has infinitely many valid strings because bytes.fromhex
    silently ignores whitespace. "e4bc…", "e4 bc…", and "e4\tbc…" are one key during
    SIGNATURE VERIFICATION but different identities for comparisons and dictionary
    keys. An event with a whitespace pubkey passed verify() because its id covered that
    same string. This bypassed both one-author-one-vote reputation deduplication and
    self-issued attestation rejection (2026-08-29 internal audit, F7).
    """
    return bool(_HEX64.fullmatch(value))


class Event(BaseModel):
    id: str = ""
    pubkey: str = ""
    created_at: int = Field(default_factory=lambda: int(time.time()),
                            strict=True, ge=0, le=(1 << 64) - 1)
    kind: int = Field(strict=True, ge=0, le=(1 << 64) - 1)
    tags: list[list[str]] = Field(default_factory=list)
    content: str = ""
    sig: str = ""

    # Enforce canonical form HERE during parsing, not at every comparison. This is the
    # sole entry point for network events into the SDK (relay._parse_event and
    # giftwrap.unwrap). Both callers catch parse errors and discard the event, so one
    # malformed relay event breaks nothing; it simply does not exist to the SDK.
    @field_validator("id")
    @classmethod
    def _check_id(cls, v: str) -> str:
        if v and not _HEX64.fullmatch(v):
            raise ValueError("event id must be exactly 64 lowercase hexadecimal characters")
        return v

    @field_validator("pubkey")
    @classmethod
    def _check_pubkey(cls, v: str) -> str:
        if v and not is_canonical_pubkey(v):
            raise ValueError("pubkey must be exactly 64 lowercase hexadecimal characters")
        return v

    @field_validator("sig")
    @classmethod
    def _check_sig(cls, v: str) -> str:
        if v and not _HEX128.fullmatch(v):
            raise ValueError("signature must be exactly 128 lowercase hexadecimal characters")
        return v

    def _validate_wire_fields(self) -> None:
        """Require the relay's unsigned integers and Unicode scalar strings.

        Recheck before signing or verification because assignment and model_copy
        can bypass Pydantic's construction-time validation.
        """
        if any(type(value) is not int or not 0 <= value < (1 << 64)
               for value in (self.created_at, self.kind)):
            raise ValueError("event timestamps and kinds must be unsigned 64-bit integers")
        if not isinstance(self.tags, list) or any(not isinstance(tag, list) for tag in self.tags):
            raise ValueError("event tags must be lists of strings")
        values = [self.id, self.pubkey, self.sig, self.content]
        values.extend(value for tag in self.tags for value in tag)
        if any(not isinstance(value, str) for value in values):
            raise ValueError("event text fields and tag elements must be strings")
        try:
            for value in values:
                value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("event strings must contain valid Unicode scalar values") from exc

    def sign(self, keys: Keys) -> "Event":
        """Set pubkey, compute id, sign the event, and return self."""
        self._validate_wire_fields()
        self.pubkey = keys.pubkey_hex
        self.id = crypto.compute_event_id(
            self.pubkey, self.created_at, self.kind, self.tags, self.content)
        self.sig = crypto.sign(self.id, keys.privkey_hex)
        return self

    def verify(self) -> bool:
        """Recompute the event id and verify its signature."""
        try:
            self._validate_wire_fields()
        except (ValueError, TypeError):
            return False
        expected = crypto.compute_event_id(
            self.pubkey, self.created_at, self.kind, self.tags, self.content)
        return self.id == expected and crypto.verify(self.id, self.sig, self.pubkey)

    def tag_value(self, name: str) -> str | None:
        for tag in self.tags:
            if len(tag) >= 2 and tag[0] == name:
                return tag[1]
        return None

    def validate_numeric_tags(self) -> None:
        """Reject the whole event if any value-bearing numeric tag is noncanonical.

        Validate every occurrence, including unused fields and duplicates. Reading
        only the first value lets a signed event disagree with strict clients.
        Bare tags retain NIP-01 semantics; required fields are checked by models.
        """
        for tag in self.tags:
            if len(tag) < 2:
                continue
            name, raw = tag[:2]
            if name == "expiration" or (self.kind in _A4A_KINDS and name in _UINT_TAGS):
                if parse_uint(raw) is None:
                    raise ValueError(f"tag {name}: every value must be a canonical unsigned integer")
            elif self.kind in _A4A_KINDS and name == "weight":
                if parse_decimal(raw) is None:
                    raise ValueError("tag weight: every value must be a canonical decimal")

    def verify_protocol(self) -> bool:
        """Check signature and whole-event numeric syntax at protocol boundaries."""
        if not self.verify():
            return False
        try:
            self.validate_numeric_tags()
        except (ValueError, TypeError):
            return False
        return True

    def delegation_ref(self) -> str | None:
        """Return a referenced delegation id ONLY from ["delegation", id].

        Do not use `tag_value("delegation")`: it accepts tag[1] from any tag with at
        least two elements, while relay/src/event.rs recognizes only an exact two-item
        tag. The relay treated ["delegation", id, "garbage"] as undelegated and skipped
        validation, while the SDK treated it as delegated and checked the chain. Relay
        verdicts then no longer described client behavior. Both sides must accept one
        exact form, which also avoids confusion with NIP-26's four-item delegation tag.
        """
        for tag in self.tags:
            if len(tag) == 2 and tag[0] == "delegation":
                return tag[1]
        return None

    def tag_values(self, name: str) -> list[str]:
        return [tag[1] for tag in self.tags if len(tag) >= 2 and tag[0] == name]

    def expiration(self) -> int | None:
        """Return the earliest NIP-40 deadline; reject any noncanonical value.

        No value-bearing expiration tag means no deadline. An invalid value is
        distinct from absence, so callers cannot accidentally make it indefinite.
        """
        values = [parse_uint(raw) for raw in self.tag_values("expiration")]
        if any(value is None for value in values):
            raise ValueError("every expiration must be a canonical unsigned integer")
        return min(values) if values else None
