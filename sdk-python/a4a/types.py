"""A4A protocol event models: 18 native kinds (31000–31985) plus reused
standard Nostr kinds. See docs/spec/a4a-protocol-v0.4.md for the full registry."""
import hashlib
import time
import json
import uuid

from pydantic import BaseModel, Field, field_validator, model_validator

from . import crypto
from .event import Event, format_decimal, parse_decimal, parse_uint

# A delegation is addressable (30000–39999) under d=<delegate pubkey>.
# It is NOT in the 10000–19999 replaceable range: that would (a) collide with the
# NIP-51 Pin list and (b) make the relay retain only one delegation per owner, so
# issuing one to a second agent would overwrite the first. With d=<delegate>, an
# owner has an independent delegation for every agent. See the v0.3 hardening plan, P0.
KIND_DELEGATION = 31000
# NIP-65 relay list (a standard replaceable Nostr kind): an agent advertises its
# relays so senders know where to deliver (v0.3 plan, P3). Tags are ["r", url]
# or ["r", url, "read"|"write"].
KIND_RELAY_LIST = 10002
KIND_AGENT_PROFILE = 31001
KIND_INTENT = 31002
KIND_OFFER = 31003
KIND_AGREEMENT = 31004
KIND_REVIEW = 31005
KIND_INVOICE = 31006
# Owner-issued delegation revocation (v0.3 plan, P4). Addressable under
# d=<delegation id>: one revocation per delegation. Signed by the owner (the
# delegation pubkey), with tag ["e", <delegation id>]. This combines short-lived
# delegations with immediate revocation.
KIND_DELEGATION_REVOCATION = 31007
KIND_SEARCH_INTENT = 31010
KIND_TRUST_ASSERTION = 31020
# Identity attestation (design §2.1): an issuer/verifier signs the claim that the
# subject key belongs to a verified identity at a given level. Addressable under
# d=<subject>: one attestation per (issuer, subject) pair. Selective disclosure
# includes only the minimum agreed fields (level and optional name), not a passport.
KIND_IDENTITY_ATTESTATION = 31021
# Connection request (design §2.4): a lightweight invitation plus an intro,
# sent BEFORE expensive conversation (each agent turn costs its owner). Mutual
# requests (A→B and B→A) establish a connection. Addressable under d=<recipient>.
# This is both an anti-spam and cost-control boundary.
KIND_CONNECTION_REQUEST = 31022
KIND_TASK_REQUEST = 31030
KIND_TASK_STATUS = 31031
KIND_TASK_RESULT = 31032
# A NIP-44-encrypted direct message between agents (content = base64 payload);
# the recipient is tag ["p", <pubkey>]. The relay can see who contacted whom;
# see the privacy warning in the a4a.nip44 module docstring.
KIND_PRIVATE_MESSAGE = 31033
# An inner event (a "rumor") for gift wrap (NIP-17/59): plaintext signed by the
# sender that exists ONLY inside the encrypted envelope (see a4a.giftwrap).
# It is published openly only when revealed as evidence in a dispute.
KIND_PRIVATE_RUMOR = 14
# Delivery acknowledgement (v0.3 plan, P1). Addressable under d=<delivery_id>,
# where delivery_id is the d tag of the acknowledged message; one acknowledgement
# per (acknowledger, delivery) pair. Tags: e=<event id>, p=<original sender>, and
# status. Recipient-side idempotency is keyed by delivery_id.
KIND_ACK_RECEIPT = 31034
KIND_REPORT = 31985

# Reserved for the proposed organization-addressed inner private letter. A
# personal inbox must not interpret these as ordinary exact-peer mail while
# the separate organization ingress and dispatcher are still undeployed.
# `a4a_conversation` is intentionally absent: personal mail already supports it.
ORGANIZATION_ONLY_PRIVATE_TAGS = frozenset({
    "a4a_owner", "a4a_descriptor", "a4a_request",
})

INTENT_TYPES = ("service_request", "product_sell", "product_buy", "meetup", "knowledge", "collab")
CATEGORIES = ("development", "design", "marketing", "content", "consulting", "hardware", "other")
TASK_STATUSES = ("accepted", "in_progress", "review", "completed", "failed")
ACK_STATUSES = ("received", "processed", "failed")
AGREEMENT_STATUSES = ("agreed", "in_progress", "completed", "disputed")


#: Grace period after an event's own deadline before it is no longer needed.
#:
#: A request is useless after its deadline, but it must not disappear immediately:
#: the recipient must be able to observe expiry and the parties must be able to cite it.
PUBLIC_GRACE_SECONDS = 30 * 24 * 3600

#: Lifetime for a public event without its own deadline (an offer is meaningless
#: without its request, and a search request is conceptually one-shot).
PUBLIC_DEFAULT_TTL_SECONDS = 90 * 24 * 3600


def _expires_at(deadline: int | None = None) -> list[str]:
    """Return the NIP-40 tag marking when a public event is no longer needed.

    The event itself must state when it becomes stale. Retention policy belongs to
    a relay and does not travel with the event, so otherwise our garbage would live
    forever on third-party relays at their operators' expense (2026-08-29 audit).

    Historical events do NOT receive this tag: agreements, reviews, trust claims,
    attestations, delegations, and profiles. Expiring them would make reputation
    disappear on its own.
    """
    now = int(time.time())
    if deadline:
        # An elapsed deadline does not make an event immediately disposable: the
        # grace period starts at the later of now and the deadline.
        base = max(now, int(deadline))
        return ["expiration", str(base + PUBLIC_GRACE_SECONDS)]
    return ["expiration", str(now + PUBLIC_DEFAULT_TTL_SECONDS)]


def _unique_d() -> list[str]:
    # Kinds 30000–39999 are parameterized replaceable (NIP-33): without a unique d,
    # a relay would replace an agent's first Intent with its second one.
    return ["d", uuid.uuid4().hex]


#: Tag integer ceiling under rule 7 §1.1 (`0|[1-9][0-9]{0,18}`: at most 19 digits).
#: Writers must reject before readers do: a 2026-09-04 external probe published a
#: 23-digit budget_max that `search_intents` (parse_uint ≤ 19 digits) could not see.
MAX_TAG_INT = 10 ** 19 - 1


def _uint_str(raw: str, name: str) -> int:
    """Parse a network tag value only when it uses canonical integer syntax.

    Plain `int()` accepted "+45000", " 45000", "45_000", and non-ASCII digits and
    gave the model 45000. For agreements this changed identity: our digest used the
    model's `str(price)`, or "45000", so canonical-price signatures verified here but
    not in an implementation hashing the original tag string. The same agreement was
    "formed" for this SDK and not for a strict client (2026-09-04 wire probe). An event
    with a non-canonical integer is rejected wholesale by `_safe_from_event`.
    """
    value = parse_uint(raw)
    if value is None:
        raise ValueError(f"tag {name}: non-canonical integer {raw!r}")
    return value


def _uint_tag(ev: Event, name: str, default: int | None = None) -> int | None:
    """Parse a named tag: absent means `default`; malformed means ValueError."""
    raw = ev.tag_value(name)
    return default if raw is None else _uint_str(raw, name)


#: Agreement signature domain tag (BIP-340 tagged hash). A party signs
#: tagged_hash(tag, terms), not sha256(terms): sha256(sha256(tag) ‖ sha256(tag) ‖ terms).
#: Thus the 32 bytes signed by an agent for an agreement can never equal an event id
#: (sha256 of a serialized "[0,…") or any other object with its own domain tag. Before
#: 2026-09-04 there was no separator (internal audit finding 6), so a digest signature
#: was indistinguishable from a signature over an event id.
AGREEMENT_DOMAIN = "a4a/agreement/v2"


def tagged_hash(tag: str, message: bytes) -> bytes:
    """BIP-340 tagged hash: sha256(sha256(tag) ‖ sha256(tag) ‖ message)."""
    tag_hash = hashlib.sha256(tag.encode("utf-8")).digest()
    return hashlib.sha256(tag_hash + tag_hash + message).digest()


def agreement_canonical(intent_id: str, offer_id: str, price: int, currency: str,
                        deadline: int, agent_a: str, agent_b: str) -> bytes:
    """Canonical terms (§1.1): a compact JSON array with price encoded as a string."""
    if any(type(value) is not int or not 0 <= value <= MAX_TAG_INT
           for value in (price, deadline)):
        raise ValueError("agreement price and deadline must be exact unsigned integers of at most 19 digits")
    if any(type(value) is not str for value in (intent_id, offer_id, currency, agent_a, agent_b)):
        raise ValueError("agreement text fields must be strings")
    # v2 keeps its original ASCII escapes and exact integer tokens. Changing
    # escaping here would invalidate existing signatures under the same domain.
    return json.dumps(
        ["a4a-agreement-v2", intent_id, offer_id, str(price), currency,
         deadline, agent_a, agent_b],
        separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def agreement_digest(intent_id: str, offer_id: str, price: int, currency: str,
                     deadline: int, agent_a: str, agent_b: str) -> str:
    """Digest signed by both parties: hex(tagged_hash(domain, canonical terms))."""
    return tagged_hash(AGREEMENT_DOMAIN, agreement_canonical(
        intent_id, offer_id, price, currency, deadline, agent_a, agent_b)).hex()


class _A4AModel(BaseModel):
    source: Event | None = Field(default=None, exclude=True)

    @field_validator("source")
    @classmethod
    def _source_numbers(cls, value: Event | None) -> Event | None:
        if value is not None:
            value.validate_numeric_tags()
        return value


class AgentProfile(_A4AModel):
    capabilities: list[str]
    category: str
    languages: list[str] = ["ru"]
    price_range: tuple[int, int, str] | None = None
    availability: str | None = None
    portfolio: str | None = None
    content: str = ""

    @field_validator("category")
    @classmethod
    def _cat(cls, v):
        if v not in CATEGORIES:
            raise ValueError(f"unknown category: {v}. Allowed: {', '.join(CATEGORIES)}")
        return v

    def to_event(self, delegation_id: str | None = None) -> Event:
        tags = [["capability", c] for c in self.capabilities]
        tags.append(["category", self.category])
        tags += [["language", lang] for lang in self.languages]
        if self.price_range:
            lo, hi, cur = self.price_range
            tags.append(["price_range", str(lo), str(hi), cur])
        if self.availability:
            tags.append(["availability", self.availability])
        if self.portfolio:
            tags.append(["portfolio", self.portfolio])
        # Put facets in the single-character `t` tag, using the Intent convention.
        # NIP-01 indexes only single-character tags, so without these entries no
        # third-party relay could find a profile. Requests had them but profiles did
        # not, even though AGENT search is a stated capability (2026-08-29 audit).
        tags.append(["t", f"a4a:cat:{self.category}"])
        tags += [["t", f"a4a:cap:{c}"] for c in self.capabilities]
        tags += [["t", f"a4a:lang:{lang}"] for lang in self.languages]
        if delegation_id:
            tags.append(["delegation", delegation_id])
        tags.append(["d", "profile"])  # Fixed d value required by specification §8.2.
        return Event(kind=KIND_AGENT_PROFILE, tags=tags, content=self.content)

    @classmethod
    def from_event(cls, ev: Event) -> "AgentProfile":
        pr = None
        for tag in ev.tags:
            if tag[0] == "price_range" and len(tag) >= 4:
                pr = (_uint_str(tag[1], "price_range"), _uint_str(tag[2], "price_range"),
                      tag[3])
        return cls(capabilities=ev.tag_values("capability"),
                   category=ev.tag_value("category") or "other",
                   languages=ev.tag_values("language") or ["ru"],
                   price_range=pr,
                   availability=ev.tag_value("availability"),
                   portfolio=ev.tag_value("portfolio"),
                   content=ev.content, source=ev)


# Writer-model numeric fields are non-negative (Field(ge=0, le=MAX_TAG_INT)). Since
# 2026-09-04, `from_event` accepts only canonical `0|[1-9][0-9]*`; a model that emitted
# "-5" could not read its own event. An MCP probe found a4a_publish_offer(price=-5)
# reaching the wire (rule 7 §1.1: writers and readers use the same grammar).
class Intent(_A4AModel):
    intent_type: str
    category: str
    need: str
    budget_min: int = Field(ge=0, le=MAX_TAG_INT)
    budget_max: int = Field(ge=0, le=MAX_TAG_INT)
    currency: str = "USD"
    deadline: int = Field(ge=0, le=MAX_TAG_INT)
    language: str = "en"
    location: str | None = None
    content: str = ""

    @field_validator("intent_type")
    @classmethod
    def _it(cls, v):
        if v not in INTENT_TYPES:
            raise ValueError(f"unknown intent_type: {v}. Allowed: {', '.join(INTENT_TYPES)}")
        return v

    @field_validator("category")
    @classmethod
    def _cat(cls, v):
        if v not in CATEGORIES:
            raise ValueError(f"unknown category: {v}. Allowed: {', '.join(CATEGORIES)}")
        return v

    def to_event(self, delegation_id: str | None = None) -> Event:
        tags = [["intent_type", self.intent_type], ["category", self.category],
                ["need", self.need], ["budget_min", str(self.budget_min)],
                ["budget_max", str(self.budget_max)], ["currency", self.currency],
                ["deadline", str(self.deadline)], ["language", self.language],
                _unique_d(), _expires_at(self.deadline)]
        # Duplicate facets into the standard single-character `t` tag. NIP-01 indexes
        # only single-character tags, so category/type/language search otherwise fails
        # on every third-party relay; strfry rejects the query outright (live probe of
        # 25 public relays on 2026-08-28). The `a4a:` prefix separates these facets
        # from unrelated topics in the shared `t` namespace.
        tags += [["t", f"a4a:cat:{self.category}"],
                 ["t", f"a4a:type:{self.intent_type}"],
                 ["t", f"a4a:lang:{self.language}"]]
        if self.location:
            tags.append(["location", self.location])
        if delegation_id:
            tags.append(["delegation", delegation_id])
        return Event(kind=KIND_INTENT, tags=tags, content=self.content)

    @classmethod
    def from_event(cls, ev: Event) -> "Intent":
        return cls(intent_type=ev.tag_value("intent_type"),
                   category=ev.tag_value("category"),
                   need=ev.tag_value("need") or "",
                   budget_min=_uint_tag(ev, "budget_min", 0),
                   budget_max=_uint_tag(ev, "budget_max", 0),
                   currency=ev.tag_value("currency") or "USD",
                   deadline=_uint_tag(ev, "deadline", 0),
                   language=ev.tag_value("language") or "ru",
                   location=ev.tag_value("location"),
                   content=ev.content, source=ev)


class Offer(_A4AModel):
    intent_id: str
    price: int = Field(ge=0, le=MAX_TAG_INT)
    currency: str = "USD"
    eta: int = Field(ge=0, le=MAX_TAG_INT)
    portfolio: str | None = None
    content: str = ""

    def to_event(self, delegation_id: str | None = None) -> Event:
        # `intent_id` identifies the request event, so duplicate it into the standard
        # `e` tag indexed by every relay; only our fork indexes multi-character `intent`.
        tags = [["intent", self.intent_id], ["e", self.intent_id],
                ["price", str(self.price), self.currency],
                ["eta", str(self.eta)], _unique_d(), _expires_at()]
        if self.portfolio:
            tags.append(["portfolio", self.portfolio])
        if delegation_id:
            tags.append(["delegation", delegation_id])
        return Event(kind=KIND_OFFER, tags=tags, content=self.content)

    @classmethod
    def from_event(cls, ev: Event) -> "Offer":
        price_tag = next((t for t in ev.tags if t[0] == "price"), ["price", "0", "USD"])
        return cls(intent_id=ev.tag_value("intent") or "",
                   price=_uint_str(price_tag[1], "price"),
                   currency=price_tag[2] if len(price_tag) > 2 else "USD",
                   eta=_uint_tag(ev, "eta", 0),
                   portfolio=ev.tag_value("portfolio"),
                   content=ev.content, source=ev)


class Agreement(_A4AModel):
    intent_id: str = Field(strict=True)
    offer_id: str = Field(strict=True)
    price: int = Field(ge=0, le=MAX_TAG_INT, strict=True)
    currency: str = Field(default="USD", strict=True)
    deadline: int = Field(ge=0, le=MAX_TAG_INT, strict=True)
    agent_a: str = Field(strict=True)
    agent_b: str = Field(strict=True)
    sig_a: str
    sig_b: str
    status: str = "agreed"
    content: str = "Agreement terms recorded"

    @field_validator("status")
    @classmethod
    def _st(cls, v):
        if v not in AGREEMENT_STATUSES:
            raise ValueError(
                f"unknown agreement status: {v}. Allowed: {', '.join(AGREEMENT_STATUSES)}")
        return v

    def digest(self) -> str:
        return agreement_digest(self.intent_id, self.offer_id, self.price,
                                self.currency, self.deadline, self.agent_a, self.agent_b)

    def verify_signatures(self) -> bool:
        d = self.digest()
        return crypto.verify(d, self.sig_a, self.agent_a) and \
               crypto.verify(d, self.sig_b, self.agent_b)

    def to_event(self, publisher_delegation: str | None = None,
                 counterparty_delegation: str | None = None,
                 publisher: str | None = None) -> Event:
        """Build the agreement event.

        `publisher_delegation` is the mandate of the PUBLISHING party, while
        `counterparty_delegation` belongs to the other party. They are assigned by
        `publisher` (`delegation_a` for `agent_a`, `delegation_b` for `agent_b`), not
        positionally. Previously the publisher mandate always became `delegation_a`,
        so when `agent_b` published, readers verified the wrong party's mandate.

        The ordinary `delegation` tag is required because the relay requires the event
        AUTHOR's mandate. Without it an agreement—the most important traceability kind—
        could never satisfy enforcement (discovered when enforcement was enabled on
        2026-08-29).
        """
        tags = [["intent", self.intent_id], ["offer", self.offer_id],
                ["price", str(self.price), self.currency],
                ["deadline", str(self.deadline)],
                ["agent_a", self.agent_a], ["agent_b", self.agent_b],
                # Duplicate both parties into single-character `p` tags, which every
                # NIP-01 relay must index. Otherwise the counterparty could not find
                # its own agreement outside our fork; only one party publishes, so the
                # other must discover it through the network (audit finding 34).
                ["p", self.agent_a], ["p", self.agent_b],
                ["sig_a", self.sig_a], ["sig_b", self.sig_b],
                ["status", self.status], _unique_d()]
        if publisher_delegation:
            tags.append(["delegation", publisher_delegation])
        # Preserve the old API default: the publisher is party A unless specified.
        publisher_is_b = publisher is not None and publisher == self.agent_b
        deleg_a = counterparty_delegation if publisher_is_b else publisher_delegation
        deleg_b = publisher_delegation if publisher_is_b else counterparty_delegation
        if deleg_a:
            tags.append(["delegation_a", deleg_a])
        if deleg_b:
            tags.append(["delegation_b", deleg_b])
        return Event(kind=KIND_AGREEMENT, tags=tags, content=self.content)

    @classmethod
    def from_event(cls, ev: Event) -> "Agreement":
        price_tag = next((t for t in ev.tags if t[0] == "price"), ["price", "0", "USD"])
        return cls(intent_id=ev.tag_value("intent") or "",
                   offer_id=ev.tag_value("offer") or "",
                   price=_uint_str(price_tag[1], "price"),
                   currency=price_tag[2] if len(price_tag) > 2 else "USD",
                   deadline=_uint_tag(ev, "deadline", 0),
                   agent_a=ev.tag_value("agent_a") or "",
                   agent_b=ev.tag_value("agent_b") or "",
                   sig_a=ev.tag_value("sig_a") or "",
                   sig_b=ev.tag_value("sig_b") or "",
                   status=ev.tag_value("status") or "agreed",
                   content=ev.content, source=ev)


class Review(_A4AModel):
    agreement_id: str
    target: str  # Rated agent pubkey; tag ["p", ...] is the SDK's spec clarification.
    rating: int = Field(ge=1, le=5)
    category: str = "overall"
    content: str = ""

    def to_event(self, delegation_id: str | None = None) -> Event:
        tags = [["agreement", self.agreement_id], ["p", self.target],
                ["rating", str(self.rating)], ["category", self.category], _unique_d()]
        if delegation_id:
            tags.append(["delegation", delegation_id])
        return Event(kind=KIND_REVIEW, tags=tags, content=self.content)

    @classmethod
    def from_event(cls, ev: Event) -> "Review":
        return cls(agreement_id=ev.tag_value("agreement") or "",
                   target=ev.tag_value("p") or "",
                   rating=_uint_tag(ev, "rating", 0),
                   category=ev.tag_value("category") or "overall",
                   content=ev.content, source=ev)


class Invoice(_A4AModel):
    bolt11: str
    amount: int = Field(ge=0, le=MAX_TAG_INT)
    currency: str = "USD"
    agreement_id: str
    payer: str
    payee: str

    def to_event(self, delegation_id: str | None = None) -> Event:
        tags = [["bolt11", self.bolt11], ["amount", str(self.amount), self.currency],
                ["agreement", self.agreement_id], ["payer", self.payer],
                ["payee", self.payee], _unique_d()]
        if delegation_id:
            tags.append(["delegation", delegation_id])
        return Event(kind=KIND_INVOICE, tags=tags, content="")

    @classmethod
    def from_event(cls, ev: Event) -> "Invoice":
        amount_tag = next((t for t in ev.tags if t[0] == "amount"), ["amount", "0", "USD"])
        return cls(bolt11=ev.tag_value("bolt11") or "",
                   amount=_uint_str(amount_tag[1], "amount"),
                   currency=amount_tag[2] if len(amount_tag) > 2 else "USD",
                   agreement_id=ev.tag_value("agreement") or "",
                   payer=ev.tag_value("payer") or "",
                   payee=ev.tag_value("payee") or "", source=ev)


class SearchIntent(_A4AModel):
    query: str
    category: str | None = None
    intent_type: str | None = None
    budget_min: int | None = Field(default=None, ge=0, le=MAX_TAG_INT)
    budget_max: int | None = Field(default=None, ge=0, le=MAX_TAG_INT)
    language: str | None = None
    since: int | None = Field(default=None, ge=0, le=MAX_TAG_INT)

    def to_event(self, delegation_id: str | None = None) -> Event:
        tags = [["query", self.query], _unique_d(), _expires_at()]
        for name in ("category", "intent_type", "budget_min", "budget_max",
                     "language", "since"):
            value = getattr(self, name)
            if value is not None:
                tags.append([name, str(value)])
        if delegation_id:
            tags.append(["delegation", delegation_id])
        return Event(kind=KIND_SEARCH_INTENT, tags=tags, content="")

    @classmethod
    def from_event(cls, ev: Event) -> "SearchIntent":
        def _int(name):
            return _uint_tag(ev, name, None)
        return cls(query=ev.tag_value("query") or "",
                   category=ev.tag_value("category"),
                   intent_type=ev.tag_value("intent_type"),
                   budget_min=_int("budget_min"), budget_max=_int("budget_max"),
                   language=ev.tag_value("language"), since=_int("since"), source=ev)


class TrustAssertion(_A4AModel):
    trusted: str
    weight: float = Field(ge=0.0, le=1.0)
    reason: str = ""

    def to_event(self, delegation_id: str | None = None) -> Event:
        tags = [["trust", self.trusted], ["weight", format_decimal(self.weight)],
                ["reason", self.reason], _unique_d()]
        if delegation_id:
            tags.append(["delegation", delegation_id])
        return Event(kind=KIND_TRUST_ASSERTION, tags=tags, content="")

    @classmethod
    def from_event(cls, ev: Event) -> "TrustAssertion":
        raw = ev.tag_value("weight")
        weight = 0.0 if raw is None else parse_decimal(raw)
        if weight is None:
            raise ValueError(f"tag weight: non-canonical decimal {raw!r}")
        return cls(trusted=ev.tag_value("trust") or "",
                   weight=weight,
                   reason=ev.tag_value("reason") or "", source=ev)


#: Identity-attestation level dictionary (kind 31021).
#:
#: A level names the EVIDENCE, not the conclusion. This used to be a free-form string
#: whose semantics were left to the issuer, so two issuers could say "verified" about
#: entirely different checks and consumers compared incomparable claims. Worse, an
#: issuer could claim `gov_id` after checking an email address and remain technically
#: compliant (2026-08-29 internal audit; dictionary in specification v0.4 §2.4).
#:
#: The value is normalized assurance on the eIDAS scale, allowing policy such as
#: "admit substantial or higher" without knowing each national scheme.
IDENTITY_LEVELS: dict[str, str] = {
    # Account control proves only ownership of that account.
    "account:email": "low",
    "account:phone": "low",
    "account:github": "low",
    "account:telegram": "low",
    "account:vk": "low",
    "account:yandex": "low",
    # Domain control is NOT proof of a legal entity; the name states that honestly.
    "org:domain": "low",
    # Organization representative backed by machine-readable power of attorney.
    "org:poa": "substantial",
    # Key bound to an organization identifier by a qualified signature.
    "org:kep": "high",
    # Living citizen verified by a government service.
    "person:gosklyuch": "substantial",
    # Customer of a bank that performed KYC.
    "person:bank": "substantial",
    # Legal entity in an international registry.
    "org:lei": "high",
}

#: Prefix for levels absent from the dictionary. Experiments are allowed but must be
#: visibly non-standard and receive the lowest assurance; an issuer-defined level
#: cannot grant itself high assurance.
EXPERIMENTAL_LEVEL_PREFIX = "x-"

#: Organization-identifier namespaces. Use a namespace/value pair instead of a
#: dedicated Russian tax-ID field, which the first foreign issuer would outgrow.
REF_NAMESPACES = ("inn", "ogrn", "ogrnip", "lei", "domain", "duns")

LOA_ORDER = ("low", "substantial", "high")


def assurance_of(level: str) -> str:
    """Return normalized assurance; a non-standard level is always `low`."""
    return IDENTITY_LEVELS.get(level, "low")


class IdentityAttestation(_A4AModel):
    """Identity attestation (kind 31021), signed by the ISSUER (verifier).

    `subject` is the verified owner/agent pubkey. `level` names the verification
    evidence. `name` is the optional legal name (selective disclosure; hidden by
    default). `issuer_name` is the human-readable issuer. `expiration` is optional
    (0 means no expiry). The issuer key signs the event: `event.pubkey` is the issuer.
    """
    subject: str
    level: str
    name: str = ""
    issuer_name: str = ""
    expiration: int = Field(default=0, ge=0, le=MAX_TAG_INT)
    ref: str = ""
    content: str = ""

    @field_validator("level")
    @classmethod
    def _level(cls, v: str) -> str:
        if v in IDENTITY_LEVELS or v.startswith(EXPERIMENTAL_LEVEL_PREFIX):
            return v
        raise ValueError(
            f"unknown attestation level: {v!r}. Use a value from IDENTITY_LEVELS "
            f"or a custom level prefixed with {EXPERIMENTAL_LEVEL_PREFIX!r} so it "
            f"is visibly non-standard")

    @field_validator("ref")
    @classmethod
    def _ref(cls, v: str) -> str:
        if not v:
            return v
        ns = v.split(":", 1)[0]
        if ns not in REF_NAMESPACES or ":" not in v:
            raise ValueError(
                f"organization identifier must be a namespace:value pair; "
                f"allowed namespaces: {', '.join(REF_NAMESPACES)}")
        return v

    @property
    def loa(self) -> str:
        """Normalized assurance lets policy ignore national scheme details."""
        return assurance_of(self.level)

    def to_event(self, delegation_id: str | None = None) -> Event:
        tags = [["d", self.subject], ["p", self.subject], ["level", self.level],
                ["loa", self.loa]]
        if self.ref:
            tags.append(["ref", self.ref])
        if self.name:
            tags.append(["name", self.name])
        if self.issuer_name:
            tags.append(["issuer_name", self.issuer_name])
        if self.expiration:
            tags.append(["expiration", str(self.expiration)])
        if delegation_id:
            tags.append(["delegation", delegation_id])
        return Event(kind=KIND_IDENTITY_ATTESTATION, tags=tags, content=self.content)

    @classmethod
    def from_event(cls, ev: Event) -> "IdentityAttestation":
        # Do NOT trust `loa` from the event: the issuer writes it and could assign any
        # assurance to its own level. Derive assurance from our dictionary; the event
        # tag is only a convenience for clients filtering at the relay.
        return cls(subject=ev.tag_value("p") or "",
                   level=ev.tag_value("level") or "",
                   name=ev.tag_value("name") or "",
                   issuer_name=ev.tag_value("issuer_name") or "",
                   # Not `parse_uint(...) or 0`: a non-canonical expiry ("+N", "abc")
                   # became None → 0 → no expiry, so a malformed attestation appeared
                   # permanent while `identity.verify_identity_attestation` rejected
                   # the same tag. Two readers in one package disagreed (2026-09-04
                   # probe). The whole event is now rejected instead.
                   expiration=ev.expiration() or 0,
                   ref=ev.tag_value("ref") or "",
                   content=ev.content, source=ev)


class ConnectionRequest(_A4AModel):
    """Connection request (kind 31022): an invitation with a short intro.

    `to_pubkey` is the recipient. Mutual requests (A→B and B→A) establish a
    connection. Addressable under d=<recipient>: one request per (author, recipient).
    """
    to_pubkey: str
    intro: str = ""

    def to_event(self, delegation_id: str | None = None) -> Event:
        tags = [["d", self.to_pubkey], ["p", self.to_pubkey]]
        if delegation_id:
            tags.append(["delegation", delegation_id])
        return Event(kind=KIND_CONNECTION_REQUEST, tags=tags, content=self.intro)

    @classmethod
    def from_event(cls, ev: Event) -> "ConnectionRequest":
        return cls(to_pubkey=ev.tag_value("p") or "", intro=ev.content, source=ev)


def _task_id_of(ev: Event) -> str:
    """Return the task identifier from an event in a task stream.

    TaskRequest used `task_id`, while TaskStatus and TaskResult used `task`. Each class
    round-tripped independently, but one filter could not collect an entire task stream,
    and the protocol registry did not document the mismatch (2026-08-29 internal audit).
    Writers now use `task_id` everywhere; readers still accept the legacy name so events
    published before unification remain readable.
    """
    return ev.tag_value("task_id") or ev.tag_value("task") or ""


class TaskRequest(_A4AModel):
    agreement_id: str
    task_id: str
    description: str
    deadline: int = Field(ge=0, le=MAX_TAG_INT)
    content: str = ""
    # Task recipient. Empty is allowed only while parsing legacy events: a task
    # without a recipient cannot be discovered, and `send_task` requires one.
    executor: str = ""

    def to_event(self, delegation_id: str | None = None) -> Event:
        tags = [["agreement", self.agreement_id], ["task_id", self.task_id],
                ["description", self.description], ["deadline", str(self.deadline)],
                # `e` identifies the agreement and `p` the executor. Every relay indexes
                # single-character tags; without them the executor could not find its task.
                ["e", self.agreement_id],
                _unique_d(), _expires_at(self.deadline)]
        if self.executor:
            tags.append(["p", self.executor])
        if delegation_id:
            tags.append(["delegation", delegation_id])
        return Event(kind=KIND_TASK_REQUEST, tags=tags, content=self.content)

    @classmethod
    def from_event(cls, ev: Event) -> "TaskRequest":
        return cls(agreement_id=ev.tag_value("agreement") or "",
                   task_id=ev.tag_value("task_id") or "",
                   description=ev.tag_value("description") or "",
                   executor=ev.tag_value("p") or "",
                   deadline=_uint_tag(ev, "deadline", 0),
                   content=ev.content, source=ev)


class TaskStatus(_A4AModel):
    task_id: str
    agreement_id: str
    status: str
    progress: int = Field(default=0, ge=0, le=100)
    content: str = ""

    @field_validator("status")
    @classmethod
    def _st(cls, v):
        if v not in TASK_STATUSES:
            raise ValueError(f"unknown task status: {v}")
        return v

    def to_event(self, delegation_id: str | None = None) -> Event:
        tags = [["task_id", self.task_id], ["agreement", self.agreement_id],
                ["e", self.agreement_id],   # Make task streams readable on every relay.
                ["status", self.status], ["progress", str(self.progress)], _unique_d()]
        if delegation_id:
            tags.append(["delegation", delegation_id])
        return Event(kind=KIND_TASK_STATUS, tags=tags, content=self.content)

    @classmethod
    def from_event(cls, ev: Event) -> "TaskStatus":
        return cls(task_id=_task_id_of(ev),
                   agreement_id=ev.tag_value("agreement") or "",
                   status=ev.tag_value("status") or "accepted",
                   progress=_uint_tag(ev, "progress", 0),
                   content=ev.content, source=ev)


class TaskResult(_A4AModel):
    task_id: str
    agreement_id: str
    result_url: str
    content: str = ""

    def to_event(self, delegation_id: str | None = None) -> Event:
        tags = [["task_id", self.task_id], ["agreement", self.agreement_id],
                ["e", self.agreement_id],   # Make task streams readable on every relay.
                ["result_url", self.result_url], _unique_d()]
        if delegation_id:
            tags.append(["delegation", delegation_id])
        return Event(kind=KIND_TASK_RESULT, tags=tags, content=self.content)

    @classmethod
    def from_event(cls, ev: Event) -> "TaskResult":
        return cls(task_id=_task_id_of(ev),
                   agreement_id=ev.tag_value("agreement") or "",
                   result_url=ev.tag_value("result_url") or "",
                   content=ev.content, source=ev)


class AckReceipt(_A4AModel):
    """Message delivery acknowledgement (kind 31034, v0.3 plan P1).

    `delivery_id` is the stable delivery id (the acknowledged message's d tag),
    unchanged across retries. The sender correlates acknowledgements with it and the
    recipient deduplicates on it. The acknowledgement's own d tag equals `delivery_id`,
    producing one acknowledgement per (acknowledger, delivery) pair.
    """
    delivery_id: str
    acked_event_id: str
    to_pubkey: str
    status: str = "received"
    content: str = ""

    @field_validator("status")
    @classmethod
    def _ack_st(cls, v):
        if v not in ACK_STATUSES:
            raise ValueError(f"unknown acknowledgement status: {v}")
        return v

    def to_event(self, delegation_id: str | None = None) -> Event:
        tags = [["d", self.delivery_id],
                ["e", self.acked_event_id],
                ["p", self.to_pubkey],
                ["status", self.status]]
        if delegation_id:
            tags.append(["delegation", delegation_id])
        return Event(kind=KIND_ACK_RECEIPT, tags=tags, content=self.content)

    @classmethod
    def from_event(cls, ev: Event) -> "AckReceipt":
        return cls(delivery_id=ev.tag_value("d") or "",
                   acked_event_id=ev.tag_value("e") or "",
                   to_pubkey=ev.tag_value("p") or "",
                   status=ev.tag_value("status") or "received",
                   content=ev.content, source=ev)


class Report(_A4AModel):
    target_event: str | None = None
    target_agent: str | None = None
    content: str = ""

    @model_validator(mode="after")
    def _at_least_one(self):
        # field_validator is unsuitable because it does not run for omitted fields.
        if self.target_event is None and self.target_agent is None:
            raise ValueError("specify target_event or target_agent")
        return self

    def to_event(self, delegation_id: str | None = None) -> Event:
        tags = [_unique_d()]
        if self.target_event:
            tags.append(["target_event", self.target_event])
        if self.target_agent:
            tags.append(["target_agent", self.target_agent])
        if delegation_id:
            tags.append(["delegation", delegation_id])
        return Event(kind=KIND_REPORT, tags=tags, content=self.content)

    @classmethod
    def from_event(cls, ev: Event) -> "Report":
        return cls(target_event=ev.tag_value("target_event"),
                   target_agent=ev.tag_value("target_agent"),
                   content=ev.content, source=ev)
