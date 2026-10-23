"""High-level A4A agent facade (API from a4a-master-spec.md, Part VIII)."""
import asyncio
import contextlib
import logging
import math
import re
import time
import uuid

from urllib.parse import urlsplit

from pydantic import ValidationError

from . import crypto, files, giftwrap, identity, nip44, timestamp, types
from . import delegation as dlg
from .event import Event, is_canonical_pubkey, parse_uint
from .keys import Keys
from .relay import RelayClient, RelayError, FanOutRelayClient
from .reputation import (
    CompletionReputation, DeliveryReputation, Reputation, agreement_parties,
    build_trust_graph, compute_completion_reputation, compute_delivery_reputation,
    compute_reputation)


class NotaryDiscoveryError(RuntimeError):
    """The relay's NIP-11 notary declaration could not be inspected."""


def _model_kind(model_cls) -> int | None:
    """Return the expected kind for validating models parsed from network events."""
    return {
        types.AgentProfile: types.KIND_AGENT_PROFILE,
        types.Intent: types.KIND_INTENT,
        types.Offer: types.KIND_OFFER,
        types.Agreement: types.KIND_AGREEMENT,
        types.Review: types.KIND_REVIEW,
        types.Invoice: types.KIND_INVOICE,
        types.SearchIntent: types.KIND_SEARCH_INTENT,
        types.TrustAssertion: types.KIND_TRUST_ASSERTION,
        types.IdentityAttestation: types.KIND_IDENTITY_ATTESTATION,
        types.ConnectionRequest: types.KIND_CONNECTION_REQUEST,
        types.TaskRequest: types.KIND_TASK_REQUEST,
        types.TaskStatus: types.KIND_TASK_STATUS,
        types.TaskResult: types.KIND_TASK_RESULT,
        types.AckReceipt: types.KIND_ACK_RECEIPT,
        types.Report: types.KIND_REPORT,
    }.get(model_cls)


def _authority(state: str, at, stamp, revocation_stamp, detail: str, evidence: dict) -> dict:
    """Keep stable response fields while separating evidence from historical authority."""
    return {"state": state, "at": at, "stamp": stamp, "revocation_stamp": revocation_stamp,
            "detail": detail, "evidence": evidence, "evidence_version": 1}


def _safe_from_event(model_cls, ev):
    """Parse a model from a network event, returning None for invalid data or kind.

    Kind validation is necessary because the relay is untrusted: a foreign,
    correctly signed event of another kind must not be parsed as, for example, an
    Offer or Review.
    """
    expected = _model_kind(model_cls)
    if expected is not None and ev.kind != expected:
        return None
    try:
        return model_cls.from_event(ev)
    except (ValidationError, ValueError, IndexError, TypeError):
        return None


# Default private-message lifetime (NIP-40 `expiration` tag). A private message is
# single-use: after delivery and acknowledgement nobody reads it again, yet without
# expiry it occupies relay storage forever. Public events (profiles, intents,
# reviews, and trust) are small and needed long-term, so they do not expire. The
# caller may disable expiry with `expires_in=0` or set it per message.
PRIVATE_TTL_SECONDS = 30 * 24 * 3600

class _BoundedSeen:
    """Bounded set of observed identifiers that evicts old entries.

    An ordinary set in a long-lived subscription grows with the spam stream.
    """

    def __init__(self, cap: int = 10_000):
        self.cap = cap
        self._order: list[str] = []
        self._set: set[str] = set()

    def __contains__(self, key: str) -> bool:
        return key in self._set

    def add(self, key: str) -> None:
        if key in self._set:
            return
        self._order.append(key)
        self._set.add(key)
        if len(self._order) > self.cap:
            self._set.discard(self._order.pop(0))


#: Maximum number of recipient relays to visit during delivery.
#:
#: The list comes from a FOREIGN event (NIP-65), so an outsider controls the number
#: of outbound connections. Without a limit, one hundred declared addresses would
#: mean one hundred connections with ten-second timeouts—up to seventeen minutes of
#: blocking. This also affects others: by naming a third-party host as its relay, a
#: recipient makes every sender connect to that host.
#:
#: Five leaves headroom over normal NIP-65 practice, which recommends only a few.
log = logging.getLogger(__name__)

MAX_RECIPIENT_RELAYS = 5


def _relay_url_acceptable(url: str, own: tuple[str, ...] = (),
                          allow_internal: bool = False) -> bool:
    """Return whether a relay URL from a FOREIGN event is acceptable.

    Only ws/wss and no internal hosts are allowed. Otherwise, a foreign agent could
    declare a “relay” such as ws://127.0.0.1:6379 and make us connect inside our own
    perimeter (2026-08-28 review, S7).

    Our own relays are always allowed, including loopback. Local development and
    testing are normal use cases, and blocking an address already in use is pointless.
    """
    if url in own:
        return True
    parts = urlsplit(url)
    if parts.scheme not in ("ws", "wss") or not parts.hostname:
        return False
    return allow_internal or not files.is_internal_host(parts.hostname)


def _check_reply_to(reply_to) -> None:
    """Refuse a malformed reply reference before anything is signed or sent.

    The reference is what binds an answer to its letter (26.09.2026: the convention of
    quoting the delivery-id by hand was not kept), so a wrong one must fail loudly here
    rather than reach the recipient as a reference to nothing.
    """
    if (not isinstance(reply_to, (tuple, list)) or len(reply_to) not in (2, 4)
            or not all(isinstance(part, str) for part in reply_to)):
        raise ValueError("reply_to must be (delivery_id, inner_id) or (delivery_id, inner_id, "
                         "routed_via_pubkey, routed_via_inner_id), all strings")
    delivery_id, inner_id = reply_to[:2]
    if re.fullmatch(r"[0-9A-Za-z_.:-]{1,128}", delivery_id) is None:
        raise ValueError("reply_to delivery_id must be 1..128 characters of [0-9A-Za-z_.:-]")
    if re.fullmatch(r"[0-9a-f]{64}", inner_id) is None:
        raise ValueError("reply_to inner_id must be 64 lowercase hexadecimal characters")
    if len(reply_to) == 4:
        # 26.09.2026, representative: an answer whose address came from a forward line says
        # so and names the forwarder - inside the signed letter, never on the open envelope.
        if not is_canonical_pubkey(reply_to[2]):
            raise ValueError("reply_to routed_via pubkey must be 64 lowercase hexadecimal characters")
        if re.fullmatch(r"[0-9a-f]{64}", reply_to[3]) is None:
            raise ValueError("reply_to routed_via inner_id must be 64 lowercase hexadecimal characters")


def _reply_reference(inner: Event) -> dict | None:
    """Return the letter a signed rumor answers, or None when it names none clearly.

    Unlike the conversation handle, the reference routes nothing: it is a hint the
    reader checks against its own journal. A missing, repeated or malformed tag is
    therefore reported as "not a bound reply" instead of discarding the letter.
    """
    tags = [tag for tag in inner.tags if tag and tag[0] == "a4a_reply"]
    if len(tags) != 1 or len(tags[0]) != 3:
        return None
    try:
        _check_reply_to(tuple(tags[0][1:]))
    except ValueError:
        return None
    reference = {"delivery_id": tags[0][1], "inner_id": tags[0][2]}
    routed = [tag for tag in inner.tags if tag and tag[0] == "a4a_routed_via"]
    if len(routed) == 1 and len(routed[0]) == 3:
        try:
            _check_reply_to((*reference.values(), routed[0][1], routed[0][2]))
        except ValueError:
            return reference
        reference["routed_via"] = {"pubkey": routed[0][1], "inner_id": routed[0][2]}
    return reference


#: Default agent-mandate lifetime in days.
#:
#: Onboarding §6.4 requires “days, not years.” A short lifetime is the PRIMARY
#: protection against a leaked agent key; revocation (31007) is an emergency switch,
#: not a replacement. Before 2026-09-05 this default was one year: the MCP server
#: already issued 30-day mandates, while README clients received 365 because the
#: default lived in the wrapper rather than the core (finding 112). A meaningful
#: lower bound is no shorter than timestamp latency (hours, §2.9), otherwise agent
#: history cannot be verified.
DEFAULT_MANDATE_DAYS = 30


class Agent:
    """Publish and discover A4A events through relays on behalf of a key pair.

    With multiple relays, publishing, reads, and subscriptions use EVERY address in
    `relays`; results are merged and deduplicated by event ID. An event is accepted
    when AT LEAST ONE relay accepts it; rejection by all relays raises an exception.

    This documentation once said “reads and subscriptions use the first relay;
    merging is absent.” That was true before 2026-09-05 and became false
    with fan-out transport. A4A relays do not synchronize with each other: a message
    exists exactly where it was stored, so reading one relay lost everything stored
    on another.

    Privacy consequence for callers: EVERY configured relay sees the query because
    it is sent to all of them. The protocol cannot hide a query from a relay that
    receives it.
    """

    def __init__(self, relays: list[str], keys: Keys | None = None,
                 allow_internal_relays: bool = False, public_journal_dir=None):
        if not relays:
            raise ValueError("at least one relay URL is required")
        self.keys = keys or Keys()
        # Read from and publish to ALL configured relays (see FanOutRelayClient).
        # Before 2026-09-08, reads used only the first: a sender stored an envelope on
        # several declared relays while the recipient watched one, so losing that
        # relay also lost unread messages. Single-relay behavior remains identical.
        self.relay = FanOutRelayClient(list(relays))
        # Our own addresses are always permitted. Other internal addresses require
        # explicit consent: by default a foreign relay list cannot direct us inside
        # the perimeter, while multi-relay local development deliberately enables
        # the option (2026-08-28 review, S7).
        self._own_relays = tuple(relays)
        self._allow_internal_relays = allow_internal_relays
        self.delegation_id: str | None = None
        self._last_addressable: dict[str, int] = {}
        self.public_journal_dir = public_journal_dir
        self.last_publication: dict | None = None

    async def __aenter__(self):
        await self.relay.connect()
        return self

    async def __aexit__(self, *exc):
        await self.relay.aclose()

    @property
    def pubkey(self) -> str:
        return self.keys.pubkey_hex

    async def _broadcast(self, ev: Event) -> None:
        """Publish a signed event to ALL configured relays, not only the first.

        Before 2026-09-04, an agent configured with multiple relays published only to
        the first (“MVP: use the first relay”), while NIP-65 and the specification
        advertised lists and only revocations were fanned out. A counterparty
        listening to the second advertised address saw nothing.

        Since 2026-09-08, the transport itself (`FanOutRelayClient`) performs fan-out,
        so a second pass here was removed. It opened duplicate connections and
        published each event twice. Nostr IDs made this harmless to data, but it
        doubled the work and made the failed-delivery log misleading. The first relay
        is no longer privileged; network survival must not depend on address order.
        """
        await self.relay.publish(ev)

    #: Last publication time for each local addressable coordinate. The key is
    #: "kind:d" and the value is that event's `created_at`; see `_bump_created_at`.
    _last_addressable: dict[str, int]

    def _bump_created_at(self, ev: Event) -> None:
        """Ensure same-second corrections to replaceable events cannot silently lose.

        Finding 118 (2026-09-05, reproduced in staging): under NIP-33, equal
        `created_at` values make a relay retain the copy with the lower `id`, not the
        latest. Republishing a coordinate in the same second—for example, removing
        text from a review or profile—therefore does nothing roughly half the time.
        The relay replies OK and the author believes the correction succeeded while
        the old text remains online. Only readers observe the silent failure.

        Replacing our OWN coordinate therefore sets the time one second after the
        previous version. Advancing one second is harmless and removes the tie.

        The memory is process-local because the target case is two consecutive
        publications by one agent. A restart in the same second could theoretically
        restore the tie, but querying a relay before every publication costs more
        than the rare effect.
        """
        # REPLACEABLE events (kinds 0, 3, and 10000–20000) use the same tie rule as
        # addressable events, but the previous implementation did not protect them.
        # An external reviewer found this as HEAL-005. It matters especially for kind
        # 10002 because replacing a failed relay depends on republishing the list. A
        # lost tie meant the replacement notice did not take effect, the relay replied
        # “accepted,” and the old list silently remained online.
        addressable = 30000 <= ev.kind < 40000
        replaceable = ev.kind in (0, 3) or 10000 <= ev.kind < 20000
        if not (addressable or replaceable):
            return
        if addressable:
            d = ev.tag_value("d")
            if d is None:
                return
            key = f"{ev.kind}:{d}"
        else:
            # A replaceable event's coordinate is its kind: one copy per author and no
            # `d` tag. A key with an empty suffix would collide with addressable events
            # that lack `d`.
            key = f"replaceable:{ev.kind}"
        previous = self._last_addressable.get(key)
        if previous is not None and ev.created_at <= previous:
            ev.created_at = previous + 1
        self._last_addressable[key] = ev.created_at

    async def _publish(self, ev: Event) -> str:
        self._bump_created_at(ev)
        ev.sign(self.keys)
        from .publications import KINDS, PublicationStore, send_record
        if self.public_journal_dir is not None and ev.kind in KINDS:
            mandate = None
            if ev.kind != types.KIND_RELAY_LIST:
                candidates = await self.relay.query({"ids": [self.delegation_id]}) if self.delegation_id else []
                mandate = next((m for m in candidates if m.id == self.delegation_id), None)
            with PublicationStore(self.public_journal_dir, self.pubkey) as store:
                store.stage(ev, mandate, [c.url for c in self.relay.clients])
                self.last_publication = await send_record(self, ev, mandate, store, require_acceptance=True)
        else:
            await self._broadcast(ev)
        return ev.id

    async def repair_publications(self, *, now=None, limit: int = 5) -> dict:
        """Retry due copies of authorized public announcements, without re-signing."""
        from pathlib import Path
        from .publications import PublicationStore, repair
        if self.public_journal_dir is None or not (Path(self.public_journal_dir) / "publications.sqlite3").exists():
            return {"checked": 0, "restored": 0, "held": 0, "deferred": 0}
        with PublicationStore(self.public_journal_dir, self.pubkey) as store:
            async with asyncio.timeout(20):
                return await repair(self, store, now=now, limit=limit)

    # --- Registration -----------------------------------------------------

    async def register(self, user_keys: Keys, name: str, days: int = DEFAULT_MANDATE_DAYS,
                       not_before: int = 0) -> str:
        """Delegate user authority to this agent and return the delegation ID.

        `not_before` is the lower bound for `created_at` (one second AFTER the latest
        revocation); see `create_delegation`.
        """
        now = int(time.time())
        ev = dlg.create_delegation(user_keys, self.pubkey, name, now + days * 86400,
                                   created_at=max(now, not_before))
        await self._broadcast(ev)
        self.delegation_id = ev.id
        return ev.id

    async def ensure_registered(self, user_keys: Keys, name: str,
                                days: int = DEFAULT_MANDATE_DAYS,
                                renew_before_days: int = DEFAULT_MANDATE_DAYS // 3) -> str:
        """Find or issue an agent mandate that survives process restarts.

        `register()` issues a delegation UNCONDITIONALLY, so every agent start used to
        produce a new kind-31000 event and `delegation_id`. Addressable replacement
        prevented outright breakage, but the mandate could neither be checked for
        expiry nor renewed deliberately—only reissued. That made relay-side delegation
        enforcement impractical: an agent started without the owner's key would
        silently stop publishing.

        Lookup uses the “this owner → this agent” COORDINATE (kind 31000,
        `d`=<agent>, author=<owner>). Another owner authorizing the same agent does not
        supply our mandate. Expired mandates and those expiring within
        `renew_before_days` are replaced. Mandates are deliberately short-lived as a
        second boundary after revocation; without early renewal an agent would
        eventually go silent without explanation.
        """
        found = await self.relay.query(
            {"kinds": [types.KIND_DELEGATION], "authors": [user_keys.pubkey_hex],
             "#d": [self.pubkey]})
        horizon = int(time.time()) + renew_before_days * 86400
        # A revoked mandate cannot be reused: the relay rejects everything under it
        # as “revoked by its owner,” while the SDK hint recommends ensure_registered,
        # which used to return the same revoked ID. This loop was found by an MCP probe
        # on 2026-09-04. The owner is present with its key here, so reauthorization is
        # legitimate: issue a new delegation with created_at later than the revocation.
        revocations = await self.relay.query(
            {"kinds": [types.KIND_DELEGATION_REVOCATION],
             "authors": [user_keys.pubkey_hex], "#d": [self.pubkey]})
        for ev in found:
            if ev.pubkey != user_keys.pubkey_hex:
                continue                      # Do not trust server-side filtering.
            if ev.tag_value("delegate") != self.pubkey:
                continue
            try:
                expiration = ev.expiration()
            except ValueError:
                continue
            if expiration is None or expiration <= horizon:
                continue
            if any(r.pubkey == user_keys.pubkey_hex and dlg.is_revocation_valid(r, ev)
                   for r in revocations):
                continue                      # Revoked; a new mandate is required.
            # Copy the exact existing mandate to newly configured nodes.
            from .publications import check_and_copy_existing_mandate
            evidence = await check_and_copy_existing_mandate(self, ev)
            # Bounded per-node reads may reveal a revocation hidden by fan-out.
            # Preserve its timestamp when the owner explicitly reauthorizes us.
            revocations.extend(evidence.revocations)
            if not evidence.usable:
                continue
            self.delegation_id = ev.id
            return ev.id
        # Date the new mandate STRICTLY after the owner's latest revocation; otherwise
        # that revocation covers it too (created_at less than or equal to its own).
        last_revocation = max((r.created_at for r in revocations
                               if r.pubkey == user_keys.pubkey_hex), default=-1)
        return await self.register(user_keys, name, days, not_before=last_revocation + 1)

    async def publish_profile(self, profile: types.AgentProfile) -> str:
        return await self._publish(profile.to_event(self.delegation_id))

    async def get_profile(self, pubkey: str) -> types.AgentProfile | None:
        """Return an agent profile by public key, or None.

        Profiles could once be published but not read: discovering someone required
        already knowing their key and manually parsing the event. This was the same
        publish-without-read failure as the task flow (2026-08-29 audit).
        """
        events = await self.relay.query(
            {"kinds": [types.KIND_AGENT_PROFILE], "authors": [pubkey]})
        # Newest first; at EQUAL times, the lower ID wins as NIP-01 requires for
        # addressable replacement. One-second resolution easily puts two profile
        # versions in the same slot. Without an explicit rule, whichever version a
        # relay returned first was displayed, producing inconsistent views across
        # relays (2026-08-29 audit).
        for ev in sorted(events, key=lambda e: (-e.created_at, e.id)):
            if ev.pubkey != pubkey:
                continue          # Do not trust server-side filtering.
            profile = _safe_from_event(types.AgentProfile, ev)
            if profile is not None:
                return profile
        return None

    async def find_agents(self, category: str | None = None,
                          capability: str | None = None,
                          language: str | None = None,
                          limit: int = 100) -> list[types.AgentProfile]:
        """Discover agents by profile, which is why profiles are published.

        The query sends ONE narrowest facet to the relay because multiple values for
        one tag mean “or,” not “and.” Remaining facets are checked locally: the relay
        is untrusted and may return extra events, while “supports X” must not return
        agents that do not support X.
        """
        flt: dict = {"kinds": [types.KIND_AGENT_PROFILE], "limit": limit}
        for value in (f"a4a:cap:{capability}" if capability else None,
                      f"a4a:cat:{category}" if category else None,
                      f"a4a:lang:{language}" if language else None):
            if value:
                flt["#t"] = [value]
                break
        out: list[types.AgentProfile] = []
        seen: set[str] = set()
        for ev in await self._query_tolerant(flt):
            if ev.pubkey in seen:
                continue          # Keep one profile per author, newest in the result.
            profile = _safe_from_event(types.AgentProfile, ev)
            if profile is None:
                continue
            if category and profile.category != category:
                continue
            if capability and capability not in profile.capabilities:
                continue
            if language and language not in profile.languages:
                continue
            seen.add(ev.pubkey)
            out.append(profile)
        return out

    # --- Discovery and negotiation ----------------------------------------

    async def publish_intent(self, intent: types.Intent) -> str:
        return await self._publish(intent.to_event(self.delegation_id))

    def _intent_filter(self, category, intent_type, language) -> dict:
        """Build an intent-search filter using ONLY indexable tags.

        Facets are duplicated in the single-character `t` tag (see
        `types.Intent.to_event`) because only our fork indexes multi-character tags,
        while strfry—the dominant network engine—rejects such filters outright. The
        filter therefore includes ONE narrowest facet; multiple values for one tag
        mean “or,” not “and.” `_intent_matches` applies the rest client-side.
        """
        flt: dict = {"kinds": [types.KIND_INTENT]}
        for value in (f"a4a:cat:{category}" if category else None,
                      f"a4a:type:{intent_type}" if intent_type else None,
                      f"a4a:lang:{language}" if language else None):
            if value:
                flt["#t"] = [value]
                break
        return flt

    @staticmethod
    def _without_multichar_tags(flt: dict) -> dict:
        """Remove unindexable tags longer than one character from a filter."""
        return {k: v for k, v in flt.items() if not (k.startswith("#") and len(k) > 2)}

    async def _query_tolerant(self, flt: dict) -> list[Event]:
        """Run a query that tolerates relays without support for our custom tags.

        NIP-01 indexes only SINGLE-character tags, while our fork supports filters
        such as `#category`. A live survey on 2026-08-28 found three foreign-relay
        behaviors: our fork and some relays silently ignore the filter and return
        extra events; khatru returns nothing; **strfry, the dominant network engine,
        rejects the entire query with an error**. Without fallback, discovery would
        fail rather than degrade on most public relays.

        On error, retry without unindexable filters; the existing client-side checks
        discard extras. An empty answer from a relay with its own filter behavior is
        indistinguishable from an honest “nothing found.” That limitation is recorded
        in the compatibility report.
        """
        try:
            return await self.relay.query(flt)
        except RelayError:
            stripped = self._without_multichar_tags(flt)
            if stripped == flt:
                raise
            return await self.relay.query(stripped)

    @staticmethod
    def _intent_matches(intent: types.Intent, category, intent_type, language) -> bool:
        """Validate intent fields client-side.

        Generic relays neither index nor filter multi-character tags
        (`#category`, `#intent_type`, `#language`), so they silently ignore the server
        filter from `_intent_filter` and return every kind-31002 event. The filter is
        still sent because it is harmless and works on A4A relays that index those tags.
        """
        if category and intent.category != category:
            return False
        if intent_type and intent.intent_type != intent_type:
            return False
        if language and intent.language != language:
            return False
        return True

    async def search_intents(self, category=None, intent_type=None, language=None,
                             budget_min=None, budget_max=None,
                             limit: int = 200) -> list[types.Intent]:
        """Return network intents by facet; `limit` controls the relay request.

        A limit is mandatory for safety, not just efficiency. Publishing is free, so
        one spammer can fill the entire result set, while every intent reaching an
        agent costs its owner tokens. A 2026-08-30 measurement returned 1,512 intents
        in one unbounded query; a large public relay would return its full history.

        Budget and remaining facets are applied AFTER the limit. For a narrow budget,
        raising `limit` may be necessary so matching events enter the sample.
        """
        flt = self._intent_filter(category, intent_type, language)
        flt["limit"] = limit
        events = await self._query_tolerant(flt)
        intents = [m for e in events if (m := _safe_from_event(types.Intent, e)) is not None]
        intents = [i for i in intents
                  if self._intent_matches(i, category, intent_type, language)]
        # Relays cannot filter a budget range; NIP-12 tags support exact matching.
        if budget_min is not None:
            intents = [i for i in intents if i.budget_max >= budget_min]
        if budget_max is not None:
            intents = [i for i in intents if i.budget_min <= budget_max]
        return intents

    async def subscribe_intents(self, category=None, intent_type=None, language=None):
        """Subscribe to newly published intents.

        KNOWN LIMITATION: unlike `search_intents`, this has no fallback query without
        unindexable tags. A relay that rejects such a filter (strfry) will reject the
        subscription. `_query_tolerant` handles one-shot search, but streaming retry
        requires restarting the generator. Address this when foreign-relay streaming
        becomes a supported scenario.
        """
        flt = self._intent_filter(category, intent_type, language)
        flt["since"] = int(time.time()) - 60
        async with contextlib.aclosing(self.relay.subscribe(flt)) as events:
            async for ev in events:
                intent = _safe_from_event(types.Intent, ev)
                if intent is None:
                    continue
                if not self._intent_matches(intent, category, intent_type, language):
                    continue
                yield intent

    async def publish_offer(self, offer: types.Offer) -> str:
        return await self._publish(offer.to_event(self.delegation_id))

    async def get_offers(self, intent_id: str, limit: int = 200) -> list[types.Offer]:
        """Return offers for an intent, rechecking the `#intent` filter client-side.

        Our fork indexes multi-character tags, but stock relays do NOT and may
        silently return every offer. As in `search_intents`, client-side validation
        prevents public relays from showing the owner offers addressed to others.
        """
        events = await self._query_tolerant(
            {"kinds": [types.KIND_OFFER], "#e": [intent_id], "limit": limit})
        offers = [m for e in events if (m := _safe_from_event(types.Offer, e)) is not None]
        return [o for o in offers if o.intent_id == intent_id]

    # --- Agreement ---------------------------------------------------------

    def sign_agreement(self, agreement: "types.Agreement") -> str:
        """Create a party's Schnorr signature over `Agreement.digest()`.

        Accept an agreement MODEL rather than ready-made hex. The digest is computed
        here from terms visible to the signer. Previously, the method signed any 32
        supplied bytes, allowing a counterparty-provided “digest” to make an agent
        sign anything, including another event's ID (internal audit finding 6, fixed
        on 2026-09-04 together with the digest's domain tag).
        """
        if not isinstance(agreement, types.Agreement):
            raise TypeError(
                "sign_agreement requires an Agreement: the digest is computed from "
                "its terms; ready-made 32-byte values are not accepted")
        return crypto.sign(agreement.digest(), self.keys.privkey_hex)

    async def publish_agreement(self, agreement: types.Agreement,
                                delegation_b: str | None = None) -> str:
        return await self._publish(
            agreement.to_event(self.delegation_id, delegation_b, publisher=self.pubkey))

    # --- Execution ---------------------------------------------------------

    async def send_task(self, agreement_id: str, description: str,
                        deadline: int, executor: str) -> str:
        """Create a task under an agreement, addressed to `executor`.

        An executor is mandatory; without one the task addresses nobody and cannot be
        found. The `p` tag is the executor's only way to find tasks on a foreign
        relay. The parameter used to be absent entirely, making the whole execution
        flow invisible to the other party (2026-08-29 audit, finding 34).
        """
        if not is_canonical_pubkey(executor):
            raise ValueError(
                "executor must be a 64-character lowercase hexadecimal public key; "
                f"received: {executor!r}")
        task_id = uuid.uuid4().hex
        req = types.TaskRequest(agreement_id=agreement_id, task_id=task_id,
                                description=description, deadline=deadline,
                                executor=executor, content=description)
        await self._publish(req.to_event(self.delegation_id))
        return task_id

    async def update_task_status(self, task_id: str, agreement_id: str,
                                 status: str, progress: int = 0,
                                 content: str = "") -> str:
        st = types.TaskStatus(task_id=task_id, agreement_id=agreement_id,
                              status=status, progress=progress, content=content)
        return await self._publish(st.to_event(self.delegation_id))

    async def submit_task_result(self, task_id: str, agreement_id: str,
                                 result_url: str, content: str = "") -> str:
        res = types.TaskResult(task_id=task_id, agreement_id=agreement_id,
                               result_url=result_url, content=content)
        return await self._publish(res.to_event(self.delegation_id))

    async def _agreement_parties(self, agreement_id: str) -> frozenset[str] | None:
        """Return parties to the MUTUALLY signed `agreement_id`, or None.

        An agreement without both signatures makes nobody a party: `agent_a` and
        `agent_b` tags are trivial to forge, while signatures over the digest are not.
        """
        for ev in await self.relay.query({"ids": [agreement_id]}):
            found = agreement_parties([ev]).get(ev.id)
            if found is not None:
                return found[1]
        return None

    async def _task_events(self, kind: int, agreement_id: str,
                           task_id: str | None) -> list[Event]:
        """Return agreement task-flow events authored ONLY by its parties.

        The SDK originally had no reader: it could publish TaskRequest/Status/Result
        but offered no way to read them. Integrators wrote raw queries and accepted a
        “result” from anyone because relays return every matching event and do not
        check authorization to publish agreement results. The natural “take the first
        result” implementation handed control to an outsider (2026-08-29 audit).
        """
        parties = await self._agreement_parties(agreement_id)
        if parties is None:
            return []
        # Filter on `e` (the agreement ID): every relay indexes single-character tags,
        # while only our fork sees `#agreement`. The `agreement` tag remains in the
        # event and is rechecked below because server-side filtering is untrusted.
        events = await self._query_tolerant({"kinds": [kind], "#e": [agreement_id]})
        out = []
        for ev in events:
            if ev.kind != kind:
                continue
            if ev.pubkey not in parties:
                continue
            if ev.tag_value("agreement") != agreement_id:
                continue   # Do not trust server filtering on multi-character tags.
            if task_id is not None and types._task_id_of(ev) != task_id:
                continue
            out.append(ev)
        return out

    async def get_task_results(self, agreement_id: str,
                               task_id: str | None = None) -> list[types.TaskResult]:
        """Return agreement task results only from its parties; see `_task_events`."""
        return [model
                for ev in await self._task_events(types.KIND_TASK_RESULT,
                                                  agreement_id, task_id)
                if (model := _safe_from_event(types.TaskResult, ev)) is not None]

    async def get_task_statuses(self, agreement_id: str,
                                task_id: str | None = None) -> list[types.TaskStatus]:
        """Return agreement task statuses only from its parties; see `_task_events`."""
        return [model
                for ev in await self._task_events(types.KIND_TASK_STATUS,
                                                  agreement_id, task_id)
                if (model := _safe_from_event(types.TaskStatus, ev)) is not None]

    # --- Reputation --------------------------------------------------------

    async def get_agreements(self, counterparty: str | None = None
                             ) -> list[types.Agreement]:
        """Return agreements in which WE are a party.

        One party publishes an agreement, but both must know about it, so the other
        must discover it on the network. Before 2026-08-29 there was no public way to
        do so. The end-to-end example worked only because both agents lived in one
        process and passed the agreement ID through a Python variable (finding 34).

        `counterparty` restricts results to agreements with that partner.
        """
        events = await self._agreements_of(self.pubkey)
        # Agreement identity is the terms digest, not the event ID. At least two
        # events represent one agreement: a proposal with one signature and the
        # completed version with two. Returning both asks the owner which is real.
        by_digest: dict[str, types.Agreement] = {}
        for ev in sorted(events, key=lambda e: e.created_at, reverse=True):
            model = _safe_from_event(types.Agreement, ev)
            if model is None:
                continue
            other = model.agent_b if model.agent_a == self.pubkey else model.agent_a
            if counterparty is not None and other != counterparty:
                continue
            try:
                key = model.digest()
            except (ValueError, TypeError):
                continue
            kept = by_digest.get(key)
            # A completed version always replaces a proposal; among equals, the
            # newest wins because events are already time-sorted.
            if kept is None or (model.verify_signatures()
                                and not kept.verify_signatures()):
                by_digest[key] = model
        return list(by_digest.values())

    async def co_sign_agreement(self, agreement: types.Agreement,
                                counterparty_delegation: str | None = None) -> str:
        """Co-sign an agreement proposed to us and publish its COMPLETE version.

        An agreement is valid only with MUTUAL signatures. A unilateral event makes
        nobody a party because `agent_a`/`agent_b` tags are trivial to forge while
        digest signatures are not. The first party publishes its signature; the
        second discovers it through `get_agreements` and signs here.

        Before 2026-08-29 neither the SDK nor MCP exposed this step, so there was no
        way to obtain the second signature and two INDEPENDENT agents could not form
        an agreement. The end-to-end example worked only because both lived in one
        process (finding 35).

        A complete agreement needs both party mandates. The counterparty mandate
        defaults to the verified proposal's source metadata; callers constructing
        an Agreement directly must supply it. Our current mandate must be set.
        Return the new agreement event ID, which subsequent events must reference.
        """
        if self.pubkey not in (agreement.agent_a, agreement.agent_b):
            raise ValueError("agreement does not include us: our key is not named as a party")
        i_am_a = agreement.agent_a == self.pubkey
        ours, theirs = ((agreement.sig_a, agreement.sig_b) if i_am_a
                        else (agreement.sig_b, agreement.sig_a))
        if ours:
            if not crypto.verify(agreement.digest(), ours, self.pubkey):
                # The slot is ours but the signature is not. An external review on
                # 2026-09-04 found that sig_b signed by key A was read as “our
                # signature is already present.” This is forgery or a foreign key;
                # neither signing nor retrying may complete such an agreement.
                raise ValueError(
                    "the signature in your slot is invalid: it does not match your key; "
                    "the proposal is forged or signed by another key. Ask the counterparty "
                    "to republish the agreement with your slot empty")
            raise ValueError("our agreement signature is already present")
        if not theirs:
            raise ValueError("the agreement has no counterparty signature to co-sign")
        digest = agreement.digest()
        other = agreement.agent_b if i_am_a else agreement.agent_a
        if not crypto.verify(digest, theirs, other):
            # Verify the counterparty before adding our signature; otherwise our
            # signature would attest to terms they did not sign.
            raise ValueError("counterparty signature does not match the agreement terms")
        # A one-signature proposal remains on the relay and can be co-signed repeatedly,
        # producing a NEW event with the same digest each time. Parties would then see
        # separate agreements with different IDs: tasks reference one and reviews the
        # other. First check whether this agreement already exists, using the terms
        # digest rather than the event ID as identity.
        for existing in await self._agreements_of(self.pubkey):
            model = _safe_from_event(types.Agreement, existing)
            if (model is not None and model.verify_signatures()
                    and model.digest() == digest):
                return existing.id
        if counterparty_delegation is None and agreement.source is not None:
            source = agreement.source
            original = _safe_from_event(types.Agreement, source)
            if (original is not None and source.verify() and source.pubkey == other
                    and original.digest() == digest):
                counterparty_delegation = source.tag_value(
                    "delegation_b" if i_am_a else "delegation_a") or source.delegation_ref()
        if not self.delegation_id:
            raise ValueError("a publisher delegation is required before co-signing an agreement")
        if not counterparty_delegation:
            raise ValueError("a counterparty delegation is required; supply it or use a verified proposal with its mandate")
        signed = agreement.model_copy(update=(
            {"sig_a": self.sign_agreement(agreement)} if i_am_a
            else {"sig_b": self.sign_agreement(agreement)}))
        # This is an assertion, not input validation. The counterparty signature was
        # checked above and ours was just produced. Mutation testing confirmed the
        # branch is unreachable through input alone. Keep it so a future signing or
        # digest regression fails loudly instead of publishing an invalid agreement.
        if not signed.verify_signatures():
            raise ValueError("agreement still fails verification after co-signing")
        return await self.publish_agreement(
            signed, delegation_b=counterparty_delegation)

    async def get_tasks(self, agreement_id: str | None = None
                        ) -> list[types.TaskRequest]:
        """Return tasks assigned to US.

        This was the other half of the same gap: an agent that accepted work could not
        learn that it had been assigned. The author is checked against the agreement;
        only a party may create its task, or any stranger's message becomes a task.
        """
        events = await self._query_tolerant(
            {"kinds": [types.KIND_TASK_REQUEST], "#p": [self.pubkey]})
        out: list[types.TaskRequest] = []
        parties_cache: dict[str, set[str] | None] = {}
        for ev in sorted(events, key=lambda e: e.created_at, reverse=True):
            model = _safe_from_event(types.TaskRequest, ev)
            if model is None or model.executor != self.pubkey:
                continue          # Do not trust server-side filtering on `p`.
            if agreement_id is not None and model.agreement_id != agreement_id:
                continue
            if model.agreement_id not in parties_cache:
                parties_cache[model.agreement_id] = await self._agreement_parties(
                    model.agreement_id)
            parties = parties_cache[model.agreement_id]
            if not parties or ev.pubkey not in parties or self.pubkey not in parties:
                continue
            out.append(model)
        return out

    async def publish_review(self, agreement_id: str, target: str, rating: int,
                             content: str = "") -> str:
        review = types.Review(agreement_id=agreement_id, target=target,
                              rating=rating, content=content)
        return await self._publish(review.to_event(self.delegation_id))

    async def publish_trust(self, trusted_pubkey: str, weight: float,
                            reason: str = "") -> str:
        """Publish a kind-31020 TrustAssertion.

        It states “I trust `trusted_pubkey` with `weight` in [0, 1].” This Web of
        Trust edge affects how reviews are WEIGHTED by
        `get_reputation(..., weighted=True)`.
        """
        ta = types.TrustAssertion(trusted=trusted_pubkey, weight=weight, reason=reason)
        return await self._publish(ta.to_event(self.delegation_id))

    async def attest_identity(self, subject_pubkey: str, level: str, name: str = "",
                              issuer_name: str = "", expiration: int = 0) -> str:
        """Issue a kind-31021 identity attestation for `subject_pubkey`.

        The ISSUER (verifier) signs with its OWN key to state that the key's controller
        is verified at `level` (email, phone, gov_id, business, and so on). Disclose
        `name` only with the subject's consent; this is selective disclosure, not a
        passport. The event is addressable, so reissuance by the same issuer replaces
        its earlier attestation.
        """
        att = types.IdentityAttestation(
            subject=subject_pubkey, level=level, name=name,
            issuer_name=issuer_name, expiration=expiration)
        return await self._publish(att.to_event(self.delegation_id))

    async def get_identity(self, pubkey: str,
                           trusted_issuers: list[str] | None = None,
                           include_self_issued: bool = False) -> list[dict]:
        """Return valid kind-31021 identity attestations for `pubkey`.

        `trusted_issuers` lists issuer public keys trusted by the caller. None returns
        every valid attestation, leaving issuer trust to caller policy/Web of Trust.
        Self-issued attestations (issuer equals subject) are excluded by default;
        `include_self_issued=True` returns them marked `self_issued`.

        Return dictionaries with issuer, level, name, issuer_name, self_issued,
        trusted, and event. `trusted` records an actual trust decision and is true
        only for entries in `trusted_issuers`. Without it, a UI must not present the
        level as verified because anyone can attest to themselves from a second key.
        """
        events = await self.relay.query(
            {"kinds": [types.KIND_IDENTITY_ATTESTATION], "#p": [pubkey]})
        result = []
        for ev in events:
            if not identity.verify_identity_attestation(
                    ev, pubkey, allow_self_issued=include_self_issued):
                continue
            if trusted_issuers is not None and ev.pubkey not in trusted_issuers:
                continue
            att = _safe_from_event(types.IdentityAttestation, ev)
            if att is None:
                continue
            result.append({"issuer": ev.pubkey, "level": att.level, "name": att.name,
                           "issuer_name": att.issuer_name,
                           "self_issued": identity.is_self_issued(ev),
                           "trusted": trusted_issuers is not None
                           and ev.pubkey in trusted_issuers,
                           "event": ev})
        return result

    async def request_connection(self, to_pubkey: str, intro: str = "") -> str:
        """Request a connection with `to_pubkey` using kind 31022.

        This is a lightweight “I propose interacting” signal with a short introduction
        sent BEFORE expensive communication. A mutual request establishes the
        connection (`is_connected`), avoiding owner credits spent on full dialogue
        with arbitrary strangers.
        """
        cr = types.ConnectionRequest(to_pubkey=to_pubkey, intro=intro)
        return await self._publish(cr.to_event(self.delegation_id))

    async def accept_connection(self, from_pubkey: str, intro: str = "") -> str:
        """Accept `from_pubkey` by publishing a reciprocal connection request."""
        return await self.request_connection(from_pubkey, intro)

    async def get_connection_requests(self, limit: int = 200) -> list[dict]:
        """Return incoming requests (`#p` is us) as from_pubkey, intro, and event."""
        events = await self.relay.query(
            {"kinds": [types.KIND_CONNECTION_REQUEST], "#p": [self.pubkey],
             "limit": limit})
        # The request is addressed by `d`=recipient: the “sender → us” pair has one
        # meaningful version and NIP-33 requires the relay to replace the old one. The
        # relay is untrusted, however, and events may predate that policy or arrive via
        # synchronization. Returning every version would make the owner handle one
        # person twice, with duplicate notices and replies (2026-08-29 audit, finding 37).
        newest: dict[str, tuple[int, str, dict]] = {}
        for ev in events:
            cr = _safe_from_event(types.ConnectionRequest, ev)
            if cr is None or cr.to_pubkey != self.pubkey:   # Recheck an untrusted relay.
                continue
            item = {"from_pubkey": ev.pubkey, "intro": cr.intro, "event": ev}
            kept = newest.get(ev.pubkey)
            # Newest wins; at EQUAL times, lower ID wins as NIP-01 requires for
            # replacement. Without an explicit rule, the relay's output order would
            # choose which version is shown.
            better = (kept is None
                      or ev.created_at > kept[0]
                      or (ev.created_at == kept[0] and ev.id < kept[1]))
            if better:
                newest[ev.pubkey] = (ev.created_at, ev.id, item)
        return [v[2] for v in newest.values()]

    async def disconnect(self, pubkey: str) -> str | None:
        """Disconnect by deleting OUR connection requests to `pubkey` via NIP-09.

        A connection exists when both parties request each other, and policy treats it
        as the strongest signal—stronger than attestations or reputation. Yet there
        was no method to withdraw consent, and the only technical mechanism was not
        exposed. A counterparty later found malicious remained authorized forever
        (2026-08-29 internal audit).

        Only OUR event is deleted. The peer's event cannot be hidden, which is correct:
        disconnection is unilateral, while “connected” requires both parties' consent.

        WARNING: deletion affects only relays that receive it. A relay that misses the
        deletion continues to consider the connection established. This is a Nostr
        property, not an implementation defect. Publish the deletion wherever the
        request was published.

        Return the deletion event ID, or None when there was nothing to delete.
        """
        mine = await self.relay.query(
            {"kinds": [types.KIND_CONNECTION_REQUEST],
             "authors": [self.pubkey], "#p": [pubkey]})
        ids = [e.id for e in mine
               if e.pubkey == self.pubkey and e.tag_value("p") == pubkey]
        if not ids:
            return None
        deletion = Event(kind=5, tags=[["e", i] for i in ids],
                         content="connection terminated")
        deletion.sign(self.keys)
        await self._broadcast(deletion)
        return deletion.id

    async def is_connected(self, pubkey: str) -> bool:
        """Return True for a MUTUAL connection: each party requested the other."""
        mine = await self.relay.query(
            {"kinds": [types.KIND_CONNECTION_REQUEST],
             "authors": [self.pubkey], "#p": [pubkey]})
        theirs = await self.relay.query(
            {"kinds": [types.KIND_CONNECTION_REQUEST],
             "authors": [pubkey], "#p": [self.pubkey]})
        # Do not trust server-side filtering; recheck author and the `p` tag.
        mine_ok = any(e.pubkey == self.pubkey and e.tag_value("p") == pubkey for e in mine)
        theirs_ok = any(e.pubkey == pubkey and e.tag_value("p") == self.pubkey for e in theirs)
        return mine_ok and theirs_ok

    async def get_counterparty_evidence(self, pubkey: str, *, window_days: int = 30,
                                        limit: int = 200, reviewer_limit: int = 5,
                                        trusted_issuers=()) -> dict:
        """Read bounded public evidence, not a fraud score or verified-person count.

        Queries every configured relay, not just the first, and merges the answers.
        The lookup is therefore visible to each of them; `coverage` reports how many
        were configured and how few actually answered. Completeness, device recovery
        and physical controller identity remain unknown. No publication or KYC calls.
        """
        from .evidence_reader import read_counterparty_evidence
        return await read_counterparty_evidence(self.relay, pubkey, window_days=window_days,
            limit=limit, reviewer_limit=reviewer_limit, trusted_issuers=trusted_issuers)

    async def get_reputation(self, pubkey: str, weighted: bool = False,
                             require_agreement: bool = True,
                             trust_graph: dict | None = None) -> Reputation:
        """Compute review-based reputation with one vote per author.

        **The default has been strict since 2026-09-05, for a measurable reason.**
        Previously, `require_agreement=False` counted every review. In staging, ten
        disposable keys and twenty events took **21 seconds** to reduce an honest
        agent's reputation from 5.0/5 to **1.4/5** for any caller using defaults. The
        MCP tool was strict by default while the library was not, protecting our agent
        but not external implementations using the same SDK. Safe behavior must be the
        default, not a reward for careful reading.

        `require_agreement=True` verifies a review's link to a signed agreement. Only
        reviews from parties to a mutually signed kind-31004 Agreement with the
        subject count. Manipulating the rating then requires the subject key's
        unforgeable agreement signature. A controller of two keys can still sign
        fictitious agreements; this does not prevent collusion.

        `weighted=True` applies the **Web of Trust**: THIS agent's trust in the author
        (kind 31020, specification §15) weights the review; a stranger weighs 0.1.
        WARNING: weighting alone is NOT Sybil-resistant because a stranger has
        positive weight and key count is unlimited (2026-08-17 audit, F1). Use
        `require_agreement=True` against reviews without an agreed transaction. It
        still does not prove participant independence or real-world performance.

        `get_delivery_reputation()` provides the behavioral delivery signal.
        """
        reviews = await self.relay.query(
            {"kinds": [types.KIND_REVIEW], "#p": [pubkey]})
        agreements = await self._agreements_of(pubkey) if require_agreement else None
        if not weighted:
            return compute_reputation(reviews, agreements=agreements,
                                      subject=pubkey)
        # A prebuilt graph may be supplied because it is global and independent of the
        # subject. Downloading it per subject amplifies load (2026-08-28 review, A11).
        if trust_graph is None:
            assertions = await self.relay.query(
                {"kinds": [types.KIND_TRUST_ASSERTION]})
            trust_graph = build_trust_graph(assertions)
        return compute_reputation(reviews, trust_graph=trust_graph, me=self.pubkey,
                                  agreements=agreements, subject=pubkey)

    async def _agreements_of(self, pubkey: str) -> list[Event]:
        """Return kind-31004 agreements naming `pubkey` as agent_a or agent_b.

        `agreement_parties` rechecks parties and signatures locally, so server-side
        filtering need not be trusted. A relay without multi-character tag support
        returns extra events rather than omitting required ones.
        """
        events = await self._query_tolerant(
            {"kinds": [types.KIND_AGREEMENT], "#p": [pubkey]})
        found: dict[str, Event] = {}
        for ev in events:
            # Read parties from SIGNED fields, not the `p` tag. That tag is only a
            # discovery address and an untrusted relay may return anything for it.
            if pubkey in (ev.tag_value("agent_a"), ev.tag_value("agent_b")):
                found[ev.id] = ev
        return list(found.values())

    async def get_completion_reputation(self, pubkey: str, *,
                                        weighted: bool = False) -> CompletionReputation:
        """Measure completed agreements as “3 of 4,” not 0.75 (specification §2.3.1).

        The denominator is mutually signed agreements whose deadlines have PASSED and
        where the agent is a party. The numerator is those for which it published a
        kind-31032 result. An unfinished future-deadline agreement says nothing and is
        excluded.

        This is harder to corrupt than reviews: an agreement needs two signatures, so
        the denominator remains under the agent's control. Reviews can reduce another
        agent from 5.0 to 1.4 in 21 seconds (2026-09-05 measurement), which motivated
        this metric.

        `weighted=True` counts only counterparties reachable through THIS agent's
        trust graph. Without a graph, self-dealing is indistinguishable from real
        transactions: an agent creates keys, contracts with them, and publishes the
        results itself. See `CompletionReputation` for remaining boundaries.

        Query the network DIRECTLY by key instead of using `get_agreements`, which is
        intentionally limited to the caller's own agreements and cannot serve a
        third-party reader (§2.3.1.4).
        """
        agreements = await self.relay.query(
            {"kinds": [types.KIND_AGREEMENT], "#p": [pubkey]})
        results = await self.relay.query(
            {"kinds": [types.KIND_TASK_RESULT], "authors": [pubkey]})
        graph = None
        if weighted:
            assertions = await self.relay.query({"kinds": [types.KIND_TRUST_ASSERTION]})
            graph = build_trust_graph(assertions)
        return compute_completion_reputation(
            agreements, results, agent=pubkey,
            trust_graph=graph, me=self.pubkey if weighted else None)

    async def get_delivery_reputation(self, pubkey: str, *,
                                      weighted: bool = False) -> DeliveryReputation:
        """Compute verifiable-delivery reputation (P2) from processed-ACK share.

        This measures how reliably an agent receives and processes addressed messages.
        `weighted=True` counts only senders trusted by THIS agent, using its own
        kind-31020 assertions. Weighting is strongly recommended for decisions: the
        denominator contains EVERY addressed message, and becoming a recipient needs
        no consent, so without a graph any stranger can lower another agent's score
        with spam (2026-08-29 audit). Per-sender influence is bounded but not removed.
        """
        messages = await self.relay.query(
            {"kinds": [types.KIND_PRIVATE_MESSAGE], "#p": [pubkey]})
        acks = await self.relay.query(
            {"kinds": [types.KIND_ACK_RECEIPT], "authors": [pubkey]})
        if not weighted:
            return compute_delivery_reputation(messages, acks, agent=pubkey)
        assertions = await self.relay.query({"kinds": [types.KIND_TRUST_ASSERTION]})
        return compute_delivery_reputation(
            messages, acks, agent=pubkey,
            trust_graph=build_trust_graph(assertions), me=self.pubkey)

    # --- Private messages (NIP-44) -----------------------------------------

    @staticmethod
    def _expiration_tag(expires_in: int | None) -> list[list[str]]:
        """Build a lifetime tag; `expires_in=0` means indefinite retention."""
        if expires_in is not None and expires_in < 0:
            # A negative lifetime makes the event expired at publication. Our relay
            # rejects it with an opaque transport error; a foreign relay may accept and
            # immediately delete it, silently losing the message (2026-08-28 review, S6).
            raise ValueError(f"expires_in cannot be negative: {expires_in}")
        ttl = PRIVATE_TTL_SECONDS if expires_in is None else expires_in
        return [["expiration", str(int(time.time()) + ttl)]] if ttl else []

    def _build_private_message(self, to_pubkey: str, content: str,
                               delivery_id: str,
                               expires_in: int | None = None) -> Event:
        """Build, but do not publish, an encrypted addressable message.

        `delivery_id` is stored in the `d` tag. Kind 31033 is addressable (NIP-33),
        so without a unique `d` the relay would replace this sender's previous
        message. A stable delivery ID across retries makes the relay replace the
        previous attempt, lets the recipient deduplicate, and gives P1 ACKs a target.
        """
        encrypted = nip44.encrypt(content, self.keys.privkey_hex, to_pubkey)
        tags = [["p", to_pubkey], ["d", delivery_id]]
        tags += self._expiration_tag(expires_in)
        if self.delegation_id:
            tags.append(["delegation", self.delegation_id])
        return Event(kind=types.KIND_PRIVATE_MESSAGE, tags=tags, content=encrypted)

    async def send_private_message(self, to_pubkey: str, content: str,
                                   delivery_id: str | None = None,
                                   wrap: bool = True,
                                   expires_in: int | None = None,
                                   conversation_id: str | None = None,
                                   reply_to: tuple[str, ...] | None = None) -> str:
        """Send a private message to `to_pubkey` and return the inner event ID.

        The `delivery_id` (`d` tag) is random by default. Use `deliver_with_ack()`
        for reliable delivery.

        `wrap=True` (THE DEFAULT since 2026-08-29) applies a **NIP-59 gift wrap** to
        hide metadata. The old default exposed the SOCIAL GRAPH: anyone reading the
        relay saw the author-recipient pair even with encrypted content. Hiding it
        required an explicit flag, so only callers already aware of the issue used it,
        and MCP offered no choice. The measured cost is a short message growing from
        176 to 2,140 bytes; traffic is not the network bottleneck (specification §2.8,
        retention policy).

        `wrap=False` sends kind 31033 with NIP-44 v2 (ChaCha20+HMAC-SHA256) encrypted
        content, BUT the relay sees the `(author, to_pubkey)` metadata. This remains an
        explicit compatibility option for implementations that read only kind 31033.
        `wrap=True` hides metadata with NIP-59: the relay sees only an envelope from a
        random ephemeral key to the recipient, hiding the sender and time. The inner
        kind-14 message is signed by the sender and plaintext INSIDE the envelope, so
        `reveal()` can later publish it as self-verifying dispute evidence. The
        recipient is always visible because delivery otherwise is impossible.
        """
        receipt = await self.send_private_message_receipt(
            to_pubkey, content, delivery_id=delivery_id, wrap=wrap,
            expires_in=expires_in, conversation_id=conversation_id,
            reply_to=reply_to)
        return receipt["inner_id"]

    def prepare_private_message(self, to_pubkey: str, content: str,
                                delivery_id: str | None = None,
                                wrap: bool = True,
                                expires_in: int | None = None,
                                conversation_id: str | None = None,
                                reply_to: tuple[str, ...] | None = None) -> tuple[Event, Event, str]:
        """Return signed (inner, outer, delivery_id) without any network access.

        Parameters and formats match `send_private_message`. Publish the exact
        outer event via `_broadcast`, not `_publish`, which would re-sign it.
        With `wrap=False`, inner and outer are the same encrypted event; its
        addressable timestamp is reserved before signing, even if never sent.

        `reply_to=(delivery_id, inner_id)` names the letter this one answers. It is
        signed into the rumor so the recipient can match it against its own journal;
        on a plain event it would expose the thread, so like `conversation_id` it
        requires the gift wrap.
        """
        to_pubkey = Keys.normalize_pubkey(to_pubkey)
        if not is_canonical_pubkey(to_pubkey):
            # Otherwise an internal detail leaked out: “could not compute ECDH:
            # non-hexadecimal number found.” It did not tell the caller that the input
            # simply was not a key (2026-08-29 audit).
            raise ValueError(
                "recipient pubkey must be 64 lowercase hexadecimal characters; "
                f"received: {to_pubkey!r}")
        if conversation_id is not None:
            if (not isinstance(conversation_id, str)
                    or re.fullmatch(r"[0-9a-f]{64}", conversation_id) is None):
                raise ValueError("conversation_id must be 64 lowercase hexadecimal characters")
            if not wrap:
                raise ValueError("conversation_id requires gift wrapping to hide routing metadata")
        if reply_to is not None:
            _check_reply_to(reply_to)
            if not wrap:
                raise ValueError("reply_to requires gift wrapping to hide the thread")
        if delivery_id is None:
            delivery_id = uuid.uuid4().hex
        elif not delivery_id:
            raise ValueError("delivery_id cannot be empty")
        if not wrap:
            ev = self._build_private_message(to_pubkey, content, delivery_id,
                                             expires_in)
            self._bump_created_at(ev)
            ev.sign(self.keys)
            return ev, ev, delivery_id
        tags = [["p", to_pubkey], ["d", delivery_id]]
        if conversation_id is not None:
            tags.append(["a4a_conversation", conversation_id])
        if reply_to is not None:
            tags.append(["a4a_reply", reply_to[0], reply_to[1]])
            if len(reply_to) == 4:
                tags.append(["a4a_routed_via", reply_to[2], reply_to[3]])
        if self.delegation_id:
            tags.append(["delegation", self.delegation_id])
        inner = Event(kind=types.KIND_PRIVATE_RUMOR, tags=tags, content=content)
        inner.sign(self.keys)
        # Put the lifetime on the ENVELOPE because that is what the relay stores; it
        # never stores the inner event. Supply the tag BEFORE signing because adding
        # it later would invalidate the envelope signature.
        gw = giftwrap.wrap(inner, to_pubkey, self.keys,
                           extra_tags=self._expiration_tag(expires_in))
        return inner, gw, delivery_id

    async def send_private_message_receipt(self, to_pubkey: str, content: str,
                                           delivery_id: str | None = None,
                                           wrap: bool = True,
                                           expires_in: int | None = None,
                                           conversation_id: str | None = None,
                                           reply_to: tuple[str, ...] | None = None) -> dict:
        """Send a message and return inner_id, outer_id, delivery_id, and status.

        Parameters and signed formats match `send_private_message`.
        `status="relay_accepted"` means AT LEAST ONE configured relay accepted the
        event, NOT that the recipient received or processed it. Rejection by all relays
        raises; partial rejection does not, and the response does not expose how many
        failed. Older documentation referred to a “primary relay,” but fan-out has a
        set with no primary. `outer_id` identifies the published envelope and
        `inner_id` the message used for ACKs. With `wrap=False` they are equal. The
        message is published exactly once.
        """
        inner, outer, delivery_id = self.prepare_private_message(
            to_pubkey, content, delivery_id=delivery_id, wrap=wrap,
            expires_in=expires_in, conversation_id=conversation_id,
            reply_to=reply_to)
        await self._broadcast(outer)
        return {"inner_id": inner.id, "outer_id": outer.id, "delivery_id": delivery_id,
                "status": "relay_accepted"}

    async def send_file(self, to_pubkey: str, *, url: str, sha256: str, key: str = "",
                        name: str = "", mime: str = "", size: int = 0,
                        wrap: bool = True, delivery_id: str | None = None,
                        enc: str = files.FILE_ENCRYPTION) -> str:
        """Send an encrypted-file REFERENCE in a private message (§2.6).

        Sender path: `blob, key = files.encrypt_file(data)`; upload `blob` to storage
        (IPFS/Arweave/HTTPS—the SDK does not access it); pass `url`,
        `files.sha256_hex(blob)`, `key`, and metadata here. The per-file random key
        travels inside this NIP-44 message, gift-wrapped by default. File contents
        stay encrypted; the relay still sees recipient/envelope metadata and storage
        sees size/request metadata. A configured gateway records both parties and
        upload/fetch times. Encryption does not promise metadata anonymity.

        Recipient path: `read_private_messages()`;
        `files.parse_file_reference(content)` (None for an invalid scheme, host, or
        hash); `files.resolve_download_target(url)`; connect to the RETURNED address
        while using the hostname for `Host` and certificate verification. Otherwise
        the HTTP client resolves again and DNS may change between checking and the
        request—the DNS rebinding attack. Download and call
        `files.open_file(blob, ref)` to verify SHA-256 and decrypt.

        `enc` names the reference scheme. The signature makes the default explicit:
        supplying `key` means our `files.FILE_ENCRYPTION` unless overridden. For a
        blob encrypted by another scheme, pass its name or the recipient will try ours
        and reject it. Without a key, `enc` is always empty: there is no encryption to
        declare. The key shape is deliberately not guessed; hidden protocol heuristics
        are worse than explicit rules. Gift wrapping hides metadata by default because
        a file reference is still a private message and need not reveal who sends to
        whom. `wrap=False` is an explicit compatibility choice; see
        `send_private_message`.
        """
        if not key:
            # A keyless reference leaves the stored file public. Do not reject because
            # callers may intentionally send public links, but never stay silent. A
            # 2026-08-30 measurement found a sender following the README distributing
            # plaintext files with no warning.
            log.warning(
                "send_file called without a key: the stored file is NOT encrypted and "
                "is available to the storage provider and anyone who learns its address. "
                "Encrypt it with files.encrypt_file(data) and pass the returned `key`")
        content = files.build_file_reference(url, sha256, key, name, mime, size,
                                             enc=enc if key else "")
        return await self.send_private_message(
            to_pubkey, content, delivery_id=delivery_id, wrap=wrap)

    async def read_private_messages(self, since: int | None = None) -> list[dict]:
        """Return incoming private messages, both plain-encrypted and gift-wrapped.

        Read kind 31033 (`#p` is our public key, NIP-44 decryption) and unwrap
        kind-1059 gift wraps, which carry metadata-private messages. Each item has
        from_pubkey, content, event, wrapped, inner_id, outer_id, delivery_id, and
        outer_event. `event` is the inner event and `outer_event` the published Event;
        without wrapping they are the same. `delivery_id` is the inner event's `d`
        tag, or None. Corrupt, misaddressed, and forged input is silently skipped
        because untrusted input must not fail the whole call.

        Repeated copies are discarded by inner event ID. One rumor may be wrapped in
        arbitrarily many envelopes, each with a new ephemeral key, while every
        duplicate costs the receiving agent (audit F6). WARNING: deduplication applies
        WITHIN ONE CALL. The SDK remembers nothing across calls; callers must persist
        “already processed” state, as `deliver_with_ack` does with `delivery_id`.

        `since` is a Unix time restricting reads to newer messages. Public addresses
        need this; otherwise every poll downloads the entire inbox history and service
        cost grows with incoming junk. For gift wraps the window automatically expands
        by the `created_at` jitter (up to two days into the past), preventing fresh
        wrapped messages from being omitted.

        WARNING: **the caller owns the processed-message journal.** Because this
        deduplication lasts only for one call, a “read, acknowledge” loop without
        persistence rereads the same window and sends a receipt every time. A
        2026-09-04 measurement found a naive recipient sending 2,762 duplicate
        kind-31034 receipts for 200 deliveries. This is neither delivery loss nor
        duplicate delivery, but wasted relay and owner resources. `ProcessedLog` in
        `agent-service` is the reference: a set of processed IDs that survives restart.
        """
        messages = []
        seen: set[str] = set()
        flt = {"kinds": [types.KIND_PRIVATE_MESSAGE], "#p": [self.pubkey]}
        if since is not None:
            flt["since"] = since
        for ev in await self.relay.query(flt):
            msg = self._decode_incoming(ev)
            if msg is None or msg["event"].id in seen:
                continue
            seen.add(msg["event"].id)
            messages.append(msg)
        # Gift-wrapped (metadata-private) messages carry a kind-14 inner rumor. Query
        # them separately because their `since` window expands by the timestamp jitter;
        # see `_unwrap_inbox`.
        flt = {"kinds": [giftwrap.KIND_GIFT_WRAP], "#p": [self.pubkey]}
        if since is not None:
            flt["since"] = since - giftwrap._JITTER_SECONDS
        for outer in await self.relay.query(flt):
            msg = self._decode_incoming(outer)
            if msg is None or msg["event"].id in seen:
                continue
            seen.add(msg["event"].id)
            messages.append(msg)
        # Results from two queries are merged. Before 2026-09-08 their order was
        # arbitrary: every plain message, then every envelope, each group in relay
        # order. A caller taking the “latest N” got an arbitrary N. A neighboring
        # agent consequently missed a fresh message when its tool showed 10 of 36 and
        # selected an old one instead of the new one.
        #
        # Sort by INNER event time. NIP-59 deliberately jitters envelope `created_at`
        # by up to two days, making it unsuitable for ordering, while the inner event
        # carries the sender's actual claimed time. This is author-declared, not
        # attested by the relay: it is suitable for display, but calculations that
        # need reception order must use relay-history `first_seen`.
        #
        # Sort ONLY by time, with no secondary key. The first implementation added the
        # event ID “for determinism,” which was wrong: an ID is a hash and therefore an
        # arbitrary order. It reordered two same-second messages and made the rewrapped
        # envelope deduplication test flaky.
        #
        # State the stability guarantee precisely: at equal times, Python preserves
        # ENUMERATION order—the order produced by the two queries and relays—not a
        # measured relay reception order. Time here is author-declared. Consumers that
        # need reception order must use relay-history `first_seen`, not this sorting.
        messages.sort(key=lambda m: m["event"].created_at)
        return messages

    def _decode_incoming(self, ev: Event) -> dict | None:
        """Decode one incoming event, or return None when it is not our message.

        Shared by batch reads and subscriptions: decrypt kind 31033 and unwrap gift
        wraps. This belongs in the SDK; otherwise every integration moving from polls
        to subscriptions would reimplement cryptography.
        """
        def addressed_to_me(event: Event) -> bool:
            recipients = [tag for tag in event.tags if tag and tag[0] == "p"]
            return (len(recipients) == 1 and len(recipients[0]) >= 2
                    and recipients[0][1] == self.pubkey)

        # Input may bypass RelayClient, so verify its signature and single recipient,
        # including empty or repeated `p` tags.
        if not ev.verify_protocol() or not addressed_to_me(ev):
            return None
        if any(tag and tag[0] in types.ORGANIZATION_ONLY_PRIVATE_TAGS
               for tag in ev.tags):
            return None  # Logical route metadata must not leak on an outer event.
        if ev.kind == types.KIND_PRIVATE_MESSAGE:
            if any(tag and tag[0] == "a4a_conversation" for tag in ev.tags):
                return None  # Conversation routing metadata must never be public.
            try:
                content = nip44.decrypt(ev.content, self.keys.privkey_hex, ev.pubkey)
            except nip44.Nip44Error:
                return None
            return {"from_pubkey": ev.pubkey, "content": content,
                    "event": ev, "wrapped": False,
                    "inner_id": ev.id, "outer_id": ev.id,
                    "delivery_id": ev.tag_value("d"), "outer_event": ev,
                    "conversation_id": None, "reply_to": None,
                    "signed_at": ev.created_at}
        if ev.kind == giftwrap.KIND_GIFT_WRAP:
            try:
                inner = giftwrap.unwrap(ev, self.keys)
            except giftwrap.GiftWrapError:
                return None
            if inner.kind != types.KIND_PRIVATE_RUMOR or not addressed_to_me(inner):
                return None   # For example, a wrapped ACK is not a message.
            if any(tag and tag[0] in types.ORGANIZATION_ONLY_PRIVATE_TAGS
                   for tag in inner.tags):
                return None  # A personal decoder cannot authorize an organization route.
            conversation_tags = [tag for tag in inner.tags
                                 if tag and tag[0] == "a4a_conversation"]
            if conversation_tags and (len(conversation_tags) != 1
                                      or len(conversation_tags[0]) != 2
                                      or re.fullmatch(r"[0-9a-f]{64}", conversation_tags[0][1]) is None):
                return None
            return {"from_pubkey": inner.pubkey, "content": inner.content,
                    "event": inner, "wrapped": True,
                    "inner_id": inner.id, "outer_id": ev.id,
                    "delivery_id": inner.tag_value("d"), "outer_event": ev,
                    "conversation_id": conversation_tags[0][1] if conversation_tags else None,
                    "reply_to": _reply_reference(inner),
                    # The sender's signed time, set by the tool; the envelope's own time is
                    # jittered on purpose and is not the send time (representative, 26.09).
                    "signed_at": inner.created_at}
        return None

    async def subscribe_private_messages(self, since: int | None = None):
        """Stream incoming private messages, both plain-encrypted and wrapped.

        Item format matches `read_private_messages`, including IDs and outer_event.
        This replaces polling: a public-address agent polling every 30 seconds spends
        four times more on empty “what is new?” requests than on messages themselves
        (2026-08-28 model). Event-ID deduplication lasts for the subscription lifetime;
        callers persist “already processed” state across runs.
        """
        # Bound deduplication memory. In a long-lived spammed process, an unbounded set
        # is a slow memory leak (2026-08-28 review, S4).
        seen = _BoundedSeen()
        # On REQ a relay sends ALL matching history before the live stream. Without a
        # window, every start and reconnect downloaded everything ever sent
        # (2026-08-28 review, A8). Envelope windows expand by timestamp jitter as in
        # `_unwrap_inbox`.
        plain = {"kinds": [types.KIND_PRIVATE_MESSAGE], "#p": [self.pubkey]}
        wrapped = {"kinds": [giftwrap.KIND_GIFT_WRAP], "#p": [self.pubkey]}
        if since is not None:
            plain["since"] = since
            wrapped["since"] = since - giftwrap._JITTER_SECONDS
        async with contextlib.aclosing(self.relay.subscribe([plain, wrapped])) as events:
            async for ev in events:
                msg = self._decode_incoming(ev)
                if msg is None or msg["event"].id in seen:
                    continue
                seen.add(msg["event"].id)
                yield msg

    async def subscribe_connection_requests(self, since: int | None = None):
        """Stream kind-31022 connection requests addressed to us.

        Like `get_connection_requests`, this rechecks the recipient because
        server-side filtering is untrusted.
        """
        flt = {"kinds": [types.KIND_CONNECTION_REQUEST], "#p": [self.pubkey]}
        if since is not None:
            flt["since"] = since
        # Deduplicate here too: a reconnect replays request history, which otherwise
        # reaches the caller repeatedly (review S4).
        seen = _BoundedSeen()
        async with contextlib.aclosing(self.relay.subscribe(flt)) as events:
            async for ev in events:
                cr = _safe_from_event(types.ConnectionRequest, ev)
                if cr is None or cr.to_pubkey != self.pubkey or ev.id in seen:
                    continue
                seen.add(ev.id)
                yield {"from_pubkey": ev.pubkey, "intro": cr.intro, "event": ev}

    async def _unwrap_inbox(
        self, since: int | None = None,
        relay: FanOutRelayClient | RelayClient | None = None,
    ) -> list[Event]:
        """Unwrap addressed kind-1059 gift wraps into signed inner events.

        Corrupt and misaddressed envelopes are skipped. `since` expands by
        `giftwrap._JITTER_SECONDS` because envelope `created_at` is deliberately moved
        into the past; a literal window would omit fresh messages. The SDK, rather
        than every caller, owns this expansion.
        """
        flt = {"kinds": [giftwrap.KIND_GIFT_WRAP], "#p": [self.pubkey]}
        if since is not None:
            flt["since"] = since - giftwrap._JITTER_SECONDS
        source = self.relay if relay is None else relay
        # Read the whole inbox, page by page and node by node (27.09.2026): one query stopped
        # at the per-node budget (2500 of 5000 across two nodes) and silently returned only
        # the newest part, so backdated acknowledgement envelopes fell out.
        if isinstance(source, FanOutRelayClient):
            batches = await source._gather(lambda client: self._all_pages(client, flt))
        else:
            batches = [await self._all_pages(source, flt)]
        wraps = list({gw.id: gw for batch in batches for gw in batch}.values())
        inners = []
        for gw in wraps:
            try:
                inners.append(giftwrap.unwrap(gw, self.keys))
            except giftwrap.GiftWrapError:
                continue
        return inners

    #: Pages one inbox read may take before it gives up loudly instead of returning a part.
    MAX_INBOX_PAGES = 50

    @staticmethod
    async def _all_pages(client, flt: dict) -> list[Event]:
        """Every event of one node matching `flt`, walking back with `until` while the node
        answers a full page. NIP-01 `limit` asks for the newest events; `until` is inclusive,
        so same-second neighbours are read twice and deduplicated by ID."""
        from . import relay as relay_mod
        budget = relay_mod.MAX_EVENTS_PER_QUERY
        found: dict[str, Event] = {}
        page = dict(flt, limit=budget)
        for _ in range(Agent.MAX_INBOX_PAGES):
            result = await client.query_bounded(page, max_events=budget)
            fresh = [ev for ev in result.events if ev.id not in found]
            found.update((ev.id, ev) for ev in result.events)
            # Done only when a page brings nothing new: a node may cap `limit` below what was
            # asked and answer EOSE, so a short page is not proof that nothing older exists.
            if not fresh:
                if result.truncated:
                    raise RelayError(f"inbox read from {client.url} cannot move past "
                                     f"{page.get('until')}: more than {budget} events in one "
                                     "second; the answer would be incomplete")
                return list(found.values())
            page = dict(page, until=min(ev.created_at for ev in fresh))
        raise RelayError(f"inbox at {client.url} holds more than {Agent.MAX_INBOX_PAGES} pages of "
                         f"{budget} events; refusing to return part of it as the whole")

    async def reveal(self, message) -> str:
        """Reveal a wrapped private message as dispute evidence.

        Publicly publish the sender-SIGNED inner event (kind 14, plaintext). Its
        self-verifying signature proves “the sender said exactly this” without
        revealing keys. This works for messages received with `wrapped=True`.
        Cryptographically, either party may reveal the conversation unilaterally
        because both retain signed messages. A “co-reveal request” is a social signal
        of good faith, not a technical prerequisite.
        """
        ev = message["event"] if isinstance(message, dict) else message
        await self._broadcast(ev)
        return ev.id

    # --- Reliable delivery (ACK, v0.3 P1 plan) ------------------------------

    async def acknowledge(self, message, status: str = "received",
                          note: str = "", wrap: bool | None = None) -> str:
        """Publish a kind-31034 acknowledgement for `message`.

        `message` is a dictionary from `read_private_messages()` or an Event. The
        delivery ID comes from its `d` tag and the acknowledgement addresses the
        sender. This is idempotent: another ACK for the same delivery replaces the
        previous one. `status` is received, processed, or failed.

        `wrap` controls gift wrapping and metadata privacy. The None default matches
        the incoming dictionary's `wrapped` value: reply to a wrapped message with a
        wrapped ACK so the relay does not learn the party pair or delivery ID. A
        public ACK exposes `note` to the relay, so it must contain no secrets; a
        wrapped ACK keeps `note` inside the encrypted envelope.
        """
        ev = message["event"] if isinstance(message, dict) else message
        delivery_id = ev.tag_value("d")
        if not delivery_id:
            raise ValueError("message has no d tag and cannot be acknowledged")
        if wrap is None:
            wrap = isinstance(message, dict) and message.get("wrapped", False)
        ack_ev = types.AckReceipt(
            delivery_id=delivery_id, acked_event_id=ev.id, to_pubkey=ev.pubkey,
            status=status, content=note).to_event(self.delegation_id)
        # An acknowledgement is as ephemeral as the delivered message, so apply the
        # same retention policy.
        ack_ev.tags += self._expiration_tag(None)
        if not wrap:
            return await self._publish(ack_ev)
        ack_ev.sign(self.keys)
        gw = giftwrap.wrap(ack_ev, ev.pubkey, self.keys,
                           extra_tags=self._expiration_tag(None))
        await self._broadcast(gw)
        return ack_ev.id

    async def get_acks(self, delivery_id: str,
                       from_pubkey: str | None = None) -> list[dict]:
        """Return kind-31034 acknowledgements for `delivery_id`.

        `from_pubkey` restricts results to the expected recipient. **Without it, the
        list contains receipts FROM ANYONE and is not delivery evidence.** A
        2026-09-05 staging test showed that an outsider who knew `delivery_id` could
        publish a recipient receipt accepted by the relay. Kind 31034 requires a
        mandate but not a relationship to the delivery. An unfiltered call then showed
        one “delivery” even though the real recipient acknowledged nothing.

        Scope of the finding: this works only for PUBLIC-METADATA messages
        (`wrap=False`). Outsiders do not know wrapped delivery IDs, wrapping is the
        default, and `deliver_with_ack` applies the recipient filter itself. Exposure
        therefore requires explicitly choosing public metadata AND calling this method
        without `from_pubkey`.

        The reverse cannot be prevented: a recipient may always refuse to acknowledge.
        Missing receipts do not prove that a message was not delivered.

        Search both public and wrapped acknowledgements. Since 2026-08-29 private
        messages are wrapped by default and ACKs return through the SAME mode as the
        message. A public-only query would therefore miss them and return an empty
        list. Delivery mechanics are not the caller's concern.
        """
        acks = await self._get_public_acks(
            self.relay, delivery_id, from_pubkey=from_pubkey)
        seen = {a["event"].id for a in acks}
        for a in await self._get_wrapped_acks(delivery_id, from_pubkey=from_pubkey):
            if a["event"].id not in seen:
                acks.append(a)
        return acks

    async def _get_public_acks(self, relay, delivery_id: str,
                               from_pubkey: str | None = None) -> list[dict]:
        """Read and locally validate public ACKs through a selected relay client."""
        events = await relay.query(
            {"kinds": [types.KIND_ACK_RECEIPT], "#d": [delivery_id]})
        acks = []
        for ev in events:
            if from_pubkey and ev.pubkey != from_pubkey:
                continue
            ack = _safe_from_event(types.AckReceipt, ev)
            # Do not trust relay-side filtering. Recheck that the ACK is for this
            # delivery (a relay may return another `d`) and addressed to US (`p` is our
            # public key); otherwise collision/substitution can falsely “confirm” it.
            if ack is None or ack.delivery_id != delivery_id \
                    or ack.to_pubkey != self.pubkey:
                continue
            acks.append({"acker_pubkey": ev.pubkey, "status": ack.status,
                         "note": ack.content, "delivery_id": ack.delivery_id,
                         "to_pubkey": ack.to_pubkey,
                         "acked_event_id": ack.acked_event_id, "event": ev})
        return acks

    async def _get_wrapped_acks(
        self, delivery_id: str,
        from_pubkey: str | None = None,
        since: int | None = None,
        relay: FanOutRelayClient | RelayClient | None = None,
    ) -> list[dict]:
        """Return gift-wrapped acknowledgements for `delivery_id` from our inbox.

        `since` is operationally essential. Without it, every poll in an ACK wait loop
        downloads and decrypts the ENTIRE lifetime envelope inbox—up to twenty full
        downloads per delivery (2026-08-28 review, S3).
        """
        acks = []
        inners = (await self._unwrap_inbox(since)
                  if relay is None else
                  await self._unwrap_inbox(since, relay=relay))
        for inner in inners:
            if inner.kind != types.KIND_ACK_RECEIPT:
                continue
            if from_pubkey and inner.pubkey != from_pubkey:
                continue
            ack = _safe_from_event(types.AckReceipt, inner)
            if ack is None or ack.delivery_id != delivery_id \
                    or ack.to_pubkey != self.pubkey:
                continue
            acks.append({"acker_pubkey": inner.pubkey, "status": ack.status,
                         "note": ack.content, "delivery_id": ack.delivery_id,
                         "to_pubkey": ack.to_pubkey,
                         "acked_event_id": ack.acked_event_id, "event": inner})
        return acks

    async def _publish_attempt(self, to_pubkey: str, content: str, delivery_id: str, *,
                               private: bool, extra_relays: list,
                               keep_envelope: bool,
                               conversation_id: str | None = None,
                               reply_to: tuple[str, ...] | None = None) -> tuple[str, Event | None]:
        """Publish one attempt of a reliable delivery.

        Returns the id reported to the caller and the envelope worth journaling (None
        when the plain `send_private_message` path is used and nothing is journaled).
        Raises RelayError when no configured relay accepted the attempt.
        """
        if private:
            if extra_relays:
                inner, outer, _ = self.prepare_private_message(
                    to_pubkey, content, delivery_id=delivery_id, wrap=True,
                    conversation_id=conversation_id, reply_to=reply_to)
                await self._broadcast(outer)
                await self.publish_to_relays(outer, extra_relays)  # best-effort
                return inner.id, outer
            if keep_envelope:
                # Same steps as send_private_message, but keeping the published
                # envelope: the journal stores it for an identical resend.
                inner, outer, _ = self.prepare_private_message(
                    to_pubkey, content, delivery_id=delivery_id, wrap=True,
                    conversation_id=conversation_id, reply_to=reply_to)
                await self._broadcast(outer)
                return inner.id, outer
            return await self.send_private_message(
                to_pubkey, content, delivery_id=delivery_id, wrap=True,
                conversation_id=conversation_id, reply_to=reply_to), None
        ev = self._build_private_message(to_pubkey, content, delivery_id)
        await self._publish(ev)
        if extra_relays:
            await self.publish_to_relays(ev, extra_relays)  # best-effort
        return ev.id, ev

    async def deliver_with_ack(self, to_pubkey: str, content: str, *,
                               retries: int = 3, ack_timeout: float = 5.0,
                               poll_interval: float = 1.0,
                               resolve_recipient_relays: bool = False,
                               private: bool = False, outbox=None,
                               conversation_id: str | None = None,
                               reply_to: tuple[str, ...] | None = None) -> dict:
        """Reliably deliver an encrypted message and wait for its recipient ACK.

        Retry up to `retries` times. The guarantee is at-least-once, so recipients MUST
        TOLERATE REPEATS. A 2026-09-04 local test delivered 200 messages in groups of
        ten while the recipient disconnected about every four seconds (11 disconnects
        in the run): all 200 were acknowledged, with no loss or `dead_letter`. The
        recipient-side cost is that without a processed journal (see
        `read_private_messages`) it acknowledges the same delivery repeatedly.

        Every retry uses the same delivery ID (addressable replacement at the relay),
        so recipients must deduplicate by delivery ID for idempotent processing.
        Return `status` (`acknowledged` or `dead_letter`), `delivery_id`, the latest
        attempt's `event_id`, `ack_status`, and `attempts`.

        `resolve_recipient_relays=True` also sends to the recipient's NIP-65 inbox
        relays (P3), not only our own, and reads the public ACK from those same relays.
        This supports disjoint sender and recipient relay sets without assuming relay
        federation. Recipient relay lookup and the number of outbound connections are
        validated and bounded by `resolve_relays()`.

        `private=True` enables **private reliable delivery**: a gift-wrapped message
        hides metadata and the recipient returns a wrapped ACK, keeping the entire
        exchange private from the relay. With recipient resolution enabled, both
        encrypted envelopes cross the recipient's NIP-65 relays without exposing the
        sender or delivery ID. The tradeoff is that a non-public receipt cannot
        contribute to public `delivery_score`; reputation comes from public
        transactions. Recipients call `acknowledge()` normally and it mirrors the
        incoming wrapping.

        `outbox` (an `a4a.outbox.OutboxStore`) keeps the outcome after the call returns:
        the delivery is recorded BEFORE the first publication, every envelope a relay
        accepted is stored (encrypted, never the plaintext), and the final state is
        written. Without it a `dead_letter` is forgotten when the session ends and a
        late ACK is never noticed; see `recheck_delivery` and `republish_delivery`.

        `reply_to=(delivery_id, inner_id)` binds the message to the letter it answers,
        as in `prepare_private_message`; every retry carries the same reference.
        """
        if type(retries) is not int or retries < 0:
            raise ValueError("retries cannot be negative and must be an integer")
        if (type(ack_timeout) not in (int, float)
                or not math.isfinite(ack_timeout) or ack_timeout < 0):
            raise ValueError("ack_timeout must be a finite non-negative number")
        if (type(poll_interval) not in (int, float)
                or not math.isfinite(poll_interval) or poll_interval <= 0):
            raise ValueError("poll_interval must be a finite positive number")
        if conversation_id is not None:
            if (not isinstance(conversation_id, str)
                    or re.fullmatch(r"[0-9a-f]{64}", conversation_id) is None):
                raise ValueError("conversation_id must be 64 lowercase hexadecimal characters")
            if not private:
                raise ValueError("conversation_id requires private gift-wrapped delivery")
        if reply_to is not None:
            _check_reply_to(reply_to)
            if not private:
                raise ValueError("reply_to requires private gift-wrapped delivery")
        to_pubkey = Keys.normalize_pubkey(to_pubkey)
        extra_relays = (await self.resolve_relays(to_pubkey)
                        if resolve_recipient_relays else [])
        # Keep one connection set open while polling. Opening every recipient relay on
        # every poll made a one-second poll interval mostly TLS/WebSocket handshakes.
        # Exact own addresses need no second client; FanOutRelayClient additionally
        # canonicalizes equivalent forms such as a trailing root slash.
        ack_urls = list(dict.fromkeys(
            url for url in extra_relays if url not in self._own_relays))
        recipient_ack_relay = None
        recipient_ack_connected = False
        if ack_urls:
            recipient_ack_relay = FanOutRelayClient(
                ack_urls, timeout=max(0.1, min(ack_timeout, 10.0)))
            recipient_ack_relay.read_deadline = max(0.1, min(ack_timeout, 5.0))
            try:
                await recipient_ack_relay.connect()
            except RelayError as error:
                # Extra publication is best-effort and receipt reads have the same
                # availability contract: our configured relays remain usable. Keep
                # the client for one bounded retry after publication: a momentary
                # handshake rejection must not permanently discard the ACK route.
                log.warning("recipient ACK relays are unavailable: %s", error)
            else:
                recipient_ack_connected = True
        delivery_id = uuid.uuid4().hex
        last_id = ""
        attempts = 0
        # Search ACKs from delivery start, adjusted for envelope timestamp jitter.
        # Without the window every poll downloads the full inbox (S3).
        started_at = int(time.time()) - giftwrap._JITTER_SECONDS
        if outbox is not None:
            outbox.start(delivery_id, to_pubkey, private=private, since=started_at)
        published = False
        # Polls that could not ask at all. A dropped connection is ordinary on a long
        # path (seen to Singapore on 23.09.2026); the client reconnects in the
        # background, so a failed poll means "ask again", not "the delivery is over".
        # Counted, so a dead_letter after no successful poll is not read as silence.
        ack_query_errors = 0
        try:
            for _ in range(retries + 1):
                attempts += 1
                try:
                    new_id, sent = await self._publish_attempt(
                        to_pubkey, content, delivery_id, private=private,
                        extra_relays=extra_relays, keep_envelope=outbox is not None,
                        conversation_id=conversation_id, reply_to=reply_to)
                except RelayError as error:
                    if not published:
                        raise  # nothing accepted anywhere: publish_failed, surfaced
                    # Already published once: a failed REPEAT loses nothing, keep waiting.
                    log.warning("repeat publication failed, still waiting for ACK: %s", error)
                    sent = None
                else:
                    last_id, published = new_id, True
                if outbox is not None and sent is not None:
                    outbox.add_envelope(delivery_id, sent)
                if recipient_ack_relay is not None and not recipient_ack_connected:
                    try:
                        await recipient_ack_relay.connect()
                    except RelayError as error:
                        log.warning("recipient ACK relay retry failed: %s", error)
                    else:
                        recipient_ack_connected = True
                deadline = time.monotonic() + ack_timeout
                while True:
                    try:
                        acks = (await self._get_wrapped_acks(
                                    delivery_id, from_pubkey=to_pubkey, since=started_at)
                                if private else
                                await self.get_acks(delivery_id, from_pubkey=to_pubkey))
                    except RelayError as error:
                        ack_query_errors += 1
                        log.warning("ACK query failed, will ask again: %s", error)
                        acks = []
                    if recipient_ack_connected:
                        try:
                            remote_acks = (await self._get_wrapped_acks(
                                                delivery_id,
                                                from_pubkey=to_pubkey,
                                                since=started_at,
                                                relay=recipient_ack_relay)
                                           if private else
                                           await self._get_public_acks(
                                                recipient_ack_relay, delivery_id,
                                                from_pubkey=to_pubkey))
                        except RelayError as error:
                            log.warning("recipient ACK relay query failed: %s", error)
                        else:
                            seen = {a["event"].id for a in acks}
                            acks.extend(a for a in remote_acks
                                        if a["event"].id not in seen)
                    if acks:
                        if outbox is not None:
                            outbox.finish(delivery_id, "acknowledged", attempts=attempts,
                                          ack_status=acks[0]["status"],
                                          ack_signed_at=acks[0]["event"].created_at)
                        return {"status": "acknowledged", "delivery_id": delivery_id,
                                "event_id": last_id, "ack_status": acks[0]["status"],
                                "attempts": attempts,
                                "ack_query_errors": ack_query_errors}
                    if time.monotonic() >= deadline:
                        break
                    await asyncio.sleep(poll_interval)
            if outbox is not None:
                outbox.finish(delivery_id, "dead_letter", attempts=attempts)
            return {"status": "dead_letter", "delivery_id": delivery_id,
                    "event_id": last_id, "ack_status": None, "attempts": attempts,
                    "ack_query_errors": ack_query_errors}
        except BaseException:
            # Three outcomes, not two: nothing accepted by any relay is not the same
            # fact as "sent, then stopped". Record which, then let the error surface.
            if outbox is not None:
                try:
                    outbox.finish(delivery_id,
                                  "interrupted" if published else "publish_failed",
                                  attempts=attempts)
                except Exception:
                    log.exception("could not record delivery %s outcome", delivery_id)
            raise
        finally:
            if recipient_ack_relay is not None:
                await recipient_ack_relay.aclose()

    async def recheck_delivery(self, outbox, delivery_id: str, *,
                               resolve_recipient_relays: bool = False) -> dict:
        """Look again for the recipient's ACK of a journaled delivery.

        The common late case: the recipient's receiver was down, came back after the
        sender gave up, and acknowledged. The ACK is on the relays; nobody asked again.
        A found ACK moves the record to `acknowledged` with `late=True`. Only the
        recipient's own ACK counts, exactly as in `deliver_with_ack`.
        """
        record = outbox.get(delivery_id)
        if record is None:
            raise ValueError("unknown delivery_id")
        if record["state"] == "publish_failed":
            return record  # nothing was sent
        if record["state"] == "acknowledged" and record["ack_status"] != "received":
            return record  # processed/failed is final; `received` may still be upgraded
        recipient = record["recipient"]
        acks = (await self._get_wrapped_acks(
                    delivery_id, from_pubkey=recipient, since=record["since"])
                if record["private"] else
                await self.get_acks(delivery_id, from_pubkey=recipient))
        if not acks and resolve_recipient_relays:
            urls = [u for u in await self.resolve_relays(recipient)
                    if u not in self._own_relays]
            if urls:
                remote = FanOutRelayClient(urls, timeout=10.0)
                try:
                    await remote.connect()
                    acks = (await self._get_wrapped_acks(
                                delivery_id, from_pubkey=recipient,
                                since=record["since"], relay=remote)
                            if record["private"] else
                            await self._get_public_acks(
                                remote, delivery_id, from_pubkey=recipient))
                except RelayError as error:
                    log.warning("recipient relays unavailable for recheck: %s", error)
                finally:
                    await remote.aclose()
        if acks:
            # A mailbox may confirm `received` on arrival and `processed` later; prefer
            # the final word. Late means "after we gave up", not "upgraded later".
            final = [a for a in acks if a["status"] in ("processed", "failed")]
            chosen = (final or acks)[0]
            outbox.finish(delivery_id, "acknowledged",
                          ack_status=chosen["status"],
                          late=record["state"] != "acknowledged",
                          ack_signed_at=chosen["event"].created_at)
        return outbox.get(delivery_id)

    async def recheck_due(self, outbox, *, now: float | None = None,
                          resolve_recipient_relays: bool = False, limit: int = 20) -> dict:
        """Recheck every journaled delivery whose next automatic check is due.

        Meant for an always-on loop (the inbox receiver calls it on its ticks), so a
        dead_letter heals itself when a late ACK appears and a `received` receipt is
        upgraded to the final word - without the agent remembering a manual command.
        Returns counts; one delivery's relay failure does not stop the others.
        """
        now = time.time() if now is None else now
        checked = acknowledged = 0
        for delivery_id in outbox.due_for_recheck(now, limit=limit):
            before = outbox.get(delivery_id)
            try:
                after = await self.recheck_delivery(
                    outbox, delivery_id, resolve_recipient_relays=resolve_recipient_relays)
            except RelayError as error:
                log.warning("automatic recheck of %s could not ask: %s", delivery_id, error)
                after = before
            outbox.mark_rechecked(delivery_id, now)
            checked += 1
            if (after["state"] == "acknowledged"
                    and (before["state"], before["ack_status"]) != ("acknowledged", after["ack_status"])):
                acknowledged += 1
        return {"checked": checked, "acknowledged": acknowledged}

    async def republish_delivery(self, outbox, delivery_id: str, *,
                                 resolve_recipient_relays: bool = False,
                                 max_republish: int = 5) -> str:
        """Publish the journaled envelope again, byte for byte, and return its id.

        Relays do not copy events to each other, so a relay that was down during the
        delivery never received it. Resending the SAME signed envelope fills that gap
        without composing a second message; the recipient deduplicates by delivery ID
        either way. Bounded, so a stuck delivery cannot become a flood.
        """
        record = outbox.get(delivery_id)
        if record is None:
            raise ValueError("unknown delivery_id")
        if record["state"] == "acknowledged":
            raise ValueError("delivery is already acknowledged")
        if record["republished"] >= max_republish:
            raise ValueError(f"delivery was already republished {max_republish} times")
        envelope = outbox.latest_envelope(delivery_id)
        if envelope is None:
            raise ValueError("nothing was ever published for this delivery")
        await self._broadcast(envelope)
        if resolve_recipient_relays:
            extra = await self.resolve_relays(record["recipient"])
            if extra:
                await self.publish_to_relays(envelope, extra)  # best-effort
        outbox.mark_republished(delivery_id)
        return envelope.id

    # --- Addressing (NIP-65, v0.3 P3 plan) ---------------------------------

    async def publish_relay_list(self, relays: list) -> str:
        """Publish a kind-10002 NIP-65 relay list for message delivery.

        `relays` contains URL strings or `(url, marker)` tuples. Marker `read` denotes
        relays where the agent READS incoming messages and where senders deliver;
        `write` denotes publication; no marker means both. Kind 10002 is replaceable,
        so publication supersedes the previous list.
        """
        tags = []
        for r in relays:
            if isinstance(r, str):
                url, marker = r, None
            else:
                url, marker = r[0], (r[1] if len(r) > 1 else None)
            tags.append(["r", url] if marker is None else ["r", url, marker])
        ev = Event(kind=types.KIND_RELAY_LIST, tags=tags, content="")
        return await self._publish(ev)

    async def resolve_relays(self, pubkey: str) -> list[str]:
        """Resolve a recipient's NIP-65 inbox relays.

        Include relays where it READS incoming messages (`read` or no marker). Return
        an empty list when no relay-list announcement exists.
        """
        pubkey = Keys.normalize_pubkey(pubkey)
        events = await self.relay.query(
            {"kinds": [types.KIND_RELAY_LIST], "authors": [pubkey]})
        if not events:
            return []
        # Resolve equal timestamps with the LOWER ID, matching relay behavior under
        # NIP-01. The former `max(created_at)` returned whichever same-second list came
        # first; reversing relay order selected another equally signed and “newest”
        # list. HEAL-005 protected the writer from ties, but the reader still resolved
        # them differently from the network, letting two agents deliver through
        # DIFFERENT lists from the same author.
        latest = min(events, key=lambda e: (-e.created_at, e.id))
        urls = []
        # WARNING: this list comes from a FOREIGN event. A recipient could declare an
        # address inside our perimeter as “its relay,” making resolved delivery connect
        # there (2026-08-28 review, S7). Validate like file references: allowlisted
        # schemes and no internal hosts.
        for t in latest.tags:
            if len(t) >= 2 and t[0] == "r":
                marker = t[2] if len(t) >= 3 else None
                if marker in (None, "read") and _relay_url_acceptable(t[1], self._own_relays, self._allow_internal_relays):
                    urls.append(t[1])
        if len(urls) > MAX_RECIPIENT_RELAYS:
            # Do not truncate silently. The recipient may have declared too many by
            # mistake, leaving some relays without delivery; operators must know.
            log.warning("recipient %s declared %d relays; visiting the first %d",
                        pubkey[:12], len(urls), MAX_RECIPIENT_RELAYS)
            urls = urls[:MAX_RECIPIENT_RELAYS]
        return urls

    async def publish_to_relays(self, event: Event, urls: list[str],
                               timeout: float = 10.0) -> dict:
        """Best-effort publish an already signed `event` to extra relays.

        Return `{url: None|"<error>"}`. One relay's failure does not fail the call
        because partial delivery is better than none. Configured relays are excluded.
        """
        async def one(url: str) -> str | None:
            try:
                async with RelayClient(url, timeout=timeout) as rc:
                    await rc.publish(event)
                return None
            except Exception as e:  # One unavailable/rejecting relay does not fail all.
                return str(e)

        # Run concurrently. Sequential traversal made total time the sum of timeouts,
        # letting the list author control our stall duration. Traversal now costs one
        # timeout regardless of address count.
        outcomes = await asyncio.gather(*(one(u) for u in urls))
        return dict(zip(urls, outcomes))

    # --- Security ----------------------------------------------------------

    async def active_owner_mandates(self, sender_pubkeys: set[str],
                                    allowed_owners: set[str] | frozenset[str]) -> dict[str, Event]:
        """Resolve current owner-signed mandates for many keys with bounded queries.

        A relay is a source of candidates, never the authorization decision. Split a
        truncated batch and recheck signatures, coordinates and revocations locally.
        Even one key whose query remains truncated fails closed instead of accepting
        an incomplete view of its authority.
        """
        if (not isinstance(sender_pubkeys, (set, frozenset))
                or len(sender_pubkeys) > 10_000
                or not isinstance(allowed_owners, (set, frozenset))
                or len(allowed_owners) > 100
                or any(not isinstance(owner, str) or not is_canonical_pubkey(owner)
                       for owner in allowed_owners)):
            raise ValueError("owner mandate lookup needs bounded exact public-key sets")
        senders = sorted(key for key in sender_pubkeys
                         if isinstance(key, str) and is_canonical_pubkey(key))
        if not senders or not allowed_owners:
            return {}
        owners = sorted(allowed_owners)

        async def complete_query(kind, keys):
            result = await self.relay.query_bounded(
                {"kinds": [kind], "authors": owners, "#d": keys}, max_events=256)
            if not result.truncated:
                return result.events
            if len(keys) == 1:
                raise RelayError("owner authorization query was truncated; authorization unavailable")
            midpoint = len(keys) // 2
            return (await complete_query(kind, keys[:midpoint])
                    + await complete_query(kind, keys[midpoint:]))

        async def all_events(kind, keys):
            events = []
            for start in range(0, len(keys), 64):
                events.extend(await complete_query(kind, keys[start:start + 64]))
            return events

        sender_set = set(senders)
        latest = {}
        for mandate in await all_events(types.KIND_DELEGATION, senders):
            sender = dlg.delegation_target(mandate)
            if (mandate.kind != types.KIND_DELEGATION
                    or mandate.pubkey not in allowed_owners
                    or sender not in sender_set or not mandate.verify()):
                continue
            coordinate = (mandate.pubkey, sender)
            previous = latest.get(coordinate)
            if previous is None or (-mandate.created_at, mandate.id) < (-previous.created_at, previous.id):
                latest[coordinate] = mandate
        if not latest:
            return {}
        revocations = await all_events(
            types.KIND_DELEGATION_REVOCATION,
            sorted({sender for _, sender in latest}))
        accepted = {}
        for (owner, sender), mandate in sorted(latest.items()):
            revoked = next((event for event in revocations
                            if event.pubkey == owner and dlg.is_revocation_valid(event, mandate)), None)
            if dlg.validate_sender_mandate(
                    sender, mandate, revocation=revoked, require_started=True):
                accepted.setdefault(sender, mandate)
        return accepted

    async def active_owner_mandate(self, sender_pubkey: str,
                                   allowed_owners: set[str] | frozenset[str]) -> Event | None:
        """Single-sender convenience wrapper for current organization affiliation."""
        return (await self.active_owner_mandates(
            {sender_pubkey}, allowed_owners)).get(sender_pubkey)

    async def validate_delegation(self, ev: Event) -> bool:
        """Validate an event's delegation chain after fetching mandate and revocation."""
        deleg_id = ev.delegation_ref()
        if not deleg_id:
            return False
        found = await self.relay.query(
            {"ids": [deleg_id], "kinds": [types.KIND_DELEGATION]})
        # The relay is untrusted, so do not rely on server-side filtering. Require the
        # EXACT requested delegation (same ID and kind), not another validly signed
        # one. Otherwise a relay could substitute a live mandate for the same delegate
        # from another owner when a revoked mandate is requested.
        deleg = next((d for d in found
                      if d.id == deleg_id and d.kind == types.KIND_DELEGATION), None)
        if deleg is None:
            return False
        # Search revocation by AGENT coordinate (31000:<owner>:<delegate>), not by this
        # mandate copy's ID. The old `e`-tag query never returned the real revocation
        # when an agent referenced ANOTHER copy: kind 31000 is addressable, reissuance
        # changes its ID, and an agent may retain the old public copy. The owner revoked
        # the agent while a counterparty still saw it as authorized.
        #
        # Copy binding was removed from the relay and `is_revocation_valid` (core audit
        # F6), but lookup here still depended on the copy even though validation did
        # not. Found on 2026-08-31 as finding 56. The single-character `#d` tag is
        # indexed by every NIP-01 relay, so this costs no compatibility.
        delegate = dlg.delegation_target(deleg)
        if delegate is None:
            return False  # `d` is missing or differs from `delegate`; see rule 8.
        revs = await self.relay.query(
            {"kinds": [types.KIND_DELEGATION_REVOCATION],
             "authors": [deleg.pubkey], "#d": [delegate]})
        # Find ANY valid revocation of THIS agent, not the “owner's first revocation.”
        # The old code took the first list item and checked its relation afterward. An
        # untrusted relay could place an unrelated revocation by the same owner first,
        # preventing the real one from being considered and leaving the mandate active
        # (2026-08-29 internal audit, F5). Recheck every revocation locally.
        revocation = next(
            (r for r in revs
             if r.pubkey == deleg.pubkey and dlg.is_revocation_valid(r, deleg)),
            None)
        return dlg.validate_delegation(ev, deleg, revocation=revocation)

    # --- Trusted timestamp (§4.1, option B) --------------------------------

    def _relay_http_base(self) -> str:
        parts = urlsplit(self._own_relays[0])
        scheme = "https" if parts.scheme == "wss" else "http"
        return f"{scheme}://{parts.netloc}"

    async def _notary_keys(self) -> tuple[str | None, dict[str, int]]:
        """Read current and retired notary keys from NIP-11.

        The current key is `a4a.notary`; retired keys are
        `a4a.notary_retired: [{pubkey, until}]`. A timestamp by a retired key is valid
        only when block time T is at most `until` (2026-09-04 rotation design).

        This is not constant because a node may rotate keys. Without NIP-11 or the
        field there is no trustworthy author to query: readers MUST NOT accept kind
        1040 from arbitrary authors (specification §2.9). The old fallback accepted any
        author when the notary had no timestamp. We now preserve the specification's
        author-selection rule. Neither a selected notary nor two timestamps alone prove
        historical authority.
        """
        def fetch() -> tuple[str | None, dict[str, int]]:
            import json
            import urllib.request
            req = urllib.request.Request(self._relay_http_base() + "/",
                                         headers={"Accept": "application/nostr+json"})
            with urllib.request.urlopen(req, timeout=5) as r:
                info = json.loads(r.read().decode("utf-8"))
            a4a = (info.get("a4a") or {}) if isinstance(info, dict) else {}
            notary = a4a.get("notary")
            current = notary if isinstance(notary, str) and is_canonical_pubkey(notary) else None
            retired: dict[str, int] = {}
            for item in a4a.get("notary_retired") or []:
                if not isinstance(item, dict):
                    continue
                pk, until = item.get("pubkey"), item.get("until")
                if (isinstance(pk, str) and is_canonical_pubkey(pk) and isinstance(until, int)
                        and until > 0 and pk != current):
                    retired[pk] = until
            return current, retired
        try:
            return await asyncio.to_thread(fetch)
        except Exception as exc:  # noqa: BLE001 — network/parser boundary becomes tri-state
            raise NotaryDiscoveryError(
                "relay NIP-11 notary declaration could not be inspected") from exc

    async def _notary_pubkey(self) -> str | None:
        return (await self._notary_keys())[0]

    async def _fetch_rest_event(self, path: str, event_id: str) -> Event | None:
        """Fetch an event through our fork's REST API and validate it as network input.

        Parsing, signature, and ID must match; an archive adds no trust.
        """
        def fetch() -> dict | None:
            import json
            import urllib.request
            try:
                with urllib.request.urlopen(self._relay_http_base() + path, timeout=5) as r:
                    return json.loads(r.read().decode("utf-8"))
            except Exception:  # noqa: BLE001 - foreign relay without REST/404 is normal
                return None
        raw = await asyncio.to_thread(fetch)
        if not isinstance(raw, dict):
            return None
        ev = RelayClient._parse_event(raw)
        return ev if ev is not None and ev.id == event_id else None

    async def _fetch_event_rest(self, event_id: str) -> Event | None:
        """Fetch via `/v1/event/<id>` when NIP-40 hides an expired mandate from queries."""
        return await self._fetch_rest_event(f"/v1/event/{event_id}", event_id)

    async def _fetch_delegation_history(self, delegation_id: str) -> Event | None:
        """Fetch a replaced mandate from `/v1/delegation-history/<id>` (since 0.3.13).

        NIP-33 reissuance physically removes the old mandate from subscriptions and
        `/v1/event` (finding 65), but the node archives it. Accept only a validly signed
        kind-31000 event with the same ID.
        """
        ev = await self._fetch_rest_event(f"/v1/delegation-history/{delegation_id}", delegation_id)
        return ev if ev is not None and ev.kind == types.KIND_DELEGATION else None

    async def get_stamp(self, event_id: str,
                        headers: "timestamp.HeaderSource | None" = None) -> "timestamp.StampVerdict":
        """Return a kind-1040 NIP-03 timestamp verdict for an event.

        Multiple timestamps may exist. Select the best: the confirmed one with the
        earliest block, otherwise `pending` if any waits, otherwise `absent`.
        `headers` supplies block headers and defaults to disk-cached Esplora.
        """
        headers = headers or timestamp.EsploraHeaders(cache=timestamp.CachedHeaders())
        try:
            current, retired = await self._notary_keys()
        except NotaryDiscoveryError:
            return timestamp.StampVerdict(
                "unverifiable", detail=(
                    "could not inspect the NIP-11 notary declaration; absence of the "
                    "notary or timestamp cannot be concluded"))
        authors = ([current] if current else []) + list(retired)
        if not authors:
            return timestamp.StampVerdict(
                "absent", detail="relay declares no notary (NIP-11 a4a.notary); there "
                                 "is no trusted author to query and arbitrary kind-1040 "
                                 "authors are not accepted")
        stamps = [s for s in await self.relay.query(
            {"kinds": [timestamp.KIND_OTS_ATTESTATION], "#e": [event_id], "authors": authors})
            if s.pubkey in authors]                      # Do not trust server filtering.
        if not stamps:
            return timestamp.StampVerdict("absent", detail="event has no timestamp")
        verdicts = []
        for s in stamps:
            v = timestamp.verify_stamp(s, event_id, headers)
            until = retired.get(s.pubkey)
            if v.confirmed and until is not None and (v.block_time or 0) > until:
                # A retired key's later signature has no authority. The proof's block
                # is real but AFTER the boundary, matching a stolen-key timestamp: a
                # past block cannot be forged, while a future one can be produced.
                v = timestamp.StampVerdict(
                    "unverifiable", block_height=v.block_height, block_time=v.block_time,
                    detail=(f"timestamp by retired notary key {s.pubkey[:12]}… after "
                            f"retirement: block {v.block_height} (T={v.block_time}) is "
                            f"later than until={until}"))
            verdicts.append(v)
        confirmed = [v for v in verdicts if v.confirmed]
        if confirmed:
            return min(confirmed, key=lambda v: v.block_time or 0)
        for state in ("pending", "unverifiable"):
            found = [v for v in verdicts if v.state == state]
            if found:
                return found[0]
        return verdicts[0]

    async def authority_at(self, event: Event,
                           headers: "timestamp.HeaderSource | None" = None) -> dict:
        """Return verifiable history facts without inventing an authority-time verdict.

        `unauthorized` means the presented signature or mandate chain is invalid;
        `unverifiable` means the mandate or verified timestamp is missing;
        `indeterminate` means the chain is valid and the event ID is anchored in a
        block, but signing, publication, and revocation order is unknown.
        `authorized_at` and `revoked_before` are no longer emitted because two upper
        bounds do not order events.

        Preserve legacy fields `{state, at, stamp, revocation_stamp, detail}`. `at` is
        block-header time, NOT publication time. `revocation_stamp` is the first
        confirmed timestamp among ID-sorted revocations, or the first unconfirmed one;
        `evidence.revocations` contains all observations. `evidence_version=1` names
        this contract, while `evidence` separates signature checks and declared terms
        from historical inference. None or `revocations_checked=False` means “not
        checked,” not a negative result. Open-network history completeness is unproven.
        """
        deleg_id = event.delegation_ref()
        evidence = {
            "event_signature_valid": event.verify(),
            "delegation_chain_valid": None,
            "delegation_created_at": None,
            "delegation_expiration": None,
            "revocations_checked": False,
            "revocations": [],
            "history_complete": False,
            "event_order_proven": False,
            "signature_time_proven": False,
        }
        if not evidence["event_signature_valid"]:
            return _authority("unauthorized", None, None, None,
                              "event signature or ID does not validate", evidence)
        try:
            event.validate_numeric_tags()
        except ValueError:
            return _authority("unauthorized", None, None, None,
                              "event has noncanonical numeric tags", evidence)
        if not deleg_id:
            return _authority("unauthorized", None, None, None,
                              "event has no delegation tag", evidence)
        headers = headers or timestamp.EsploraHeaders(cache=timestamp.CachedHeaders())
        stamp = await self.get_stamp(event.id, headers)
        if not stamp.confirmed:
            detail = stamp.detail
            if stamp.state == "absent" and event.kind not in timestamp.NOTARISED_KINDS:
                detail = (f"absent (kind {event.kind} not notarised): the notary "
                          f"timestamps only historical kinds {sorted(timestamp.NOTARISED_KINDS)}")
            return _authority("unverifiable", None, stamp, None, detail, evidence)
        at = stamp.block_time
        found = await self.relay.query({"ids": [deleg_id], "kinds": [types.KIND_DELEGATION]})
        deleg = next((d for d in found
                      if d.id == deleg_id and d.kind == types.KIND_DELEGATION), None)
        if deleg is None:
            deleg = await self._fetch_event_rest(deleg_id)
        if deleg is None:
            # Reissued: no live copy exists, so the node archive is the final source.
            deleg = await self._fetch_delegation_history(deleg_id)
        if deleg is None or deleg.kind != types.KIND_DELEGATION:
            return _authority("unverifiable", at, stamp, None,
                              "mandate not found: it expired on a relay without REST, "
                              "or it was reissued and this relay has no replaced-mandate "
                              "archive (/v1/delegation-history since 0.3.13, our fork only)",
                              evidence)
        # Check that the chain has a valid declared interval at all. Its beginning is
        # not treated as the actual issuance time of the mandate or event.
        chain_valid = dlg.validate_delegation(event, deleg, at=deleg.created_at)
        evidence["delegation_chain_valid"] = chain_valid
        if not chain_valid:
            return _authority("unauthorized", at, stamp, None,
                              "mandate chain is invalid: signature, tags, delegate, or "
                              "empty declared validity interval", evidence)
        evidence["delegation_created_at"] = deleg.created_at
        evidence["delegation_expiration"] = deleg.expiration()
        delegate = dlg.delegation_target(deleg)
        revs = await self.relay.query(
            {"kinds": [types.KIND_DELEGATION_REVOCATION],
             "authors": [deleg.pubkey], "#d": [delegate or ""]})
        valid = {r.id: r for r in revs
                 if r.pubkey == deleg.pubkey and dlg.is_revocation_valid(r, deleg)}
        evidence["revocations_checked"] = True
        representative: timestamp.StampVerdict | None = None
        for rev in sorted(valid.values(), key=lambda r: r.id):
            rstamp = await self.get_stamp(rev.id, headers)
            evidence["revocations"].append(
                {"id": rev.id, "created_at": rev.created_at, "stamp": rstamp})
            if representative is None or (not representative.confirmed and rstamp.confirmed):
                representative = rstamp
        detail = (
            "signatures and mandate binding verified; event ID anchored in block "
            f"{stamp.block_height} (T={at}). Applicable revocations found: {len(valid)}; "
            "history completeness is unproven. An ID timestamp does not prove signing "
            "or publication time. Two upper time bounds do not order events; created_at "
            "and mandate lifetime are signed claims, not independent measurements")
        return _authority("indeterminate", at, stamp, representative, detail, evidence)

    async def revoke_delegation(self, user_keys: Keys, delegation: Event,
                                reason: str = "",
                                extra_relays: list[str] | None = None) -> str:
        """Revoke a delegation as its owner and return the kind-31007 event ID.

        The OWNER key that signed the delegation must sign its revocation.

        **A revocation binds only relays that receive it.** A 2026-08-30 measurement
        found immediate rejection (0.0 seconds) on the relay receiving it, matching
        the README. On a second relay holding the same delegation, the stolen key kept
        publishing INDEFINITELY because revocation reached only the configured relay.

        Fan revocation out everywhere the agent could publish: configured relays and
        those in its own kind-10002 NIP-65 announcement. `extra_relays` covers any
        others known to the owner.

        No complete guarantee is possible: a relay that misses the revocation cannot
        learn it, an open-network property rather than an implementation defect. Logs
        therefore name every relay that rejected it so the owner knows where the
        revocation did NOT take effect.
        """
        rev = dlg.create_revocation(user_keys, delegation, reason=reason)
        await self._broadcast(rev)

        # Include the agent's own relay announcement and owner-supplied addresses.
        # Configured relays were already handled above.
        targets: list[str] = []
        delegate = delegation.tag_value("d") or ""
        if delegate:
            try:
                targets.extend(await self.resolve_relays(delegate))
            except Exception as e:  # noqa: BLE001 - an unavailable relay cannot cancel revocation
                log.warning("could not read the agent relay list (%s); revocation was "
                            "sent only to known addresses", e)
        targets.extend(extra_relays or [])
        targets = [u for u in dict.fromkeys(targets) if u not in self._own_relays]
        if targets:
            results = await self.publish_to_relays(rev, targets)
            failed = {u: e for u, e in results.items() if e}
            if failed:
                log.warning("REVOCATION DID NOT REACH relays: %s. The delegation remains "
                            "active there; publish the revocation manually",
                            ", ".join(failed))
        return rev.id
