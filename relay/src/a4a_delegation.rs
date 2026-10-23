//! A4A delegation chain validation.
//!
//! Mirrors `sdk-python/a4a/delegation.py::validate_delegation()`. Unlike
//! NIP-26 (`delegation.rs`), an A4A event does not carry an inline
//! delegation signature/condition string — it carries a 2-element
//! `["delegation", <delegation_event_id>]` tag that references a separate
//! kind-31000 event (see `Event::a4a_delegation_ref()` in `event.rs`).
//! Fetching that referenced event by id is an async/repo concern (outside
//! this module, see the relay-fork-integration-blueprint §2.3/§2.4); this
//! module only performs the pure crypto/tag validation once both `Event`
//! objects (the event and its claimed delegation) are in hand.

use crate::event::Event;
#[cfg(test)]
use crate::utils::unix_time;

/// Kind used for A4A delegation events. Addressable (30000–39999), keyed by
/// `d`=<delegate pubkey>: an owner holds one delegation per agent. NOT in the
/// replaceable 10000–19999 range — there it collided with NIP-51 Pin list and
/// a relay would keep only one delegation per owner (see v0.3 plan, P0).
pub const A4A_KIND_DELEGATION: u64 = 31000;

/// Kind used for A4A delegation revocation events. Addressable, keyed by
/// `d`=<delegate pubkey> -- the AGENT, not one signed copy of the delegation.
/// An owner may revoke a delegation before its `expiration` by publishing one
/// of these, signed by the same key that signed the delegation.
///
/// This doc comment said `d`=<delegation_event_id> until 04.09.2026, describing
/// the model that audit F6 replaced: re-issuing a delegation changes its event
/// id, so a revocation bound to that id left every earlier copy alive. The code
/// moved to the coordinate `31000:<owner>:<delegate>`; this comment did not, and
/// an implementer reading it would build a revocation the relay confirms with
/// OK=true and then ignores. Found by an agent that was allowed to read only the
/// docs, third wave.
pub const A4A_KIND_REVOCATION: u64 = 31007;

/// NIP-03 timestamp (kind 1040): proof that an event existed no later than a
/// Bitcoin block's time. Published by the relay notary; see specification §2.9.
pub const A4A_KIND_TIMESTAMP: u64 = 1040;

/// Validate that `delegation_event` legitimately delegates authority to
/// `event`'s author, per the 5 A4A SDK rules (`sdk-python/a4a/delegation.py`):
///
/// 1. `delegation_event.kind == 31000`
/// 2. `delegation_event`'s own signature is valid (the owner signed it) —
///    reuses `Event::validate()`, which checks both the id (sha256 of the
///    canonical form) and the Schnorr signature.
/// 3. `event`'s signature is valid — NOT re-checked here. The relay's
///    write path already runs `Event::validate()` on every incoming event
///    (see `event.rs::From<EventCmd>`) before any A4A hook can run, so by
///    the time `event` reaches this function its signature is already
///    known-good. Re-validating it here would be a redundant secp256k1
///    call on every event, not a correctness fix.
/// 4. `delegation_event`'s "delegate" tag equals `event.pubkey` — the
///    delegation was issued to this event's author.
/// 5. `delegation_event`'s "owner" tag equals `delegation_event.pubkey` —
///    anti-forgery: the claimed owner must be the actual signer.
/// 6. `expiration > now`, where `expiration` comes from the delegation's
///    "expiration" tag (NIP-40 tag name/parsing, reused via
///    `Event::expiration()`); a missing or non-numeric expiration makes
///    the delegation invalid (never panics).
/// 7. `event`'s own `["delegation", id]` tag names exactly this delegation
///    event. Callers fetch the delegation BY that id, so this looks
///    tautological -- it is not: the fetch decodes the id as hex and is
///    therefore case-insensitive, so it can return a delegation whose id is
///    not string-equal to what was asked for. Everything downstream that
///    keys off the requested spelling (the revocation lookup, the verdict
///    cache) then works on a different key than the delegation it validated.
///    Binding the two here means no future lookup path can reintroduce that
///    split without this function noticing.
/// 8. `delegation_event` carries a `d` tag equal to `delegate` and written in
///    canonical form (64 lowercase hex characters); see `delegation_target`.
#[must_use]
pub fn validate_a4a_delegation(event: &Event, delegation_event: &Event) -> bool {
    delegation_rejection(event, delegation_event).is_none()
}

/// The FIRST rule `delegation_event` breaks for `event`, as a reason a client can
/// act on — or `None` when the chain is valid.
///
/// `validate_a4a_delegation` is defined through this function on purpose: the
/// relay already had four places deciding "is this delegation valid", and three
/// findings in a row came from those places answering differently. A reason
/// string must not become a fifth decision point, so there is exactly one list
/// of rules and the boolean is derived from it.
///
/// Why reasons at all: seven distinct failures used to collapse into one string,
/// "invalid or expired A4A delegation". An agent whose owner revoked it, an agent
/// whose mandate simply expired, and a client that mis-built the `d` tag all got
/// the same answer and none of them learned what to do (third wave, finding 63).
#[must_use]
pub fn delegation_rejection(event: &Event, delegation_event: &Event) -> Option<&'static str> {
    if event.a4a_delegation_ref().as_deref() != Some(delegation_event.id.as_str()) {
        return Some("event does not reference this delegation");
    }
    if delegation_event.kind != A4A_KIND_DELEGATION {
        return Some("referenced event is not a delegation (kind 31000)");
    }
    if delegation_event.validate().is_err() {
        return Some("delegation signature is invalid");
    }
    if delegation_event.tag_values_by_name("delegate").first() != Some(&event.pubkey) {
        return Some("delegation names a different delegate than the event author");
    }
    if delegation_event.tag_values_by_name("owner").first() != Some(&delegation_event.pubkey) {
        return Some("delegation owner tag does not match its signer");
    }
    // Three outcomes: open, expired (or no deadline), clock unreadable.
    // Collapsing the third into `unix_time() == 0` revived every `exp > 0`.
    let now = crate::utils::unix_time_from(std::time::SystemTime::now());
    if now.is_none() {
        return Some("relay clock is unusable, cannot confirm the delegation is unexpired");
    }
    if !delegation_event
        .expiration()
        .is_some_and(|exp| crate::utils::deadline_still_open(exp, now) == Some(true))
    {
        return Some("delegation has expired or carries no expiration");
    }
    if delegation_target(delegation_event).is_none() {
        return Some("delegation tag d is missing, contradicts delegate, or is not canonical");
    }
    None
}

/// Canonical key spelling: exactly 64 LOWERCASE hexadecimal characters.
pub(crate) fn is_canonical_pubkey(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The delegate by which a delegation is ADDRESSED: its `d` tag. Returns `None`
/// when the tag is absent, differs from `delegate`, or is not canonical.
///
/// Why this rule exists: kind 31000 is addressed by `d`, and its revocation uses
/// the same coordinate. Delegation validation used to require only `delegate`, with
/// no `d` at all, and never compared the two tags that must agree. A delegation
/// without `d` passed validation, after which two paths diverged: authorization used
/// `delegate`, while revocation cache invalidation looked up `d` and found nothing.
/// The relay accepted the owner's revocation, yet the agent could publish for the
/// entire cache TTL (five minutes in production). A 2026-08-31 probe reproduced this
/// before the fix: the missing-`d` delegation passed and a valid revocation did not
/// clear the cache.
///
/// Case is not cosmetic here. `revocation_target` lowercases the delegate, while the
/// SQLite lookup compares tag text byte for byte. A delegation with uppercase `d`
/// would be missed just as silently. Requiring canonical input is simpler and safer
/// than normalizing three separate comparison paths.
#[must_use]
pub fn delegation_target(delegation: &Event) -> Option<String> {
    let d = delegation.tag_values_by_name("d").first()?.to_string();
    let delegate = delegation.tag_values_by_name("delegate").first()?.to_string();
    if d != delegate || !is_canonical_pubkey(&d) {
        return None;
    }
    Some(d)
}

/// The AGENT a revocation names -- the delegate pubkey in its `d` tag.
///
/// A revocation revokes an agent, not one signed copy of a delegation. Kind
/// 31000 is addressable by `d`=<delegate>, so re-issuing replaces the delegation
/// and CHANGES its event id; a revocation bound to that id left every earlier
/// copy alive, and those copies are public -- anyone could have kept one and
/// republished it on a relay that never saw the newer delegation. The
/// coordinate `31000:<owner>:<delegate>` is the one thing that survives
/// re-issuing, so that is what a revocation names (SDK-side reasoning in
/// `sdk-python/a4a/delegation.py`, audit F6).
///
/// `None` when the revocation is malformed: no `d`, or an `a` tag that
/// contradicts it. The `e` tag stays informational -- which copy the owner had
/// in hand -- and deliberately takes no part in validation, since using it would
/// reintroduce the per-copy binding.
/// The FIRST shape rule `revocation` breaks, as a reason the relay can return —
/// or `None` when its tags are well-formed. `revocation_target` is defined
/// through this so the value and the reason cannot drift apart.
///
/// Why: a revocation with an upper-case `d` and no `a` tag used to be refused
/// with "must name a delegate consistently in d and a" — about a tag the event
/// did not carry. Found on the wire by a counterparty (third wave).
#[must_use]
pub fn revocation_shape_rejection(revocation: &Event) -> Option<&'static str> {
    let d_values = revocation.tag_values_by_name("d");
    let Some(delegate) = d_values.first() else {
        return Some("A4A revocation must carry tag d = the delegate pubkey");
    };
    if !is_canonical_pubkey(delegate) {
        return Some(
            "A4A revocation tag d must be the delegate pubkey as 64 lowercase hex characters",
        );
    }
    // A revocation is permanent history and has no lifetime. With an `expiration`
    // tag, NIP-40 hides it from queries after the deadline (and another relay may
    // delete it), causing a counterparty that discovers revocations through REQ to
    // authorize the agent again. An owner would not intend this, but a library that
    // adds expiration to every event could produce it (internal finding 79).
    if revocation.tags.iter().any(|tag| tag.first().is_some_and(|name| name == "expiration")) {
        return Some(
            "A4A revocation must not carry an expiration tag: a revocation is history and \
             an expiring one would silently revive the delegation for every reader",
        );
    }
    for tag in revocation.tags.iter().filter(|tag| tag.first().is_some_and(|name| name == "a")) {
        let Some(coord) = tag.get(1) else {
            return Some("A4A revocation must name a delegate consistently in d and a");
        };
        let parts: Vec<&str> = coord.split(':').collect();
        let agrees = parts.len() == 3
            && parts[0] == A4A_KIND_DELEGATION.to_string()
            && parts[1].eq_ignore_ascii_case(&revocation.pubkey)
            && parts[2].eq_ignore_ascii_case(delegate);
        if !agrees {
            return Some("A4A revocation must name a delegate consistently in d and a");
        }
    }
    None
}

#[must_use]
pub fn revocation_target(revocation: &Event) -> Option<String> {
    if revocation_shape_rejection(revocation).is_some() {
        return None;
    }
    revocation.tag_values_by_name("d").first().cloned()
}


/// True if `revocation` really revokes `delegation`: correct kind, valid
/// signature, signed by the delegation's OWNER, naming the SAME delegate, and
/// dated no earlier than the delegation itself.
///
/// The timestamp comparison is not decoration. Without it an owner who revoked
/// an agent and later hired it again could never issue a working mandate: the
/// old revocation would ban that agent forever.
#[must_use]
pub fn validate_a4a_revocation(revocation: &Event, delegation: &Event) -> bool {
    let Some(delegate) = delegation.tag_values_by_name("delegate").first().cloned() else {
        return false;
    };
    revocation.kind == A4A_KIND_REVOCATION
        && revocation.validate().is_ok()
        && revocation.pubkey == delegation.pubkey
        && revocation_target(revocation).is_some_and(|t| t == delegate.to_lowercase())
        && revocation.created_at >= delegation.created_at
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_hashes::{sha256, Hash};
    use secp256k1::{Keypair, Secp256k1};

    /// Build an unsigned event with the given fields; id/sig are filled in
    /// by `sign_event()`.
    fn make_event(pubkey: String, kind: u64, created_at: u64, tags: Vec<Vec<String>>) -> Event {
        Event {
            id: String::new(),
            pubkey,
            delegated_by: None,
            created_at,
            kind,
            tags,
            content: String::new(),
            sig: String::new(),
            tagidx: None,
        }
    }

    /// Compute a genuine id (sha256 of the canonical form) and Schnorr
    /// signature for `event`, using `keypair`. `event.pubkey` must already
    /// match `keypair`'s x-only public key.
    fn sign_event(mut event: Event, keypair: &Keypair) -> Event {
        let secp = Secp256k1::new();
        let canonical = event.to_canonical().expect("canonicalize");
        let digest: sha256::Hash = sha256::Hash::hash(canonical.as_bytes());
        event.id = format!("{digest:x}");
        let sig = secp.sign_schnorr_no_aux_rand(digest.as_ref(), keypair);
        event.sig = sig.to_string();
        event
    }

    struct Chain {
        owner_keypair: Keypair,
        owner_pubkey: String,
        agent_keypair: Keypair,
        agent_pubkey: String,
    }

    fn make_chain() -> Chain {
        let secp = Secp256k1::new();
        let mut rng = secp256k1::rand::thread_rng();
        let owner_keypair = Keypair::new(&secp, &mut rng);
        let owner_pubkey = owner_keypair.x_only_public_key().0.to_string();
        let agent_keypair = Keypair::new(&secp, &mut rng);
        let agent_pubkey = agent_keypair.x_only_public_key().0.to_string();
        Chain {
            owner_keypair,
            owner_pubkey,
            agent_keypair,
            agent_pubkey,
        }
    }

    /// A valid, unexpired delegation event signed by `owner`, delegating to
    /// `agent_pubkey`, with `owner` tag equal to the real signer.
    fn valid_delegation_event(chain: &Chain, expiration: u64) -> Event {
        let delegation = make_event(
            chain.owner_pubkey.clone(),
            A4A_KIND_DELEGATION,
            1_000,
            vec![
                // `d` is required: kind 31000 is addressed by delegate, and its
                // revocation is looked up through the same coordinate.
                vec!["d".to_owned(), chain.agent_pubkey.clone()],
                vec!["delegate".to_owned(), chain.agent_pubkey.clone()],
                vec!["owner".to_owned(), chain.owner_pubkey.clone()],
                vec!["expiration".to_owned(), expiration.to_string()],
            ],
        );
        sign_event(delegation, &chain.owner_keypair)
    }

    /// A valid event signed by the agent, referencing `delegation_id`.
    fn agent_event(chain: &Chain, delegation_id: &str) -> Event {
        let event = make_event(
            chain.agent_pubkey.clone(),
            1,
            1_000,
            vec![vec!["delegation".to_owned(), delegation_id.to_owned()]],
        );
        sign_event(event, &chain.agent_keypair)
    }

    fn future_expiration() -> u64 {
        unix_time() + 3600
    }

    fn past_expiration() -> u64 {
        unix_time().saturating_sub(3600)
    }

    // 1. valid chain -> true
    #[test]
    fn valid_chain_is_accepted() {
        let chain = make_chain();
        let delegation = valid_delegation_event(&chain, future_expiration());
        let event = agent_event(&chain, &delegation.id);
        assert!(validate_a4a_delegation(&event, &delegation));
    }

    // 2. delegation.kind != 10001 -> false
    #[test]
    fn wrong_kind_is_rejected() {
        let chain = make_chain();
        let mut delegation = make_event(
            chain.owner_pubkey.clone(),
            1, // not 10001
            1_000,
            vec![
                vec!["d".to_owned(), chain.agent_pubkey.clone()],
                vec!["delegate".to_owned(), chain.agent_pubkey.clone()],
                vec!["owner".to_owned(), chain.owner_pubkey.clone()],
                vec!["expiration".to_owned(), future_expiration().to_string()],
            ],
        );
        delegation = sign_event(delegation, &chain.owner_keypair);
        let event = agent_event(&chain, &delegation.id);
        assert!(!validate_a4a_delegation(&event, &delegation));
    }

    // 3. delegation signature invalid (tampered after signing) -> false
    #[test]
    fn invalid_delegation_signature_is_rejected() {
        let chain = make_chain();
        let mut delegation = valid_delegation_event(&chain, future_expiration());
        let event = agent_event(&chain, &delegation.id);
        // Tamper the signature bytes without changing id/content, so the
        // id still "matches" the (stale) canonical hash but the Schnorr
        // signature no longer verifies.
        delegation.sig = "0".repeat(128);
        assert!(!validate_a4a_delegation(&event, &delegation));
    }

    // 4. delegate != event.pubkey -> false
    #[test]
    fn delegate_mismatch_is_rejected() {
        let chain = make_chain();
        let other_agent = "f".repeat(64);
        let mut delegation = make_event(
            chain.owner_pubkey.clone(),
            A4A_KIND_DELEGATION,
            1_000,
            vec![
                vec!["d".to_owned(), other_agent.clone()],
                vec!["delegate".to_owned(), other_agent], // not chain.agent_pubkey
                vec!["owner".to_owned(), chain.owner_pubkey.clone()],
                vec!["expiration".to_owned(), future_expiration().to_string()],
            ],
        );
        delegation = sign_event(delegation, &chain.owner_keypair);
        let event = agent_event(&chain, &delegation.id);
        assert!(!validate_a4a_delegation(&event, &delegation));
    }

    // 5. owner tag != delegation signer (spoofed owner) -> false
    #[test]
    fn spoofed_owner_is_rejected() {
        let chain = make_chain();
        let spoofed_owner = "a".repeat(64);
        let mut delegation = make_event(
            chain.owner_pubkey.clone(), // actually signed by chain.owner_keypair
            A4A_KIND_DELEGATION,
            1_000,
            vec![
                vec!["d".to_owned(), chain.agent_pubkey.clone()],
                vec!["delegate".to_owned(), chain.agent_pubkey.clone()],
                vec!["owner".to_owned(), spoofed_owner], // does not match signer
                vec!["expiration".to_owned(), future_expiration().to_string()],
            ],
        );
        delegation = sign_event(delegation, &chain.owner_keypair);
        let event = agent_event(&chain, &delegation.id);
        assert!(!validate_a4a_delegation(&event, &delegation));
    }

    // 6. expired -> false
    #[test]
    fn expired_delegation_is_rejected() {
        let chain = make_chain();
        let delegation = valid_delegation_event(&chain, past_expiration());
        let event = agent_event(&chain, &delegation.id);
        assert!(!validate_a4a_delegation(&event, &delegation));
    }

    // Canonical-form rule on the REVOCATION side (internal audit, 2026-09-04).
    // Before the fix, `.to_lowercase()` let an uppercase-key revocation validate and
    // receive OK=true, but the later lowercase lookup could not find it.
    #[test]
    fn revocation_with_upper_case_delegate_is_rejected() {
        let chain = make_chain();
        let delegation = valid_delegation_event(&chain, future_expiration());
        let mut revocation = valid_revocation_event(&chain, &delegation);
        // Uppercase ONLY `d`; keep `a` unchanged so the canonical-form check, not
        // coordinate consistency, is what makes the test fail.
        revocation.tags[0] = vec!["d".to_owned(), chain.agent_pubkey.to_uppercase()];
        let revocation = sign_event(revocation, &chain.owner_keypair);
        // Precondition: the signature remains valid, so this case is wire-reachable.
        assert!(revocation.validate().is_ok(), "test setup produced an invalid event");
        assert!(revocation_target(&revocation).is_none());
        assert!(!validate_a4a_revocation(&revocation, &delegation));
    }

    #[test]
    fn revocation_target_returns_the_key_when_it_is_canonical() {
        let chain = make_chain();
        let delegation = valid_delegation_event(&chain, future_expiration());
        let revocation = valid_revocation_event(&chain, &delegation);
        assert_eq!(
            revocation_target(&revocation).as_deref(),
            Some(chain.agent_pubkey.as_str())
        );
    }

    #[test]
    fn every_revocation_coordinate_must_agree_and_history_never_expires() {
        let chain = make_chain();
        let delegation = valid_delegation_event(&chain, future_expiration());
        for extra in [vec!["a".to_owned()], vec!["a".to_owned(), "31001:wrong:wrong".to_owned()], vec!["expiration".to_owned()]] {
            let mut revocation = valid_revocation_event(&chain, &delegation);
            revocation.tags.push(extra);
            let revocation = sign_event(revocation, &chain.owner_keypair);
            assert!(!validate_a4a_revocation(&revocation, &delegation));
        }
        let mut revocation = valid_revocation_event(&chain, &delegation);
        for tag in &mut revocation.tags {
            if tag[0] == "a" {
                tag[1] = tag[1].to_uppercase();
                tag.push("wss://relay.example.com".to_owned());
            }
        }
        let revocation = sign_event(revocation, &chain.owner_keypair);
        assert!(validate_a4a_revocation(&revocation, &delegation));
    }

    // 7a. non-numeric expiration -> false
    #[test]
    fn non_numeric_expiration_is_rejected() {
        let chain = make_chain();
        let mut delegation = make_event(
            chain.owner_pubkey.clone(),
            A4A_KIND_DELEGATION,
            1_000,
            vec![
                vec!["d".to_owned(), chain.agent_pubkey.clone()],
                vec!["delegate".to_owned(), chain.agent_pubkey.clone()],
                vec!["owner".to_owned(), chain.owner_pubkey.clone()],
                vec!["expiration".to_owned(), "not-a-number".to_owned()],
            ],
        );
        delegation = sign_event(delegation, &chain.owner_keypair);
        let event = agent_event(&chain, &delegation.id);
        assert!(!validate_a4a_delegation(&event, &delegation));
    }

    // 7b. absent expiration tag -> false
    #[test]
    fn absent_expiration_is_rejected() {
        let chain = make_chain();
        let mut delegation = make_event(
            chain.owner_pubkey.clone(),
            A4A_KIND_DELEGATION,
            1_000,
            vec![
                vec!["d".to_owned(), chain.agent_pubkey.clone()],
                vec!["delegate".to_owned(), chain.agent_pubkey.clone()],
                vec!["owner".to_owned(), chain.owner_pubkey.clone()],
                // no "expiration" tag at all
            ],
        );
        delegation = sign_event(delegation, &chain.owner_keypair);
        let event = agent_event(&chain, &delegation.id);
        assert!(!validate_a4a_delegation(&event, &delegation));
    }

    /// A valid, owner-signed revocation of the AGENT. `created_at` is 2 000 —
    /// later than the delegations built at 1 000, as a real revocation always is.
    fn valid_revocation_event(chain: &Chain, delegation: &Event) -> Event {
        let revocation = make_event(
            chain.owner_pubkey.clone(),
            A4A_KIND_REVOCATION,
            2_000,
            vec![
                vec!["d".to_owned(), chain.agent_pubkey.clone()],
                vec![
                    "a".to_owned(),
                    format!(
                        "{}:{}:{}",
                        A4A_KIND_DELEGATION, chain.owner_pubkey, chain.agent_pubkey
                    ),
                ],
                vec!["e".to_owned(), delegation.id.clone()],
            ],
        );
        sign_event(revocation, &chain.owner_keypair)
    }

    // 9c. FINDING F6 -- a revocation must cover EVERY copy of the delegation.
    // Kind 31000 is addressable, so re-issuing replaces it and changes its event
    // id; a revocation bound to that id left earlier copies alive, and those
    // copies are public. The owner revoked, the agent kept publishing.
    #[test]
    fn revocation_covers_an_earlier_copy_of_the_delegation() {
        let chain = make_chain();
        let old_copy = valid_delegation_event(&chain, future_expiration());
        let revocation = valid_revocation_event(&chain, &old_copy);
        assert!(validate_a4a_revocation(&revocation, &old_copy));
    }

    // 9d. A revocation must NOT ban the agent forever: an owner who revokes and
    // later hires the same agent again must be able to issue a working mandate.
    #[test]
    fn revocation_does_not_cover_a_later_delegation() {
        let chain = make_chain();
        let old_copy = valid_delegation_event(&chain, future_expiration());
        let revocation = valid_revocation_event(&chain, &old_copy);
        let mut rehired = make_event(
            chain.owner_pubkey.clone(),
            A4A_KIND_DELEGATION,
            revocation.created_at + 1,
            vec![
                vec!["d".to_owned(), chain.agent_pubkey.clone()],
                vec!["delegate".to_owned(), chain.agent_pubkey.clone()],
                vec!["owner".to_owned(), chain.owner_pubkey.clone()],
                vec!["expiration".to_owned(), future_expiration().to_string()],
            ],
        );
        rehired = sign_event(rehired, &chain.owner_keypair);
        assert!(!validate_a4a_revocation(&revocation, &rehired));
    }

    // 9. valid owner-signed revocation -> true
    #[test]
    fn valid_revocation_is_accepted() {
        let chain = make_chain();
        let delegation = valid_delegation_event(&chain, future_expiration());
        let revocation = valid_revocation_event(&chain, &delegation);
        assert!(validate_a4a_revocation(&revocation, &delegation));
    }

    // 10. revocation signed by a non-owner -> false
    #[test]
    fn revocation_by_non_owner_is_rejected() {
        let chain = make_chain();
        let delegation = valid_delegation_event(&chain, future_expiration());
        // signed by the agent keypair instead of the owner keypair.
        let mut revocation = make_event(
            chain.agent_pubkey.clone(),
            A4A_KIND_REVOCATION,
            2_000,
            vec![
                vec!["d".to_owned(), delegation.id.clone()],
                vec!["e".to_owned(), delegation.id.clone()],
                vec!["delegate".to_owned(), chain.agent_pubkey.clone()],
            ],
        );
        revocation = sign_event(revocation, &chain.agent_keypair);
        assert!(!validate_a4a_revocation(&revocation, &delegation));
    }

    // 11. revocation's "e" tag points at a different delegation id -> false
    #[test]
    fn revocation_wrong_delegation_ref_is_rejected() {
        let chain = make_chain();
        let delegation = valid_delegation_event(&chain, future_expiration());
        let other_delegation_id = "e".repeat(64);
        let mut revocation = make_event(
            chain.owner_pubkey.clone(),
            A4A_KIND_REVOCATION,
            2_000,
            vec![
                vec!["d".to_owned(), other_delegation_id.clone()],
                vec!["e".to_owned(), other_delegation_id],
                vec!["delegate".to_owned(), chain.agent_pubkey.clone()],
            ],
        );
        revocation = sign_event(revocation, &chain.owner_keypair);
        assert!(!validate_a4a_revocation(&revocation, &delegation));
    }

    // 12. wrong kind -> false
    #[test]
    fn revocation_wrong_kind_is_rejected() {
        let chain = make_chain();
        let delegation = valid_delegation_event(&chain, future_expiration());
        let mut revocation = make_event(
            chain.owner_pubkey.clone(),
            1, // not 31007
            2_000,
            vec![
                vec!["d".to_owned(), delegation.id.clone()],
                vec!["e".to_owned(), delegation.id.clone()],
                vec!["delegate".to_owned(), chain.agent_pubkey.clone()],
            ],
        );
        revocation = sign_event(revocation, &chain.owner_keypair);
        assert!(!validate_a4a_revocation(&revocation, &delegation));
    }

    // 7b. A delegation event that is valid in every other respect, but is NOT
    // the one the event's own tag names, must be rejected. Callers fetch by
    // id, so this can only happen when the fetch is laxer than string
    // equality (hex decoding is case-insensitive) -- exactly the split that
    // let a revoked delegation keep working. Kept as a standalone rule so no
    // future lookup path can reintroduce it silently.
    #[test]
    fn delegation_not_named_by_the_event_is_rejected() {
        let chain = make_chain();
        let delegation = valid_delegation_event(&chain, future_expiration());
        let event = agent_event(&chain, &"f".repeat(64));
        assert!(!validate_a4a_delegation(&event, &delegation));
    }

    // 13. FINDING 54 -- a delegation without a `d` tag. Everything else is valid:
    // owner signature, `delegate`, `owner`, and expiration. But kind 31000 is
    // addressed by `d`, and revocation uses the same coordinate. Cache invalidation
    // silently misses such a delegation, letting the revoked agent publish for the
    // entire cache TTL.
    #[test]
    fn delegation_without_d_tag_is_rejected() {
        let chain = make_chain();
        let mut delegation = make_event(
            chain.owner_pubkey.clone(),
            A4A_KIND_DELEGATION,
            1_000,
            vec![
                vec!["delegate".to_owned(), chain.agent_pubkey.clone()],
                vec!["owner".to_owned(), chain.owner_pubkey.clone()],
                vec!["expiration".to_owned(), future_expiration().to_string()],
            ],
        );
        delegation = sign_event(delegation, &chain.owner_keypair);
        let event = agent_event(&chain, &delegation.id);
        assert!(!validate_a4a_delegation(&event, &delegation));
    }

    // 14. `d` exists but names a DIFFERENT delegate from `delegate`: authorization
    // would use one tag while revocation used the other.
    #[test]
    fn delegation_with_contradictory_d_tag_is_rejected() {
        let chain = make_chain();
        let mut delegation = make_event(
            chain.owner_pubkey.clone(),
            A4A_KIND_DELEGATION,
            1_000,
            vec![
                vec!["d".to_owned(), "b".repeat(64)],
                vec!["delegate".to_owned(), chain.agent_pubkey.clone()],
                vec!["owner".to_owned(), chain.owner_pubkey.clone()],
                vec!["expiration".to_owned(), future_expiration().to_string()],
            ],
        );
        delegation = sign_event(delegation, &chain.owner_keypair);
        let event = agent_event(&chain, &delegation.id);
        assert!(!validate_a4a_delegation(&event, &delegation));
    }

    // 15. The same path through letter case; a valid test setup matters here.
    //
    // The first version uppercased the key ONLY in the delegation and left the agent
    // event lowercase. Rule 4 (`delegate` != `event.pubkey`) rejected that delegation,
    // so the test passed for the wrong reason and survived removal of the case check.
    // Mutation testing exposed the mistake.
    //
    // The key is therefore uppercase EVERYWHERE: the event is signed with the same
    // spelling used by the delegation. The data is internally consistent, the
    // signature is real, and rule 4 passes. Only the canonical-form rule can reject it.
    //
    // This is wire-reachable, not hypothetical. The relay does not lowercase `pubkey`:
    // `Event::validate()` checks the canonical id and signature, while hex key parsing
    // is case-insensitive. The first assertion records that precondition. Another
    // implementation can therefore send this event and obtain a delegation that cannot
    // be revoked: `revocation_target` lowercases the delegate while SQLite compares the
    // tag text byte for byte.
    #[test]
    fn delegation_with_upper_case_key_is_rejected() {
        let chain = make_chain();
        let shouty = chain.agent_pubkey.to_uppercase();
        let mut delegation = make_event(
            chain.owner_pubkey.clone(),
            A4A_KIND_DELEGATION,
            1_000,
            vec![
                vec!["d".to_owned(), shouty.clone()],
                vec!["delegate".to_owned(), shouty.clone()],
                vec!["owner".to_owned(), chain.owner_pubkey.clone()],
                vec!["expiration".to_owned(), future_expiration().to_string()],
            ],
        );
        delegation = sign_event(delegation, &chain.owner_keypair);

        let event = make_event(
            shouty,
            1,
            1_000,
            vec![vec!["delegation".to_owned(), delegation.id.clone()]],
        );
        let event = sign_event(event, &chain.agent_keypair);

        // Test precondition: if the relay starts rejecting non-canonical pubkeys on its
        // own, this assertion will fail and show that the rule below became redundant.
        assert!(
            event.validate().is_ok(),
            "precondition changed: the relay no longer accepts uppercase pubkeys"
        );
        assert_eq!(
            delegation.tag_values_by_name("delegate").first(),
            Some(&event.pubkey),
            "invalid setup: rule 4 must pass or the test succeeds for the wrong reason"
        );

        assert!(!validate_a4a_delegation(&event, &delegation));
    }

    // 16. The `delegation_target` contract in isolation.
    //
    // `validate_a4a_delegation` cannot reach the length check: rule 4 requires
    // `delegate` to match `event.pubkey`, which is always 64 characters in a signed
    // event. Removing the length check therefore survived mutation testing, not because
    // it was redundant, but because a neighboring rule masked it. That coupling is
    // unsafe: rule 4 may change while `d` goes directly into a lookup query. This public
    // function's contract is therefore tested directly.
    #[test]
    fn delegation_target_demands_a_full_length_key() {
        let short = "abc123";
        let event = make_event(
            "0".repeat(64),
            A4A_KIND_DELEGATION,
            1_000,
            vec![
                vec!["d".to_owned(), short.to_owned()],
                vec!["delegate".to_owned(), short.to_owned()],
            ],
        );
        assert_eq!(delegation_target(&event), None, "short key was accepted");
    }

    #[test]
    fn delegation_target_returns_the_key_when_tags_agree() {
        let key = "a".repeat(64);
        let event = make_event(
            "0".repeat(64),
            A4A_KIND_DELEGATION,
            1_000,
            vec![
                vec!["d".to_owned(), key.clone()],
                vec!["delegate".to_owned(), key.clone()],
            ],
        );
        assert_eq!(
            delegation_target(&event),
            Some(key),
            "matching tags must return the delegate, or rule 8 would reject every \
             delegation without the negative tests noticing"
        );
    }

    // 8. a4a_delegation_ref extracts id from a 2-element ["delegation", id] tag
    #[test]
    fn a4a_delegation_ref_extracts_id() {
        let mut event = Event::simple_event();
        event.tags = vec![vec!["delegation".to_owned(), "abc123".to_owned()]];
        assert_eq!(event.a4a_delegation_ref(), Some("abc123".to_owned()));
    }

    // 8b. a4a_delegation_ref returns None when the tag is absent
    #[test]
    fn a4a_delegation_ref_none_when_absent() {
        let event = Event::simple_event();
        assert_eq!(event.a4a_delegation_ref(), None);
    }

    // 8c. a4a_delegation_ref does not confuse the 4-element NIP-26 tag
    // (same tag name, different arity) with the 2-element A4A form.
    #[test]
    fn a4a_delegation_ref_ignores_nip26_style_tag() {
        let mut event = Event::simple_event();
        event.tags = vec![vec![
            "delegation".to_owned(),
            "delegator".to_owned(),
            "kind=1".to_owned(),
            "sig".to_owned(),
        ]];
        assert_eq!(event.a4a_delegation_ref(), None);
    }
}
