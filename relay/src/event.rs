//! Event parsing and validation
use crate::delegation::validate_delegation;
use crate::error::Error::{
    CommandUnknownError, EventCouldNotCanonicalize, EventInvalidId, EventInvalidSignature,
    EventMalformedPubkey,
};
use crate::error::Result;
use crate::event::EventWrapper::WrappedAuth;
use crate::event::EventWrapper::WrappedEvent;
use crate::nip05;
use crate::utils::unix_time;
use bitcoin_hashes::{sha256, Hash};
use lazy_static::lazy_static;
use secp256k1::{schnorr, Secp256k1, VerifyOnly, XOnlyPublicKey};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::value::Value;
use serde_json::Number;
use std::collections::HashMap;
use std::collections::HashSet;
use std::str::FromStr;
use tracing::debug;
use crate::subscription::TagOperand;

lazy_static! {
    /// Secp256k1 verification instance.
    pub static ref SECP: Secp256k1<VerifyOnly> = Secp256k1::verification_only();
}

/// Event command in network format.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct EventCmd {
    // expecting static "EVENT"
    cmd: String,
    event: Event,
}

impl EventCmd {
    #[must_use]
    pub fn event_id(&self) -> &str {
        &self.event.id
    }
}

/// Parsed nostr event.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Event {
    pub id: String,
    pub pubkey: String,
    #[serde(skip)]
    pub delegated_by: Option<String>,
    pub created_at: u64,
    pub kind: u64,
    #[serde(deserialize_with = "tag_from_string")]
    // NOTE: array-of-arrays may need to be more general than a string container
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
    // Optimization for tag search, built on demand.
    #[serde(skip)]
    pub tagidx: Option<HashMap<String, HashSet<String>>>,
}

/// Simple tag type for array of array of strings.
type Tag = Vec<Vec<String>>;

/// Hard cap on the number of MULTI-char-named tags a single event will
/// have INDEXED into the `tag` table (see F2: every non-empty tag name is
/// now indexed, not just single-char NIP-01/NIP-12 tags). Without a cap,
/// an attacker can pack thousands of throwaway multi-char tags into one
/// event (bounded only by `max_event_bytes`, ~128KB) and cause unbounded
/// `tag`-table bloat per event. Multi-char tags beyond the cap are simply
/// not indexed -- the event itself (and its full tag list, in the stored
/// JSON) is still accepted and persisted unchanged; only server-side
/// `#tag` filter matching on the excess multi-char tags stops working.
///
/// This cap does NOT apply to single-char tag names (see
/// [`single_char_tagname`]) such as `d`/`e`/`p`/`a` -- those are ALWAYS
/// indexed regardless of how many tags precede them in the event's tag
/// array. NIP-01 thread/mention search (`#e`/`#p`) and parameterized-
/// replaceable dedup (queries on `t.name='d'`, which every 31xxx A4A event
/// relies on) depend on single-char tags being indexed unconditionally; an
/// event with >100 tags whose `d`/`e`/`p` tags happen to land after
/// position 100 must not silently lose that indexing. The cap only bounds
/// the F2 multi-char discovery tags, which are the actual DB-bloat vector
/// this constant targets. A legitimate A4A event (e.g. Intent) has on the
/// order of 10 tags, so 100 leaves generous headroom.
pub const MAX_INDEXED_TAGS_PER_EVENT: usize = 100;

/// Deserializer that ensures we always have a [`Tag`].
fn tag_from_string<'de, D>(deserializer: D) -> Result<Tag, D::Error>
    where
        D: Deserializer<'de>,
{
    let opt = Option::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

/// Attempt to form a single-char tag name.
#[must_use]
pub fn single_char_tagname(tagname: &str) -> Option<char> {
    // We return the tag character if and only if the tagname consists
    // of a single char.
    let mut tagnamechars = tagname.chars();
    let firstchar = tagnamechars.next();
    match firstchar {
        Some(_) => {
            // check second char
            if tagnamechars.next().is_none() {
                firstchar
            } else {
                None
            }
        }
        None => None,
    }
}

pub enum EventWrapper {
    WrappedEvent(Event),
    WrappedAuth(Event),
}

/// Convert network event to parsed/validated event.
impl From<EventCmd> for Result<EventWrapper> {
    fn from(ec: EventCmd) -> Result<EventWrapper> {
        // ensure command is correct
        if ec.cmd == "EVENT" {
            ec.event.validate().map(|_| {
                let mut e = ec.event;
                e.build_index();
                e.update_delegation();
                WrappedEvent(e)
            })
        } else if ec.cmd == "AUTH" {
            // we don't want to validate the event here, because NIP-42 can be disabled
            // it will be validated later during the authentication process
            Ok(WrappedAuth(ec.event))
        } else {
            Err(CommandUnknownError)
        }
    }
}

impl Event {
    #[cfg(test)]
    #[must_use]
    pub fn simple_event() -> Event {
        Event {
            id: "0".to_owned(),
            pubkey: "0".to_owned(),
            delegated_by: None,
            created_at: 0,
            kind: 0,
            tags: vec![],
            content: "".to_owned(),
            sig: "0".to_owned(),
            tagidx: None,
        }
    }

    #[must_use]
    pub fn is_kind_metadata(&self) -> bool {
        self.kind == 0
    }

    /// Should this event be persisted?
    #[must_use]
    pub fn is_ephemeral(&self) -> bool {
        self.kind >= 20000 && self.kind < 30000
    }

    /// Whether an `expiration` tag carries a value the relay could NOT parse.
    ///
    /// Finding 125: values such as `"+1788556527"` and `"05"` made an event immortal.
    /// `expiration()` silently discarded the unreadable value, so the event appeared
    /// unbounded, was accepted even when its intended deadline was past, and was always
    /// returned. This is a one-step NIP-40 bypass. Expiration is the only number the
    /// relay parses itself, so rule 7 requires canonical spelling and rejects any other.
    #[must_use]
    pub fn has_malformed_expiration(&self) -> bool {
        self.tags
            .iter()
            .filter(|t| t.len() > 1 && t[0] == "expiration")
            .any(|t| crate::utils::parse_canonical_u64(&t[1]).is_none())
    }

    /// Is this event currently expired?
    pub fn is_expired(&self) -> bool {
        // No clock: fail closed. Treating that as "now == 0" kept expired
        // events alive whenever `exp > 0`.
        let Some(now) = crate::utils::unix_time_from(std::time::SystemTime::now()) else {
            return true;
        };
        self.expiration().is_some_and(|exp| exp <= now)
    }

    /// Determine the time at which this event should expire
    pub fn expiration(&self) -> Option<u64> {
        // From multiple `expiration` tags, use the NEAREST deadline rather than the first.
        //
        // NIP-40 describes one such tag, but clients can send two. This is practical:
        // a library may add a default deadline before caller code adds its own, leaving
        // both in the event. Before 2026-09-04, `.take(1)` made array order decisive.
        // Our live-check script exposed the issue by appending "one hour" AFTER the
        // SDK's "thirty days," believing it would leave production data for an hour
        // while test events actually remained for a month.
        //
        // The minimum is the only safe choice: a second tag must not extend the lifetime
        // the event assigned to itself.
        self.tags
            .iter()
            .filter(|t| t.len() > 1 && t[0] == "expiration")
            .filter_map(|t| crate::utils::parse_canonical_u64(&t[1]))
            .min()
    }

    /// Should this event be replaced with newer timestamps from same author?
    #[must_use]
    pub fn is_replaceable(&self) -> bool {
        self.kind == 0
            || self.kind == 3
            || self.kind == 41
            || (self.kind >= 10000 && self.kind < 20000)
    }

    /// Should this event be replaced with newer timestamps from same author, for distinct `d` tag values?
    #[must_use]
    pub fn is_param_replaceable(&self) -> bool {
        self.kind >= 30000 && self.kind < 40000
    }

    /// Should this event be replaced with newer timestamps from same author, for distinct `d` tag values?
    #[must_use]
    pub fn distinct_param(&self) -> Option<String> {
        if self.is_param_replaceable() {
            let default = "".to_string();
            let dvals: Vec<&String> = self
                .tags
                .iter()
                .filter(|x| !x.is_empty())
                .filter(|x| x.first().unwrap() == "d")
                .map(|x| x.get(1).unwrap_or(&default))
                .take(1)
                .collect();
            let dval_first = dvals.first();
            match dval_first {
                Some(_) => dval_first.map(|x| x.to_string()),
                None => Some(default),
            }
        } else {
            None
        }
    }

    /// Pull a NIP-05 Name out of the event, if one exists
    #[must_use]
    pub fn get_nip05_addr(&self) -> Option<nip05::Nip05Name> {
        if self.is_kind_metadata() {
            // very quick check if we should attempt to parse this json
            if self.content.contains("\"nip05\"") {
                // Parse into JSON
                let md_parsed: Value = serde_json::from_str(&self.content).ok()?;
                let md_map = md_parsed.as_object()?;
                let nip05_str = md_map.get("nip05")?.as_str()?;
                return nip05::Nip05Name::try_from(nip05_str).ok();
            }
        }
        None
    }

    // is this event delegated (properly)?
    // does the signature match, and are conditions valid?
    // if so, return an alternate author for the event
    #[must_use]
    pub fn delegated_author(&self) -> Option<String> {
        // is there a delegation tag?
        let delegation_tag: Vec<String> = self
            .tags
            .iter()
            .filter(|x| x.len() == 4)
            .filter(|x| x.first().unwrap() == "delegation")
            .take(1)
            .next()?
            .clone(); // get first tag

        //let delegation_tag = self.tag_values_by_name("delegation");
        // delegation tags should have exactly 3 elements after the name (pubkey, condition, sig)
        // the event is signed by the delagatee
        let delegatee = &self.pubkey;
        // the delegation tag references the claimed delagator
        let delegator: &str = delegation_tag.get(1)?;
        let querystr: &str = delegation_tag.get(2)?;
        let sig: &str = delegation_tag.get(3)?;

        // attempt to get a condition query; this requires the delegation to have a valid signature.
        if let Some(cond_query) = validate_delegation(delegator, delegatee, querystr, sig) {
            // The signature was valid, now we ensure the delegation
            // condition is valid for this event:
            if cond_query.allows_event(self) {
                // since this is allowed, we will provide the delegatee
                Some(delegator.into())
            } else {
                debug!("an event failed to satisfy delegation conditions");
                None
            }
        } else {
            debug!("event had had invalid delegation signature");
            None
        }
    }

    /// Update delegation status
    pub fn update_delegation(&mut self) {
        self.delegated_by = self.delegated_author();
    }

    /// Extract the referenced A4A delegation event id, if present.
    ///
    /// A4A delegation tags are `["delegation", <delegation_event_id>]` —
    /// exactly 2 elements. This is distinct from (and does not collide
    /// with) NIP-26's `delegated_author()`, which only looks at 4-element
    /// `delegation` tags (`[delegator, cond_query, sig]` after the name).
    /// This is pure tag extraction, no crypto: the actual delegation event
    /// referenced by this id must be fetched and validated separately (see
    /// `a4a_delegation::validate_a4a_delegation`).
    ///
    /// The id is lower-cased here, and this is a security property, not
    /// cosmetics. It is the ONLY place the relay learns a delegation id, and
    /// downstream that id is used two different ways: `get_event_by_id`
    /// decodes it as hex (case-insensitive), while the revocation lookup
    /// matches it against a stored `d` tag as a STRING (case-sensitive).
    /// Without a canonical form those two disagree: upper-casing the id still
    /// finds the delegation but no longer finds its revocation, and a revoked
    /// agent keeps publishing. Same for the verdict cache, whose key is this
    /// string -- two spellings meant two independent cache entries, and
    /// evicting one left the other admitting events.
    #[must_use]
    pub fn a4a_delegation_ref(&self) -> Option<String> {
        self.tags
            .iter()
            .filter(|x| x.len() == 2)
            .filter(|x| x.first().unwrap() == "delegation")
            .map(|x| x.get(1).unwrap().to_lowercase())
            .take(1)
            .next()
    }
    /// Build an event tag index
    pub fn build_index(&mut self) {
        // if there are no tags; just leave the index as None
        if self.tags.is_empty() {
            return;
        }
        // otherwise, build an index
        // NOTE: Option B (A4A discovery) indexes tags of ANY name length
        // (>=1 char), not just single-char NIP-01/NIP-12 tags. This is what
        // allows multi-char tags like "category"/"intent_type" to be
        // queryable via `#category` filters (see subscription.rs).
        let mut idx: HashMap<String, HashSet<String>> = HashMap::new();
        // iterate over tags that have at least 2 elements
        for t in self.tags.iter().filter(|x| x.len() > 1) {
            let tagname = t.first().unwrap();
            if tagname.is_empty() {
                continue;
            }
            let tagval = t.get(1).unwrap();
            // ensure a vector exists for this tag
            idx.entry(tagname.clone()).or_default();
            // get the tag vec and insert entry
            let idx_tag_vec = idx.get_mut(tagname).expect("could not get tag vector");
            idx_tag_vec.insert(tagval.clone());
        }
        // save the tag structure
        self.tagidx = Some(idx);
    }

    /// Create a short event identifier, suitable for logging.
    #[must_use]
    pub fn get_event_id_prefix(&self) -> String {
        self.id.chars().take(8).collect()
    }
    #[must_use]
    pub fn get_author_prefix(&self) -> String {
        self.pubkey.chars().take(8).collect()
    }

    /// Retrieve tag initial values across all tags matching the name
    #[must_use]
    pub fn tag_values_by_name(&self, tag_name: &str) -> Vec<String> {
        self.tags
            .iter()
            .filter(|x| x.len() > 1)
            .filter(|x| x.first().unwrap() == tag_name)
            .map(|x| x.get(1).unwrap().clone())
            .collect()
    }

    #[must_use]
    pub fn is_valid_timestamp(&self, reject_future_seconds: Option<usize>) -> bool {
        if let Some(allowable_future) = reject_future_seconds {
            let curr_time = unix_time();
            // Saturate: a failed clock is `u64::MAX`, and `+` would panic in debug.
            let limit = curr_time.saturating_add(allowable_future as u64);
            if limit < self.created_at {
                let delta = self.created_at - curr_time;
                debug!(
                    "event is too far in the future ({} seconds), rejecting",
                    delta
                );
                return false;
            }
        }
        true
    }

    /// Check if this event has a valid signature.
    pub fn validate(&self) -> Result<()> {
        // Diagnostic limitation inherited from upstream: invalid events return a
        // generic validation error; detailed reasons stay in debug logging.
        // validation is performed by:
        // * parsing JSON string into event fields
        // * create an array:
        // ** [0, pubkey-hex-string, created-at-num, kind-num, tags-array-of-arrays, content-string]
        // * serialize with no spaces/newlines
        let c_opt = self.to_canonical();
        if c_opt.is_none() {
            debug!("could not canonicalize");
            return Err(EventCouldNotCanonicalize);
        }
        let c = c_opt.unwrap();
        // * compute the sha256sum.
        let digest: sha256::Hash = sha256::Hash::hash(c.as_bytes());
        let hex_digest = format!("{digest:x}");
        // * ensure the id matches the computed sha256sum.
        if self.id != hex_digest {
            debug!("event id does not match digest");
            return Err(EventInvalidId);
        }
        // * validate the message digest (sig) using the pubkey & computed sha256 message hash.
        let sig = schnorr::Signature::from_str(&self.sig).map_err(|_| EventInvalidSignature)?;
        // secp256k1 0.30 accepts the MESSAGE as a byte slice. The intermediate
        // `Message::from_slice` in 0.21 existed to validate a length of 32, which is
        // redundant here because this digest is a SHA-256 output and cannot vary in size.
        let Ok(pubkey) = XOnlyPublicKey::from_str(&self.pubkey) else {
            debug!("client sent malformed pubkey");
            return Err(EventMalformedPubkey);
        };
        SECP.verify_schnorr(&sig, digest.as_ref(), &pubkey)
            .map_err(|_| EventInvalidSignature)
    }

    /// Convert event to canonical representation for signing.
    pub fn to_canonical(&self) -> Option<String> {
        // create a JsonValue for each event element
        let mut c: Vec<Value> = vec![];
        // id must be set to 0
        let id = Number::from(0_u64);
        c.push(serde_json::Value::Number(id));
        // public key
        c.push(Value::String(self.pubkey.clone()));
        // creation time
        let created_at = Number::from(self.created_at);
        c.push(serde_json::Value::Number(created_at));
        // kind
        let kind = Number::from(self.kind);
        c.push(serde_json::Value::Number(kind));
        // tags
        c.push(self.tags_to_canonical());
        // content
        c.push(Value::String(self.content.clone()));
        serde_json::to_string(&Value::Array(c)).ok()
    }

    /// Convert tags to a canonical form for signing.
    fn tags_to_canonical(&self) -> Value {
        let mut tags = Vec::<Value>::new();
        // iterate over self tags,
        for t in &self.tags {
            // each tag is a vec of strings
            let mut a = Vec::<Value>::new();
            for v in t.iter() {
                a.push(serde_json::Value::String(v.clone()));
            }
            tags.push(serde_json::Value::Array(a));
        }
        serde_json::Value::Array(tags)
    }

    /// Determine if the given tag and value set intersect with tags in this event.
    #[must_use]
    pub fn generic_tag_val_intersect(&self, tagname: &str, check: &TagOperand) -> bool {
        // Requiring every member of an empty set imposes no tag requirement.
        if matches!(check, TagOperand::And(values) if values.is_empty()) {
            return true;
        }
        match &self.tagidx {
            // check if this is indexable tagname
            Some(idx) => match idx.get(tagname) {
                Some(valset) => {
                    match &check {
                        TagOperand::And(v) => valset.intersection(v).count() == v.len(),
                        TagOperand::Or(v) => valset.intersection(v).count() > 0
                    }
                }
                None => false,
            },
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_creation() {
        // create an event
        let event = Event::simple_event();
        assert_eq!(event.id, "0");
    }

    #[test]
    fn event_serialize() -> Result<()> {
        // serialize an event to JSON string
        let event = Event::simple_event();
        let j = serde_json::to_string(&event)?;
        assert_eq!(j, "{\"id\":\"0\",\"pubkey\":\"0\",\"created_at\":0,\"kind\":0,\"tags\":[],\"content\":\"\",\"sig\":\"0\"}");
        Ok(())
    }

    #[test]
    fn empty_event_tag_match() {
        let event = Event::simple_event();
        assert!(!event
            .generic_tag_val_intersect("e", &TagOperand::Or(HashSet::from(["foo".to_owned(), "bar".to_owned()]))));
    }

    #[test]
    fn empty_and_filter_has_no_tag_requirement() {
        let mut event = Event::simple_event();
        for tags in [vec![], vec![vec!["category".to_owned(), "review".to_owned()]]] {
            event.tags = tags;
            event.build_index();
            assert!(event.generic_tag_val_intersect("category", &TagOperand::And(HashSet::new())));
            assert!(!event.generic_tag_val_intersect("category", &TagOperand::Or(HashSet::new())));
        }
    }

    #[test]
    fn single_event_tag_match() {
        let mut event = Event::simple_event();
        event.tags = vec![vec!["e".to_owned(), "foo".to_owned()]];
        event.build_index();
        assert!(
            event.generic_tag_val_intersect(
                "e",
                &TagOperand::Or(HashSet::from(["foo".to_owned(), "bar".to_owned()])),
            )
        );
    }

    #[test]
    fn multi_char_tagname_indexed() {
        // A4A discovery tags (multi-char names) must be indexed too, not
        // silently dropped like the upstream single_char_tagname gate did.
        let mut event = Event::simple_event();
        event.tags = vec![vec!["category".to_owned(), "development".to_owned()]];
        event.build_index();
        assert!(event.generic_tag_val_intersect(
            "category",
            &TagOperand::Or(HashSet::from(["development".to_owned()])),
        ));
        assert!(!event.generic_tag_val_intersect(
            "category",
            &TagOperand::Or(HashSet::from(["design".to_owned()])),
        ));
    }

    #[test]
    fn event_tags_serialize() -> Result<()> {
        // serialize an event with tags to JSON string
        let mut event = Event::simple_event();
        event.tags = vec![
            vec![
                "e".to_owned(),
                "xxxx".to_owned(),
                "wss://example.com".to_owned(),
            ],
            vec![
                "p".to_owned(),
                "yyyyy".to_owned(),
                "wss://example.com:3033".to_owned(),
            ],
        ];
        let j = serde_json::to_string(&event)?;
        assert_eq!(j, "{\"id\":\"0\",\"pubkey\":\"0\",\"created_at\":0,\"kind\":0,\"tags\":[[\"e\",\"xxxx\",\"wss://example.com\"],[\"p\",\"yyyyy\",\"wss://example.com:3033\"]],\"content\":\"\",\"sig\":\"0\"}");
        Ok(())
    }

    #[test]
    fn event_deserialize() -> Result<()> {
        let raw_json = r#"{"id":"1384757da583e6129ce831c3d7afc775a33a090578f888dd0d010328ad047d0c","pubkey":"bbbd9711d357df4f4e498841fd796535c95c8e751fa35355008a911c41265fca","created_at":1612650459,"kind":1,"tags":null,"content":"hello world","sig":"59d0cc47ab566e81f72fe5f430bcfb9b3c688cb0093d1e6daa49201c00d28ecc3651468b7938642869ed98c0f1b262998e49a05a6ed056c0d92b193f4e93bc21"}"#;
        let e: Event = serde_json::from_str(raw_json)?;
        assert_eq!(e.kind, 1);
        assert_eq!(e.tags.len(), 0);
        Ok(())
    }

    #[test]
    fn event_canonical() {
        let e = Event {
            id: "999".to_owned(),
            pubkey: "012345".to_owned(),
            delegated_by: None,
            created_at: 501_234,
            kind: 1,
            tags: vec![],
            content: "this is a test".to_owned(),
            sig: "abcde".to_owned(),
            tagidx: None,
        };
        let c = e.to_canonical();
        let expected = Some(r#"[0,"012345",501234,1,[],"this is a test"]"#.to_owned());
        assert_eq!(c, expected);
    }

    #[test]
    fn event_tag_select() {
        let e = Event {
            id: "999".to_owned(),
            pubkey: "012345".to_owned(),
            delegated_by: None,
            created_at: 501_234,
            kind: 1,
            tags: vec![
                vec!["j".to_owned(), "abc".to_owned()],
                vec!["e".to_owned(), "foo".to_owned()],
                vec!["e".to_owned(), "bar".to_owned()],
                vec!["e".to_owned(), "baz".to_owned()],
                vec![
                    "p".to_owned(),
                    "aaaa".to_owned(),
                    "ws://example.com".to_owned(),
                ],
            ],
            content: "this is a test".to_owned(),
            sig: "abcde".to_owned(),
            tagidx: None,
        };
        let v = e.tag_values_by_name("e");
        assert_eq!(v, vec!["foo", "bar", "baz"]);
    }

    #[test]
    fn event_no_tag_select() {
        let e = Event {
            id: "999".to_owned(),
            pubkey: "012345".to_owned(),
            delegated_by: None,
            created_at: 501_234,
            kind: 1,
            tags: vec![
                vec!["j".to_owned(), "abc".to_owned()],
                vec!["e".to_owned(), "foo".to_owned()],
                vec!["e".to_owned(), "baz".to_owned()],
                vec![
                    "p".to_owned(),
                    "aaaa".to_owned(),
                    "ws://example.com".to_owned(),
                ],
            ],
            content: "this is a test".to_owned(),
            sig: "abcde".to_owned(),
            tagidx: None,
        };
        let v = e.tag_values_by_name("x");
        // asking for tags that don't exist just returns zero-length vector
        assert_eq!(v.len(), 0);
    }

    #[test]
    fn event_canonical_with_tags() {
        let e = Event {
            id: "999".to_owned(),
            pubkey: "012345".to_owned(),
            delegated_by: None,
            created_at: 501_234,
            kind: 1,
            tags: vec![
                vec!["#e".to_owned(), "aoeu".to_owned()],
                vec![
                    "#p".to_owned(),
                    "aaaa".to_owned(),
                    "ws://example.com".to_owned(),
                ],
            ],
            content: "this is a test".to_owned(),
            sig: "abcde".to_owned(),
            tagidx: None,
        };
        let c = e.to_canonical();
        let expected_json = r###"[0,"012345",501234,1,[["#e","aoeu"],["#p","aaaa","ws://example.com"]],"this is a test"]"###;
        let expected = Some(expected_json.to_owned());
        assert_eq!(c, expected);
    }

    #[test]
    fn ephemeral_event() {
        let mut event = Event::simple_event();
        event.kind = 20000;
        assert!(event.is_ephemeral());
        event.kind = 29999;
        assert!(event.is_ephemeral());
        event.kind = 30000;
        assert!(!event.is_ephemeral());
        event.kind = 19999;
        assert!(!event.is_ephemeral());
    }

    #[test]
    fn replaceable_event() {
        let mut event = Event::simple_event();
        event.kind = 0;
        assert!(event.is_replaceable());
        event.kind = 3;
        assert!(event.is_replaceable());
        event.kind = 10000;
        assert!(event.is_replaceable());
        event.kind = 19999;
        assert!(event.is_replaceable());
        event.kind = 20000;
        assert!(!event.is_replaceable());
    }

    #[test]
    fn param_replaceable_event() {
        let mut event = Event::simple_event();
        event.kind = 30000;
        assert!(event.is_param_replaceable());
        event.kind = 39999;
        assert!(event.is_param_replaceable());
        event.kind = 29999;
        assert!(!event.is_param_replaceable());
        event.kind = 40000;
        assert!(!event.is_param_replaceable());
    }

    #[test]
    fn param_replaceable_value_case_1() {
        // NIP case #1: "tags":[["d",""]]
        let mut event = Event::simple_event();
        event.kind = 30000;
        event.tags = vec![vec!["d".to_owned(), "".to_owned()]];
        assert_eq!(event.distinct_param(), Some("".to_string()));
    }

    #[test]
    fn param_replaceable_value_case_2() {
        // NIP case #2: "tags":[]: implicit d tag with empty value
        let mut event = Event::simple_event();
        event.kind = 30000;
        assert_eq!(event.distinct_param(), Some("".to_string()));
    }

    #[test]
    fn param_replaceable_value_case_3() {
        // NIP case #3: "tags":[["d"]]: implicit empty value ""
        let mut event = Event::simple_event();
        event.kind = 30000;
        event.tags = vec![vec!["d".to_owned()]];
        assert_eq!(event.distinct_param(), Some("".to_string()));
    }

    #[test]
    fn param_replaceable_value_case_4() {
        // NIP case #4: "tags":[["d",""],["d","not empty"]]: only first d tag is considered
        let mut event = Event::simple_event();
        event.kind = 30000;
        event.tags = vec![
            vec!["d".to_owned(), "".to_string()],
            vec!["d".to_owned(), "not empty".to_string()],
        ];
        assert_eq!(event.distinct_param(), Some("".to_string()));
    }

    #[test]
    fn param_replaceable_value_case_4b() {
        // Variation of #4 with
        // NIP case #4: "tags":[["d","not empty"],["d",""]]: only first d tag is considered
        let mut event = Event::simple_event();
        event.kind = 30000;
        event.tags = vec![
            vec!["d".to_owned(), "not empty".to_string()],
            vec!["d".to_owned(), "".to_string()],
        ];
        assert_eq!(event.distinct_param(), Some("not empty".to_string()));
    }

    #[test]
    fn param_replaceable_value_case_5() {
        // NIP case #5: "tags":[["d"],["d","some value"]]: only first d tag is considered
        let mut event = Event::simple_event();
        event.kind = 30000;
        event.tags = vec![
            vec!["d".to_owned()],
            vec!["d".to_owned(), "second value".to_string()],
            vec!["d".to_owned(), "third value".to_string()],
        ];
        assert_eq!(event.distinct_param(), Some("".to_string()));
    }

    #[test]
    fn param_replaceable_value_case_6() {
        // NIP case #6: "tags":[["e"]]: same as no tags
        let mut event = Event::simple_event();
        event.kind = 30000;
        event.tags = vec![vec!["e".to_owned()]];
        assert_eq!(event.distinct_param(), Some("".to_string()));
    }

    #[test]
    fn expiring_event_none() {
        // regular events do not expire
        let mut event = Event::simple_event();
        event.kind = 7;
        event.tags = vec![vec!["test".to_string(), "foo".to_string()]];
        assert_eq!(event.expiration(), None);
    }

    #[test]
    fn expiring_event_empty() {
        // regular events do not expire
        let mut event = Event::simple_event();
        event.kind = 7;
        event.tags = vec![vec!["expiration".to_string()]];
        assert_eq!(event.expiration(), None);
    }

    #[test]
    fn expiring_event_future() {
        // a normal expiring event
        let exp: u64 = 1676264138;
        let mut event = Event::simple_event();
        event.kind = 1;
        event.tags = vec![vec!["expiration".to_string(), exp.to_string()]];
        assert_eq!(event.expiration(), Some(exp));
    }

    #[test]
    fn expiring_event_negative() {
        // expiration set to a negative value (invalid)
        let exp: i64 = -90;
        let mut event = Event::simple_event();
        event.kind = 1;
        event.tags = vec![vec!["expiration".to_string(), exp.to_string()]];
        assert_eq!(event.expiration(), None);
    }

    #[test]
    fn expiring_event_zero() {
        // a normal expiring event set to zero
        let exp: i64 = 0;
        let mut event = Event::simple_event();
        event.kind = 1;
        event.tags = vec![vec!["expiration".to_string(), exp.to_string()]];
        assert_eq!(event.expiration(), Some(0));
    }

    #[test]
    fn expiring_event_fraction() {
        // expiration is fractional (invalid)
        let exp: f64 = 23.334;
        let mut event = Event::simple_event();
        event.kind = 1;
        event.tags = vec![vec!["expiration".to_string(), exp.to_string()]];
        assert_eq!(event.expiration(), None);
    }

    #[test]
    fn expiring_event_multiple() {
        // multiple values, we just take the first
        let mut event = Event::simple_event();
        event.kind = 1;
        event.tags = vec![
            vec!["expiration".to_string(), (10).to_string()],
            vec!["expiration".to_string(), (20).to_string()],
        ];
        assert_eq!(event.expiration(), Some(10));
    }
}

#[cfg(test)]
mod signature_rejection {
    use super::*;
    use bitcoin_hashes::{sha256, Hash};
    use secp256k1::{Keypair, Secp256k1};

    /// Event signed by `keypair` with a genuine id and signature.
    fn signed_event(keypair: &Keypair, content: &str) -> Event {
        let secp = Secp256k1::new();
        let mut event = Event {
            id: String::new(),
            pubkey: keypair.x_only_public_key().0.to_string(),
            delegated_by: None,
            created_at: 1_700_000_000,
            kind: 1,
            tags: vec![],
            content: content.to_owned(),
            sig: String::new(),
            tagidx: None,
        };
        let canonical = event.to_canonical().expect("canonicalize");
        let digest: sha256::Hash = sha256::Hash::hash(canonical.as_bytes());
        event.id = format!("{digest:x}");
        event.sig = secp
            .sign_schnorr_no_aux_rand(digest.as_ref(), keypair)
            .to_string();
        event
    }

    fn keypair() -> Keypair {
        Keypair::new(&Secp256k1::new(), &mut secp256k1::rand::thread_rng())
    }

    /// Positive control: an honest event passes. Without this, the three rejection
    /// tests below would also pass with a completely broken validator that rejects all
    /// events, because "rejects every forgery" would still be technically true.
    #[test]
    fn honest_event_is_accepted() {
        assert!(signed_event(&keypair(), "honest event").validate().is_ok());
    }

    /// Signature with one changed character: syntactically valid, cryptographically wrong.
    ///
    /// This is the relay's fundamental defense against forged events: the signature
    /// proves authorship, and reputation, delegation, and agreements all depend on it.
    /// Before 2026-08-30 there was no dedicated rejection test; the suite proved only
    /// that valid signatures passed and would stay green if verification accepted all.
    #[test]
    fn tampered_signature_is_rejected() {
        let mut event = signed_event(&keypair(), "content");
        let ch = if event.sig.as_bytes()[10] == b'0' { '1' } else { '0' };
        event.sig.replace_range(10..11, &ch.to_string());
        assert!(matches!(event.validate(), Err(crate::error::Error::EventInvalidSignature)));
    }

    /// A genuine but unrelated signature made by another key over different content.
    #[test]
    fn signature_from_another_key_is_rejected() {
        let mut event = signed_event(&keypair(), "content");
        let other = signed_event(&keypair(), "unrelated content");
        event.sig = other.sig;
        assert!(matches!(event.validate(), Err(crate::error::Error::EventInvalidSignature)));
    }

    /// An event with a substituted `id` and valid signature must be rejected.
    ///
    /// Such an event is internally consistent from the SIGNATURE perspective: the
    /// signature covers the content and verifies against the relay's recomputed digest.
    /// Only comparing `id` with that digest catches substitution. Before 2026-08-30 no
    /// test covered it; removing the id check left the entire suite green.
    ///
    /// The impact is not cosmetic. Deduplication, deletion addressing (NIP-09), and
    /// an event's delegation reference all depend on `id`. A freely chosen id makes
    /// all three mechanisms point at arbitrary data.
    #[test]
    fn tampered_id_is_rejected() {
        let mut event = signed_event(&keypair(), "content");
        event.id = "f".repeat(64);
        assert!(matches!(event.validate(), Err(crate::error::Error::EventInvalidId)));
    }

    /// Substituted author: the signature belongs to a key other than the named one.
    ///
    /// Rejection occurs earlier at id comparison because pubkey is part of the
    /// canonical form. That is correct: the author cannot change while id stays fixed.
    #[test]
    fn swapped_author_is_rejected() {
        let mut event = signed_event(&keypair(), "content");
        event.pubkey = keypair().x_only_public_key().0.to_string();
        assert!(event.validate().is_err());
    }
}

#[cfg(test)]
mod digest_representation {
    use bitcoin_hashes::{sha256, Hash};

    /// The hexadecimal SHA-256 representation is PROTOCOL, not implementation detail.
    ///
    /// An event `id` is this string and implementations use it for identity. The
    /// `bitcoin_hashes` dependency defines the representation, so a crate update could
    /// silently change it. This concern was checked during the 0.14 migration (it did
    /// not change). The test pins the RFC-known SHA-256 vector for "abc".
    #[test]
    fn sha256_hex_matches_the_known_vector() {
        let d: sha256::Hash = sha256::Hash::hash(b"abc");
        assert_eq!(
            format!("{d:x}"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "SHA-256 representation changed; event id matching would break"
        );
    }
}

#[cfg(test)]
mod expiration_tag {
    use super::*;

    fn event_with_tags(tags: Vec<Vec<String>>) -> Event {
        Event {
            id: "0".repeat(64),
            pubkey: "a".repeat(64),
            delegated_by: None,
            created_at: 0,
            kind: 31002,
            tags,
            content: String::new(),
            sig: "b".repeat(128),
            tagidx: None,
        }
    }

    #[test]
    fn a_single_expiration_tag_is_read_as_before() {
        // Positive control: without this, taking the minimum is indistinguishable from breakage.
        let ev = event_with_tags(vec![vec!["expiration".to_owned(), "1000".to_owned()]]);
        assert_eq!(ev.expiration(), Some(1000));
    }

    #[test]
    fn no_expiration_tag_means_no_expiration() {
        let ev = event_with_tags(vec![vec!["p".to_owned(), "x".to_owned()]]);
        assert_eq!(ev.expiration(), None);
    }

    /// From multiple `expiration` tags, use the NEAREST rather than the first in order.
    ///
    /// Before 2026-09-04, `.take(1)` let the earlier array element win. This is not
    /// hypothetical: a client library that adds a default deadline and caller code that
    /// adds its own leave both in the event. Our live-check script hit this by appending
    /// "one hour" after the SDK's "thirty days" and leaving test events in production
    /// for a month while assuming the opposite.
    #[test]
    fn the_nearest_expiration_wins_regardless_of_tag_order() {
        let far = vec!["expiration".to_owned(), "2000000".to_owned()];
        let near = vec!["expiration".to_owned(), "1000".to_owned()];
        assert_eq!(
            event_with_tags(vec![far.clone(), near.clone()]).expiration(),
            Some(1000),
            "the earlier distant deadline won, extending the event's intended lifetime"
        );
        assert_eq!(
            event_with_tags(vec![near, far]).expiration(),
            Some(1000),
            "tag order must not affect event lifetime"
        );
    }

    /// Validity consensus (internal audit): the relay parsed `"+N"` as a number because
    /// Rust's `str::parse::<u64>` accepts a leading plus, while the SDK's `parse_uint`
    /// (`[0-9]{1,19}`) rejects it. A delegation with `expiration = "+N"` was valid for
    /// the relay and invalid for the client. The SDK form is canonical because the
    /// specification requires canonical representations; the relay now matches it.
    /// Finding 125: a non-canonical expiration also made an event immortal in queries,
    /// because the relay treated an unreadable deadline as absent. Intake now detects
    /// and rejects such events.
    #[test]
    fn malformed_expiration_is_detected_not_ignored() {
        let mut event = Event::simple_event();
        event.tags = vec![vec!["expiration".to_owned(), "1788556527".to_owned()]];
        assert!(!event.has_malformed_expiration(), "canonical expiration must pass");

        for bad in ["+1788556527", "05", "00", "1788556527.0", " 1788556527", "abc", "-5", "1e9"] {
            event.tags = vec![vec!["expiration".to_owned(), bad.to_owned()]];
            assert!(
                event.has_malformed_expiration(),
                "value {bad:?} was not recognized as non-canonical; the event would become immortal"
            );
            assert_eq!(event.expiration(), None, "{bad:?}");
        }

        // With two tags, one canonical and one malformed, reject the event anyway;
        // otherwise the malformed tag remains a way to bypass the deadline.
        event.tags = vec![
            vec!["expiration".to_owned(), "1788556527".to_owned()],
            vec!["expiration".to_owned(), "+1788556527".to_owned()],
        ];
        assert!(event.has_malformed_expiration());

        event.tags = vec![vec!["expiration".to_owned()]];
        assert!(!event.has_malformed_expiration(), "a tag without a value is a different case");
    }

    #[test]
    fn expiration_accepts_only_canonical_decimal_digits() {
        for bad in ["+1000", " 1000", "1000.0", "-1000", "12345678901234567890"] {
            assert_eq!(
                event_with_tags(vec![vec!["expiration".to_owned(), bad.to_owned()]]).expiration(),
                None,
                "{bad:?} was accepted as a number but the SDK rejects it; consensus broke"
            );
        }
        // Leading zeroes have been forbidden since 2026-09-04 (0|[1-9][0-9]{0,18}).
        // Allowing them made normalizing and literal readers derive two digests for one deal.
        assert_eq!(
            event_with_tags(vec![vec!["expiration".to_owned(), "01000".to_owned()]]).expiration(),
            None,
            "leading zero was accepted but the SDK rejects it; consensus broke"
        );
        assert_eq!(
            event_with_tags(vec![vec!["expiration".to_owned(), "0".to_owned()]]).expiration(),
            Some(0),
            "a single zero is a valid number"
        );
    }

    #[test]
    fn an_unparsable_expiration_does_not_hide_a_valid_one() {
        // Garbage next to a real deadline must not make the event unbounded.
        let ev = event_with_tags(vec![
            vec!["expiration".to_owned(), "not-a-number".to_owned()],
            vec!["expiration".to_owned(), "1000".to_owned()],
        ]);
        assert_eq!(ev.expiration(), Some(1000));
    }
}
