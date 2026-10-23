//! Subscription and filter parsing
use crate::error::Result;
use crate::event::Event;
use serde::de::Unexpected;
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::collections::HashMap;
use std::collections::HashSet;
use std::ops::Deref;

/// Subscription identifier and set of request filters
#[derive(Serialize, PartialEq, Eq, Debug, Clone)]
pub struct Subscription {
    pub id: String,
    pub filters: Vec<ReqFilter>,
}

/// Tag query is AND or OR operation
#[derive(Serialize, PartialEq, Eq, Debug, Clone)]
pub enum TagOperand {
    And(HashSet<String>),
    Or(HashSet<String>),
}

impl Deref for TagOperand {
    type Target = HashSet<String>;

    fn deref(&self) -> &Self::Target {
        match self {
            TagOperand::Or(v) => v,
            TagOperand::And(v) => v,
        }
    }
}

/// Filter for requests
///
/// Corresponds to client-provided subscription request elements.  Any
/// element can be present if it should be used in filtering, or
/// absent ([`None`]) if it should be ignored.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct ReqFilter {
    /// Event hashes
    pub ids: Option<Vec<String>>,
    /// Event kinds
    pub kinds: Option<Vec<u64>>,
    /// Events published after this time
    pub since: Option<u64>,
    /// Events published before this time
    pub until: Option<u64>,
    /// List of author public keys
    pub authors: Option<Vec<String>>,
    /// Limit number of results
    pub limit: Option<u64>,
    /// Set of tags. Keyed by full tag name (not just a single char) so that
    /// A4A discovery tags (`#category`, `#intent_type`, ...) work alongside
    /// standard single-char NIP-01/NIP-12 tags (`#e`, `#p`, ...).
    pub tags: Option<HashMap<String, TagOperand>>,
    /// Force no matches due to malformed data
    // we can't represent it in the req filter, so we don't want to
    // erroneously match.  This basically indicates the req tried to
    // do something invalid.
    pub force_no_match: bool,
}

impl Serialize for ReqFilter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        if let Some(ids) = &self.ids {
            map.serialize_entry("ids", &ids)?;
        }
        if let Some(kinds) = &self.kinds {
            map.serialize_entry("kinds", &kinds)?;
        }
        if let Some(until) = &self.until {
            map.serialize_entry("until", until)?;
        }
        if let Some(since) = &self.since {
            map.serialize_entry("since", since)?;
        }
        if let Some(limit) = &self.limit {
            map.serialize_entry("limit", limit)?;
        }
        if let Some(authors) = &self.authors {
            map.serialize_entry("authors", &authors)?;
        }
        // serialize tags
        if let Some(tags) = &self.tags {
            for (k, v) in tags {
                match v {
                    TagOperand::Or(values) => map.serialize_entry(&format!("#{k}"), values)?,
                    TagOperand::And(values) => map.serialize_entry(&format!("#{k}&"), values)?,
                }
            }
        }
        map.end()
    }
}

/// Cap on values in a single tag filter.
///
/// Every value of an AND filter becomes its own subquery (SQLite) or JOIN
/// (Postgres), and nothing but the message size limited how many there could be:
/// ten thousand five-byte values fit in one 128 KB message. The resulting
/// statement is expensive to plan before it is expensive to run, and it holds a
/// database reader thread the whole time. Rejecting is better than truncating:
/// a silently shortened filter answers a question the client did not ask.
pub const MAX_TAG_VALUES_PER_FILTER: usize = 100;

/// Cap on distinct tag names in one filter, for the same reason.
pub const MAX_TAGS_PER_FILTER: usize = 20;

/// Cap on `authors` and on `ids` in one filter — each list separately.
///
/// Every value becomes one bound SQL parameter. SQLite's default limit is 999 per
/// statement, and a live probe measured the cliff exactly: 990 authors
/// answered in 0.10 s, 999 never answered at all -- the statement failed, the
/// error left the query closure before EOSE was sent, and the subscription hung
/// in silence. Two lists of 256 plus kinds, tags and limits stay well under 999.
/// A client that follows more keys splits them across filters or subscriptions;
/// a filter that cannot be served is refused with a reason, not served wrongly.
pub const MAX_IDS_OR_AUTHORS_PER_FILTER: usize = 256;

/// Parse filter fields strictly: a wrong type is a named error, not silently
/// "field absent." Upstream used `.ok()`, turning `{"kinds":["a"]}` into a filter
/// without kinds and therefore the entire database. Internal finding 90 reproduced
/// 936 events returned for that typo. Client errors must be visible, not leak data.
fn strict_field<'de, T: Deserialize<'de>, E: serde::de::Error>(name: &str, val: &'de Value) -> Result<T, E> {
    T::deserialize(val).map_err(|_| {
        serde::de::Error::invalid_type(
            Unexpected::Other(&format!("filter field {name:?} has the wrong type")),
            &"a filter with correctly typed fields",
        )
    })
}

impl<'de> Deserialize<'de> for ReqFilter {
    fn deserialize<D>(deserializer: D) -> Result<ReqFilter, D::Error>
    where
        D: Deserializer<'de>,
    {
        let received: Value = Deserialize::deserialize(deserializer)?;
        let filter = received.as_object().ok_or_else(|| {
            serde::de::Error::invalid_type(
                Unexpected::Other("reqfilter is not an object"),
                &"a json object",
            )
        })?;
        let mut rf = ReqFilter {
            ids: None,
            kinds: None,
            since: None,
            until: None,
            authors: None,
            limit: None,
            tags: None,
            force_no_match: false,
        };
        let empty_string = "".into();
        let mut ts: Option<HashMap<String, TagOperand>> = None;
        // iterate through each key, and assign values that exist
        for (key, val) in filter {
            // ids
            if key == "ids" {
                let raw_ids: Option<Vec<String>> = Some(strict_field("ids", val)?);
                if let Some(a) = raw_ids.as_ref() {
                    if a.len() > MAX_IDS_OR_AUTHORS_PER_FILTER {
                        return Err(serde::de::Error::invalid_type(
                            Unexpected::Other("too many ids in one filter"),
                            &"a json object",
                        ));
                    }
                    if a.contains(&empty_string) {
                        return Err(serde::de::Error::invalid_type(
                            Unexpected::Other("prefix matches must not be empty strings"),
                            &"a json object",
                        ));
                    }
                }
                rf.ids = raw_ids;
            } else if key == "kinds" {
                rf.kinds = Some(strict_field("kinds", val)?);
            } else if key == "since" {
                rf.since = Some(strict_field("since", val)?);
            } else if key == "until" {
                rf.until = Some(strict_field("until", val)?);
            } else if key == "limit" {
                rf.limit = Some(strict_field("limit", val)?);
            } else if key == "authors" {
                let raw_authors: Option<Vec<String>> = Some(strict_field("authors", val)?);
                if let Some(a) = raw_authors.as_ref() {
                    if a.len() > MAX_IDS_OR_AUTHORS_PER_FILTER {
                        return Err(serde::de::Error::invalid_type(
                            Unexpected::Other("too many authors in one filter"),
                            &"a json object",
                        ));
                    }
                    if a.contains(&empty_string) {
                        return Err(serde::de::Error::invalid_type(
                            Unexpected::Other("prefix matches must not be empty strings"),
                            &"a json object",
                        ));
                    }
                }
                rf.authors = raw_authors;
            } else if key.starts_with('#') && key.len() > 1 {
                if ts.as_ref().is_some_and(|m| m.len() >= MAX_TAGS_PER_FILTER) {
                    return Err(serde::de::Error::invalid_type(
                        Unexpected::Other("too many tag filters"),
                        &"a json object",
                    ));
                }
                // Option B (A4A discovery): accept `#<name>` for ANY name
                // length (>=1 char), not just a single char. This is what
                // lets `#category`/`#intent_type`/etc. be parsed instead of
                // silently dropped.
                if ts.is_none() {
                    // Initialize the tag if necessary
                    ts = Some(HashMap::new());
                }
                if let Some(m) = ts.as_mut() {
                    let tag_vals: Option<Vec<String>> = Some(strict_field(key, val)?);
                    if let Some(v) = tag_vals {
                        if v.len() > MAX_TAG_VALUES_PER_FILTER {
                            return Err(serde::de::Error::invalid_type(
                                Unexpected::Other("too many values for one tag filter"),
                                &"a json object",
                            ));
                        }
                        let hs = v.into_iter().collect::<HashSet<_>>();
                        // Semantics preserved from the original single-char
                        // parser, generalized by trailing-`&` detection
                        // instead of fixed key length:
                        // `#<name>` -> OR over values.
                        // `#<name>&` (trailing `&`) -> AND over values.
                        // e.g. `#e` -> Or, `#e&` -> And (name "e");
                        // `#category` -> Or, `#category&` -> And (name "category").
                        let rest = &key[1..];
                        let (name, hs_op) = if rest.len() > 1 && rest.ends_with('&') {
                            (&rest[..rest.len() - 1], TagOperand::And(hs))
                        } else {
                            (rest, TagOperand::Or(hs))
                        };
                        // `#t` and `#t&` share the name "t". Silent replacement
                        // would make JSON key order determine filter semantics.
                        if m.contains_key(name) {
                            return Err(serde::de::Error::invalid_type(
                                Unexpected::Other("conflicting OR and AND filters for one tag"),
                                &"a json object",
                            ));
                        }
                        m.insert(name.to_owned(), hs_op);
                    }
                };
            }
        }
        rf.tags = ts;
        Ok(rf)
    }
}

impl<'de> Deserialize<'de> for Subscription {
    /// Custom deserializer for subscriptions, which have a more
    /// complex structure than the other message types.
    fn deserialize<D>(deserializer: D) -> Result<Subscription, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut v: Value = Deserialize::deserialize(deserializer)?;
        // this should be a 3-or-more element array.
        // verify the first element is a String, REQ
        // get the subscription from the second element.
        // convert each of the remaining objects into filters

        // check for array
        let va = v
            .as_array_mut()
            .ok_or_else(|| serde::de::Error::custom("not array"))?;

        // check length
        if va.len() < 3 {
            return Err(serde::de::Error::custom("not enough fields"));
        }
        let mut i = va.iter_mut();
        // get command ("REQ") and ensure it is a string
        let req_cmd_str: serde_json::Value = i.next().unwrap().take();
        let req = req_cmd_str
            .as_str()
            .ok_or_else(|| serde::de::Error::custom("first element of request was not a string"))?;
        if req != "REQ" {
            return Err(serde::de::Error::custom("missing REQ command"));
        }

        // ensure sub id is a string
        let sub_id_str: serde_json::Value = i.next().unwrap().take();
        let sub_id = sub_id_str
            .as_str()
            .ok_or_else(|| serde::de::Error::custom("missing subscription id"))?;

        let mut filters = vec![];
        for fv in i {
            let f: ReqFilter = serde_json::from_value(fv.take())
                .map_err(|e| serde::de::Error::custom(format!("could not parse filter: {e}")))?;
            // create indexes
            filters.push(f);
        }
        filters.dedup();
        Ok(Subscription {
            id: sub_id.to_owned(),
            filters,
        })
    }
}

impl Subscription {
    /// Get a copy of the subscription identifier.
    #[must_use]
    pub fn get_id(&self) -> String {
        self.id.clone()
    }

    /// Determine if any filter is requesting historical (database)
    /// queries.  If every filter has limit:0, we do not need to query the DB.
    #[must_use]
    pub fn needs_historical_events(&self) -> bool {
        self.filters.iter().any(|f| f.limit != Some(0))
    }

    /// Determine if this subscription matches a given [`Event`].  Any
    /// individual filter match is sufficient.
    #[must_use]
    pub fn interested_in_event(&self, event: &Event) -> bool {
        for f in &self.filters {
            if f.interested_in_event(event) {
                return true;
            }
        }
        false
    }

    /// Is this subscription defined as a scraper query
    pub fn is_scraper(&self) -> bool {
        for f in &self.filters {
            let mut precision = 0;
            if f.ids.is_some() {
                precision += 2;
            }
            if f.authors.is_some() {
                precision += 1;
            }
            if f.kinds.is_some() {
                precision += 1;
            }
            if f.tags.is_some() {
                precision += 1;
            }
            if precision < 2 {
                return true;
            }
        }
        false
    }
}

fn prefix_match(prefixes: &[String], target: &str) -> bool {
    for prefix in prefixes {
        if target.starts_with(prefix) {
            return true;
        }
    }
    // none matched
    false
}

impl ReqFilter {
    fn ids_match(&self, event: &Event) -> bool {
        self.ids
            .as_ref()
            .is_none_or(|vs| prefix_match(vs, &event.id))
    }

    fn authors_match(&self, event: &Event) -> bool {
        self.authors
            .as_ref()
            .is_none_or(|vs| prefix_match(vs, &event.pubkey))
    }

    fn delegated_authors_match(&self, event: &Event) -> bool {
        if let Some(delegated_pubkey) = &event.delegated_by {
            self.authors
                .as_ref()
                .is_none_or(|vs| prefix_match(vs, delegated_pubkey))
        } else {
            false
        }
    }

    fn tag_match(&self, event: &Event) -> bool {
        // get the hashset from the filter.
        if let Some(map) = &self.tags {
            for (key, val) in map.iter() {
                let tag_match = event.generic_tag_val_intersect(key, val);
                // if there is no match for this tag, the match fails.
                if !tag_match {
                    return false;
                }
                // if there was a match, we move on to the next one.
            }
        }
        // if the tag map is empty, the match succeeds (there was no filter)
        true
    }

    /// Check if this filter either matches, or does not care about the kind.
    fn kind_match(&self, kind: u64) -> bool {
        self.kinds.as_ref().is_none_or(|ks| ks.contains(&kind))
    }

    /// Determine if all populated fields in this filter match the provided event.
    #[must_use]
    pub fn interested_in_event(&self, event: &Event) -> bool {
        //        self.id.as_ref().map(|v| v == &event.id).unwrap_or(true)
        self.ids_match(event)
            && self.since.is_none_or(|t| event.created_at >= t)
            && self.until.is_none_or(|t| event.created_at <= t)
            && self.kind_match(event.kind)
            && (self.authors_match(event) || self.delegated_authors_match(event))
            && self.tag_match(event)
            && !self.force_no_match
    }
}

#[cfg(test)]
mod tests {
    /// Finding 90: a wrongly typed field used to disappear and produce a match-all
    /// filter. It now raises a parse error naming the field and returns no events.
    #[test]
    fn wrongly_typed_filter_field_is_an_error_not_match_all() {
        for (json, field) in [
            (r#"["REQ","x",{"kinds":["a"]}]"#, "kinds"),
            (r#"["REQ","x",{"kinds":"a"}]"#, "kinds"),
            (r#"["REQ","x",{"since":"abc"}]"#, "since"),
            (r#"["REQ","x",{"until":[1]}]"#, "until"),
            (r#"["REQ","x",{"limit":-1}]"#, "limit"),
            (r#"["REQ","x",{"authors":[1]}]"#, "authors"),
            (r#"["REQ","x",{"ids":[true]}]"#, "ids"),
            (r##"["REQ","x",{"#t":[1]}]"##, "#t"),
        ] {
            let err = serde_json::from_str::<super::Subscription>(json)
                .err()
                .unwrap_or_else(|| panic!("{json}: parsed as a valid match-all filter"));
            assert!(err.to_string().contains(field), "{json}: error omits field name: {err}");
        }
        // Positive control: correct field types remain accepted.
        let ok = serde_json::from_str::<super::Subscription>(
            r##"["REQ","x",{"kinds":[1],"since":1,"until":2,"limit":3,"authors":["ab"],"ids":["cd"],"#t":["a"]}]"##,
        );
        assert!(ok.is_ok(), "{ok:?}");
    }

    use super::*;

    #[test]
    fn empty_request_parse() -> Result<()> {
        let raw_json = "[\"REQ\",\"some-id\",{}]";
        let s: Subscription = serde_json::from_str(raw_json)?;
        assert_eq!(s.id, "some-id");
        assert_eq!(s.filters.len(), 1);
        assert_eq!(s.filters.first().unwrap().authors, None);
        Ok(())
    }

    #[test]
    fn incorrect_header() {
        let raw_json = "[\"REQUEST\",\"some-id\",\"{}\"]";
        assert!(serde_json::from_str::<Subscription>(raw_json).is_err());
    }

    #[test]
    fn req_missing_filters() {
        let raw_json = "[\"REQ\",\"some-id\"]";
        assert!(serde_json::from_str::<Subscription>(raw_json).is_err());
    }

    #[test]
    fn req_empty_authors_prefix() {
        let raw_json = "[\"REQ\",\"some-id\",{\"authors\": [\"\"]}]";
        assert!(serde_json::from_str::<Subscription>(raw_json).is_err());
    }

    #[test]
    fn req_empty_ids_prefix() {
        let raw_json = "[\"REQ\",\"some-id\",{\"ids\": [\"\"]}]";
        assert!(serde_json::from_str::<Subscription>(raw_json).is_err());
    }

    #[test]
    fn req_empty_ids_prefix_mixed() {
        let raw_json = "[\"REQ\",\"some-id\",{\"ids\": [\"\",\"aaa\"]}]";
        assert!(serde_json::from_str::<Subscription>(raw_json).is_err());
    }

    #[test]
    fn legacy_filter() {
        // legacy field in filter
        let raw_json = "[\"REQ\",\"some-id\",{\"kind\": 3}]";
        assert!(serde_json::from_str::<Subscription>(raw_json).is_ok());
    }

    #[test]
    fn dupe_filter() -> Result<()> {
        let raw_json = r#"["REQ","some-id",{"kinds": [1984]}, {"kinds": [1984]}]"#;
        let s: Subscription = serde_json::from_str(raw_json)?;
        assert_eq!(s.filters.len(), 1);
        Ok(())
    }

    #[test]
    fn dupe_filter_many() -> Result<()> {
        // duplicate filters in different order
        let raw_json = r#"["REQ","some-id",{"kinds":[1984]},{"kinds":[1984]},{"kinds":[1984]},{"kinds":[1984]}]"#;
        let s: Subscription = serde_json::from_str(raw_json)?;
        assert_eq!(s.filters.len(), 1);
        Ok(())
    }

    #[test]
    fn author_filter() -> Result<()> {
        let raw_json = r#"["REQ","some-id",{"authors": ["test-author-id"]}]"#;
        let s: Subscription = serde_json::from_str(raw_json)?;
        assert_eq!(s.id, "some-id");
        assert_eq!(s.filters.len(), 1);
        let first_filter = s.filters.first().unwrap();
        assert_eq!(
            first_filter.authors,
            Some(vec!("test-author-id".to_owned()))
        );
        Ok(())
    }

    #[test]
    fn interest_author_prefix_match() -> Result<()> {
        // subscription with a filter for ID
        let s: Subscription = serde_json::from_str(r#"["REQ","xyz",{"authors": ["abc"]}]"#)?;
        let e = Event {
            id: "foo".to_owned(),
            pubkey: "abcd".to_owned(),
            delegated_by: None,
            created_at: 0,
            kind: 0,
            tags: Vec::new(),
            content: "".to_owned(),
            sig: "".to_owned(),
            tagidx: None,
        };
        assert!(s.interested_in_event(&e));
        Ok(())
    }

    #[test]
    fn interest_id_prefix_match() -> Result<()> {
        // subscription with a filter for ID
        let s: Subscription = serde_json::from_str(r#"["REQ","xyz",{"ids": ["abc"]}]"#)?;
        let e = Event {
            id: "abcd".to_owned(),
            pubkey: "".to_owned(),
            delegated_by: None,
            created_at: 0,
            kind: 0,
            tags: Vec::new(),
            content: "".to_owned(),
            sig: "".to_owned(),
            tagidx: None,
        };
        assert!(s.interested_in_event(&e));
        Ok(())
    }

    #[test]
    fn interest_id_nomatch() -> Result<()> {
        // subscription with a filter for ID
        let s: Subscription = serde_json::from_str(r#"["REQ","xyz",{"ids": ["xyz"]}]"#)?;
        let e = Event {
            id: "abcde".to_owned(),
            pubkey: "".to_owned(),
            delegated_by: None,
            created_at: 0,
            kind: 0,
            tags: Vec::new(),
            content: "".to_owned(),
            sig: "".to_owned(),
            tagidx: None,
        };
        assert!(!s.interested_in_event(&e));
        Ok(())
    }

    #[test]
    fn interest_until() -> Result<()> {
        // subscription with a filter for ID and time
        let s: Subscription =
            serde_json::from_str(r#"["REQ","xyz",{"ids": ["abc"], "until": 1000}]"#)?;
        let e = Event {
            id: "abc".to_owned(),
            pubkey: "".to_owned(),
            delegated_by: None,
            created_at: 50,
            kind: 0,
            tags: Vec::new(),
            content: "".to_owned(),
            sig: "".to_owned(),
            tagidx: None,
        };
        assert!(s.interested_in_event(&e));
        Ok(())
    }

    #[test]
    fn interest_range() -> Result<()> {
        // subscription with a filter for ID and time
        let s_in: Subscription =
            serde_json::from_str(r#"["REQ","xyz",{"ids": ["abc"], "since": 100, "until": 200}]"#)?;
        let s_before: Subscription =
            serde_json::from_str(r#"["REQ","xyz",{"ids": ["abc"], "since": 100, "until": 140}]"#)?;
        let s_after: Subscription =
            serde_json::from_str(r#"["REQ","xyz",{"ids": ["abc"], "since": 160, "until": 200}]"#)?;
        let e = Event {
            id: "abc".to_owned(),
            pubkey: "".to_owned(),
            delegated_by: None,
            created_at: 150,
            kind: 0,
            tags: Vec::new(),
            content: "".to_owned(),
            sig: "".to_owned(),
            tagidx: None,
        };
        assert!(s_in.interested_in_event(&e));
        assert!(!s_before.interested_in_event(&e));
        assert!(!s_after.interested_in_event(&e));
        Ok(())
    }

    #[test]
    fn interest_time_and_id() -> Result<()> {
        // subscription with a filter for ID and time
        let s: Subscription =
            serde_json::from_str(r#"["REQ","xyz",{"ids": ["abc"], "since": 1000}]"#)?;
        let e = Event {
            id: "abc".to_owned(),
            pubkey: "".to_owned(),
            delegated_by: None,
            created_at: 50,
            kind: 0,
            tags: Vec::new(),
            content: "".to_owned(),
            sig: "".to_owned(),
            tagidx: None,
        };
        assert!(!s.interested_in_event(&e));
        Ok(())
    }

    #[test]
    fn interest_time_and_id2() -> Result<()> {
        // subscription with a filter for ID and time
        let s: Subscription = serde_json::from_str(r#"["REQ","xyz",{"id":"abc", "since": 1000}]"#)?;
        let e = Event {
            id: "abc".to_owned(),
            pubkey: "".to_owned(),
            delegated_by: None,
            created_at: 1001,
            kind: 0,
            tags: Vec::new(),
            content: "".to_owned(),
            sig: "".to_owned(),
            tagidx: None,
        };
        assert!(s.interested_in_event(&e));
        Ok(())
    }

    #[test]
    fn interest_id() -> Result<()> {
        // subscription with a filter for ID
        let s: Subscription = serde_json::from_str(r#"["REQ","xyz",{"id":"abc"}]"#)?;
        let e = Event {
            id: "abc".to_owned(),
            pubkey: "".to_owned(),
            delegated_by: None,
            created_at: 0,
            kind: 0,
            tags: Vec::new(),
            content: "".to_owned(),
            sig: "".to_owned(),
            tagidx: None,
        };
        assert!(s.interested_in_event(&e));
        Ok(())
    }

    #[test]
    fn authors_single() -> Result<()> {
        // subscription with a filter for ID
        let s: Subscription = serde_json::from_str(r#"["REQ","xyz",{"authors":["abc"]}]"#)?;
        let e = Event {
            id: "123".to_owned(),
            pubkey: "abc".to_owned(),
            delegated_by: None,
            created_at: 0,
            kind: 0,
            tags: Vec::new(),
            content: "".to_owned(),
            sig: "".to_owned(),
            tagidx: None,
        };
        assert!(s.interested_in_event(&e));
        Ok(())
    }

    #[test]
    fn authors_multi_pubkey() -> Result<()> {
        // check for any of a set of authors, against the pubkey
        let s: Subscription = serde_json::from_str(r#"["REQ","xyz",{"authors":["abc", "bcd"]}]"#)?;
        let e = Event {
            id: "123".to_owned(),
            pubkey: "bcd".to_owned(),
            delegated_by: None,
            created_at: 0,
            kind: 0,
            tags: Vec::new(),
            content: "".to_owned(),
            sig: "".to_owned(),
            tagidx: None,
        };
        assert!(s.interested_in_event(&e));
        Ok(())
    }

    #[test]
    fn authors_multi_no_match() -> Result<()> {
        // check for any of a set of authors, against the pubkey
        let s: Subscription = serde_json::from_str(r#"["REQ","xyz",{"authors":["abc", "bcd"]}]"#)?;
        let e = Event {
            id: "123".to_owned(),
            pubkey: "xyz".to_owned(),
            delegated_by: None,
            created_at: 0,
            kind: 0,
            tags: Vec::new(),
            content: "".to_owned(),
            sig: "".to_owned(),
            tagidx: None,
        };
        assert!(!s.interested_in_event(&e));
        Ok(())
    }

    #[test]
    fn serialize_filter() -> Result<()> {
        let s: Subscription = serde_json::from_str(
            r##"["REQ","xyz",{"authors":["abc", "bcd"], "since": 10, "until": 20, "limit":100, "#e": ["foo", "bar"], "#d": ["test"]}]"##,
        )?;
        let f = s.filters.first();
        let serialized = serde_json::to_string(&f)?;
        let serialized_wrapped = format!(r##"["REQ", "xyz",{}]"##, serialized);
        let parsed: Subscription = serde_json::from_str(&serialized_wrapped)?;
        let parsed_filter = parsed.filters.first();
        if let Some(pf) = parsed_filter {
            assert_eq!(pf.since, Some(10));
            assert_eq!(pf.until, Some(20));
            assert_eq!(pf.limit, Some(100));
            assert_eq!(f, parsed_filter, "serialization must preserve tag restrictions");
        } else {
            panic!("filter could not be parsed");
        }
        Ok(())
    }

    /// A filter's tag values are bounded only by the message size, and each AND
    /// value becomes its own subquery/JOIN. Ten thousand five-byte values fit in
    /// one 128 KB message and turn into a statement no engine plans cheaply --
    /// and with a blocking thread held for the duration. Reject the filter
    /// instead of trying to serve it.
    #[test]
    fn oversized_tag_filter_is_rejected() -> Result<()> {
        let vals: Vec<String> = (0..(MAX_TAG_VALUES_PER_FILTER + 1))
            .map(|i| format!("v{i}"))
            .collect();
        let json = format!(
            r##"["REQ","x",{{"kinds":[1],"#t":{}}}]"##,
            serde_json::to_string(&vals).unwrap()
        );
        assert!(
            serde_json::from_str::<Subscription>(&json).is_err(),
            "filter with {} tag values was accepted",
            vals.len()
        );
        Ok(())
    }

    /// Unlike tag values, `authors` and `ids` had no cap. Live measurement on the
    /// production relay (internal finding 71): 990 values returned EOSE in 0.10 s,
    /// while 999 never returned EOSE. SQLite raised "too many SQL variables" before
    /// EOSE was sent, leaving the subscription hanging and the SDK client timing out.
    /// A clear parse refusal is safer, honest, and never reaches the database.
    #[test]
    fn oversized_authors_filter_is_rejected() -> Result<()> {
        let vals: Vec<String> = (0..(MAX_IDS_OR_AUTHORS_PER_FILTER + 1))
            .map(|i| format!("{i:064x}"))
            .collect();
        let json = format!(
            r##"["REQ","x",{{"authors":{}}}]"##,
            serde_json::to_string(&vals).unwrap()
        );
        let err = serde_json::from_str::<Subscription>(&json)
            .expect_err("filter with too many authors was accepted");
        assert!(err.to_string().contains("too many authors"), "refusal omits reason: {err}");
        Ok(())
    }

    #[test]
    fn oversized_ids_filter_is_rejected() -> Result<()> {
        let vals: Vec<String> = (0..(MAX_IDS_OR_AUTHORS_PER_FILTER + 1))
            .map(|i| format!("{i:064x}"))
            .collect();
        let json = format!(r##"["REQ","x",{{"ids":{}}}]"##, serde_json::to_string(&vals).unwrap());
        let err = serde_json::from_str::<Subscription>(&json)
            .expect_err("filter with too many ids was accepted");
        assert!(err.to_string().contains("too many ids"), "refusal omits reason: {err}");
        Ok(())
    }

    /// Positive control: exactly at the cap is accepted. Without this, the test
    /// above would not distinguish a bounded relay from one rejecting every list.
    #[test]
    fn authors_filter_at_the_cap_is_accepted() -> Result<()> {
        let vals: Vec<String> = (0..MAX_IDS_OR_AUTHORS_PER_FILTER)
            .map(|i| format!("{i:064x}"))
            .collect();
        let json = format!(
            r##"["REQ","x",{{"authors":{}}}]"##,
            serde_json::to_string(&vals).unwrap()
        );
        let s: Subscription = serde_json::from_str(&json)?;
        assert_eq!(s.filters[0].authors.as_ref().map(Vec::len), Some(MAX_IDS_OR_AUTHORS_PER_FILTER));
        Ok(())
    }

    /// `#t` and `#t&` both land under the name "t", so one silently replaced the
    /// other and WHICH one survived depended on JSON key order. A filter whose
    /// meaning depends on map iteration order is not a filter -- refuse it.
    #[test]
    fn conflicting_or_and_operands_for_one_tag_are_rejected() -> Result<()> {
        let json = r##"["REQ","x",{"kinds":[1],"#t":["a"],"#t&":["b"]}]"##;
        assert!(
            serde_json::from_str::<Subscription>(json).is_err(),
            "conflicting #t and #t& were accepted; key order would choose semantics"
        );
        Ok(())
    }

    #[test]
    fn is_scraper() -> Result<()> {
        assert!(serde_json::from_str::<Subscription>(
            r#"["REQ","some-id",{"kinds": [1984],"since": 123,"limit":1}]"#
        )?
        .is_scraper());
        assert!(serde_json::from_str::<Subscription>(
            r#"["REQ","some-id",{"kinds": [1984]},{"kinds": [1984],"authors":["aaaa"]}]"#
        )?
        .is_scraper());
        assert!(!serde_json::from_str::<Subscription>(
            r#"["REQ","some-id",{"kinds": [1984],"authors":["aaaa"]}]"#
        )?
        .is_scraper());
        assert!(
            !serde_json::from_str::<Subscription>(r#"["REQ","some-id",{"ids": ["aaaa"]}]"#)?
                .is_scraper()
        );
        assert!(!serde_json::from_str::<Subscription>(
            r##"["REQ","some-id",{"#p": ["aaaa"],"kinds":[1,4]}]"##
        )?
        .is_scraper());
        Ok(())
    }

    #[test]
    fn multi_char_tag_filter_parses() -> Result<()> {
        // A4A discovery filter: `#category` must NOT be silently dropped
        // (this is the exact bug this task fixes).
        let raw_json = r##"["REQ","some-id",{"#category":["development"]}]"##;
        let s: Subscription = serde_json::from_str(raw_json)?;
        let f = s.filters.first().expect("one filter");
        let tags = f.tags.as_ref().expect("tags should be present");
        assert_eq!(
            tags.get("category"),
            Some(&TagOperand::Or(HashSet::from(["development".to_owned()])))
        );
        Ok(())
    }

    #[test]
    fn serialize_and_filter_preserves_operand_and_values() {
        let filter: ReqFilter = serde_json::from_str(r##"{"#category&":["development","review"]}"##).unwrap();
        let serialized = serde_json::to_string(&filter).unwrap();
        let restored: ReqFilter = serde_json::from_str(&serialized).unwrap();
        assert_eq!(filter, restored);
    }

    #[test]
    fn tag_filter_wrong_types_are_rejected() {
        for field in ["#p", "#category", "#category&"] {
            for value in [serde_json::json!("value"), serde_json::json!(null),
                          serde_json::json!({"value": "a"}), serde_json::json!(12)] {
                let filter = serde_json::json!({field: value});
                assert!(serde_json::from_value::<ReqFilter>(filter).is_err(),
                        "wrong type for {field} was silently discarded");
            }
        }
    }

    #[test]
    fn multi_char_tag_filter_and_operand_parses() -> Result<()> {
        // trailing `&` on a multi-char tag name means AND, same semantics
        // as the pre-existing single-char `#e&` behavior.
        let raw_json = r##"["REQ","some-id",{"#category&":["development","design"]}]"##;
        let s: Subscription = serde_json::from_str(raw_json)?;
        let f = s.filters.first().expect("one filter");
        let tags = f.tags.as_ref().expect("tags should be present");
        assert_eq!(
            tags.get("category"),
            Some(&TagOperand::And(HashSet::from([
                "development".to_owned(),
                "design".to_owned()
            ])))
        );
        Ok(())
    }

    #[test]
    fn single_char_tag_filter_still_parses_backward_compat() -> Result<()> {
        // Backward compatibility: standard NIP-01/NIP-12 single-char tag
        // filters (`#e`, `#e&`) must keep working exactly as before.
        let raw_json = r##"["REQ","some-id",{"#e":["abc"],"#p&":["def","ghi"]}]"##;
        let s: Subscription = serde_json::from_str(raw_json)?;
        let f = s.filters.first().expect("one filter");
        let tags = f.tags.as_ref().expect("tags should be present");
        assert_eq!(
            tags.get("e"),
            Some(&TagOperand::Or(HashSet::from(["abc".to_owned()])))
        );
        assert_eq!(
            tags.get("p"),
            Some(&TagOperand::And(HashSet::from([
                "def".to_owned(),
                "ghi".to_owned()
            ])))
        );
        Ok(())
    }
}
