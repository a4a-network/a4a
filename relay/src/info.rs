//! Relay metadata using NIP-11
/// Relay Info
use crate::config::Settings;
use serde::{Deserialize, Serialize};

pub const CARGO_PKG_VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");
pub const UNIT: &str = "msats";

/// A4A fork version, maintained separately from the upstream crate version.
/// They identify different products and must not be conflated in health reports.
pub const A4A_RELAY_VERSION: &str = "0.3.23";

/// A4A capabilities advertised through NIP-11.
///
/// Without this declaration, a client can distinguish an A4A-aware relay from a stock
/// relay only by sending a request and observing the result. The distinction matters:
/// a stock relay IGNORES a multi-character tag filter and returns everything, while
/// strfry rejects the request. Advance knowledge lets clients select a query strategy
/// instead of discovering compatibility through failure.
#[derive(Debug, Serialize, Deserialize)]
pub struct A4aCapabilities {
    /// A4A protocol version implemented by the relay.
    pub protocol: String,
    /// Whether the relay indexes and filters multi-character tags (`#category`, `#agreement`).
    pub multi_char_tag_filters: bool,
    /// Whether `/v1/inbox` requires a NIP-98 proof from the recipient key.
    pub inbox_auth: bool,
    /// Event kinds that require a valid owner mandate (kind 31000).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_required_for_kinds: Option<Vec<u64>>,
    /// Time-notary public key. Readers accept only this key's kind-1040 (NIP-03)
    /// events as timestamps for this relay's history. Absent when no notary is declared.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notary: Option<String>,
    /// Retired notary keys. A timestamp from such a key is accepted only when the
    /// block time T <= until. Absent when the key has never rotated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notary_retired: Option<Vec<crate::config::NotaryRetired>>,
}

/// Limitations of the relay as specified in NIP-111
/// (This nip isn't finalized so may change)
#[derive(Debug, Serialize, Deserialize)]
#[allow(unused)]
pub struct Limitation {
    #[serde(skip_serializing_if = "Option::is_none")]
    payment_required: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    restricted_writes: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(unused)]
pub struct Fees {
    #[serde(skip_serializing_if = "Option::is_none")]
    admission: Option<Vec<Fee>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    publication: Option<Vec<Fee>>,
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(unused)]
pub struct Fee {
    amount: u64,
    unit: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(unused)]
pub struct RelayInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_nips: Option<Vec<i64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limitation: Option<Limitation>,
    /// Extension field advertising A4A capabilities. Readers that do not recognize
    /// it ignore it, as NIP-11 permits, while A4A clients can discover support.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub a4a: Option<A4aCapabilities>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fees: Option<Fees>,
}

/// Convert an Info configuration into public Relay Info
impl From<Settings> for RelayInfo {
    fn from(c: Settings) -> Self {
        let mut supported_nips = vec![1, 2, 9, 11, 12, 15, 16, 20, 22, 33, 40];

        if c.authorization.nip42_auth {
            supported_nips.push(42);
            supported_nips.sort();
        }

        let i = c.info;

        let limitations = Limitation {
            payment_required: Some(false),
            restricted_writes: Some(
                c.verified_users.is_enabled()
                    || c.authorization.pubkey_whitelist.is_some()
                    || c.grpc.restricts_write
                    // A relay that requires delegation for at least one event kind has
                    // restricted writes; otherwise clients learn this only on rejection.
                    || (c.a4a.enabled
                        && c.a4a
                            .required_for_kinds
                            .as_ref()
                            .is_some_and(|k| !k.is_empty())),
            ),
        };

        // The paid-relay subsystem was removed on 2026-08-28. This relay is free;
        // publication is restricted through an allowlist and Web of Trust, not payment.
        let (payment_url, fees): (Option<String>, Option<Fees>) = (None, None);

        let a4a_caps = if c.a4a.enabled {
            Some(A4aCapabilities {
                protocol: "0.4".to_owned(),
                multi_char_tag_filters: true,
                inbox_auth: c.a4a.inbox_auth,
                delegation_required_for_kinds: c
                    .a4a
                    .required_for_kinds
                    .clone()
                    .filter(|k| !k.is_empty()),
                notary: c.a4a.notary_pubkey.clone(),
                notary_retired: Some(c.a4a.notary_retired.clone()).filter(|v| !v.is_empty()),
            })
        } else {
            None
        };

        RelayInfo {
            id: i.relay_url,
            name: i.name,
            description: i.description,
            pubkey: i.pubkey,
            contact: i.contact,
            supported_nips: Some(supported_nips),
            // Identify the fork, not upstream. Publishing a modified binary under the
            // upstream project's name would misattribute our defects. The upstream
            // version from which this fork diverged is reported alongside it.
            software: Some("https://a4a.network".to_owned()),
            version: Some(format!(
                "{A4A_RELAY_VERSION} (a4a-relay {})",
                CARGO_PKG_VERSION.unwrap_or("unknown")
            )),
            a4a: a4a_caps,
            limitation: Some(limitations),
            payment_url,
            fees,
            icon: i.relay_icon,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Settings;

    /// The relay must identify itself as a fork rather than as upstream.
    ///
    /// This is a modified binary. Claiming the upstream identity would misattribute our
    /// defects and send readers to the wrong source. The useful upstream version remains
    /// visible alongside the fork version.
    #[test]
    fn relay_identifies_itself_as_a_fork() {
        let info: RelayInfo = Settings::default().into();
        let software = info.software.unwrap();
        assert_eq!(
            software,
            "https://a4a.network",
            "relay identifies itself unexpectedly: {software}"
        );
        let version = info.version.unwrap();
        assert!(version.starts_with(A4A_RELAY_VERSION), "relay version missing: {version}");
        assert!(version.contains("a4a-relay"), "relay version origin missing: {version}");
    }

    /// Clients must discover A4A support without probing for a failure.
    ///
    /// A stock relay ignores multi-character tag filters and returns everything, while
    /// strfry rejects the request. This difference determines the query strategy and
    /// must therefore be advertised in advance.
    #[test]
    fn a4a_capabilities_are_advertised_when_enabled() {
        let mut settings = Settings::default();
        settings.a4a.enabled = true;
        settings.a4a.required_for_kinds = Some(vec![31002, 31003]);
        let info: RelayInfo = settings.into();
        let caps = info.a4a.expect("A4A capabilities were not advertised");
        assert!(caps.multi_char_tag_filters);
        assert!(!caps.inbox_auth);
        assert_eq!(caps.delegation_required_for_kinds, Some(vec![31002, 31003]));
        // When no notary is declared, omit the field entirely instead of emitting `null`.
        assert!(caps.notary.is_none());
        let json = serde_json::to_string(&caps).unwrap();
        assert!(!json.contains("notary"), "NIP-11 contains a notary field without a notary: {json}");
    }

    #[test]
    fn inbox_auth_requirement_is_advertised() {
        let mut settings = Settings::default();
        settings.a4a.enabled = true;
        settings.a4a.inbox_auth = true;
        let info: RelayInfo = settings.into();
        let caps = info.a4a.expect("A4A capabilities were not advertised");
        assert!(caps.inbox_auth);
        assert!(serde_json::to_string(&caps).unwrap().contains("\"inbox_auth\":true"));
    }

    /// Readers accept timestamps (kind 1040, NIP-03) only from the relay-advertised
    /// notary. Any key can publish kind 1040, so arbitrary authors cannot be trusted.
    /// The notary public key therefore belongs in NIP-11 rather than in client constants.
    #[test]
    fn notary_pubkey_is_advertised_when_configured() {
        let mut settings = Settings::default();
        settings.a4a.enabled = true;
        settings.a4a.notary_pubkey = Some("ab".repeat(32));
        let info: RelayInfo = settings.into();
        let caps = info.a4a.expect("A4A capabilities were not advertised");
        assert_eq!(caps.notary.as_deref(), Some("ab".repeat(32).as_str()));
    }

    /// A non-canonical notary key must fail at startup, not diverge silently later.
    #[test]
    fn retired_notary_keys_are_advertised_only_when_present() {
        let mut settings = Settings::default();
        settings.a4a.enabled = true;
        settings.a4a.notary_pubkey = Some("ab".repeat(32));
        let json = { let info: RelayInfo = settings.clone().into(); serde_json::to_string(&info).unwrap() };
        assert!(!json.contains("notary_retired"), "empty retired-notary list appeared in NIP-11: {json}");
        settings.a4a.notary_retired = vec![crate::config::NotaryRetired { pubkey: "cd".repeat(32), until: 1_788_000_000 }];
        let json = { let info: RelayInfo = settings.clone().into(); serde_json::to_string(&info).unwrap() };
        assert!(json.contains(&format!("\"notary_retired\":[{{\"pubkey\":\"{}\",\"until\":1788000000}}]", "cd".repeat(32))), "{json}");
    }

    #[test]
    #[should_panic(expected = "notary_pubkey")]
    fn non_canonical_notary_pubkey_fails_fast() {
        let mut settings = Settings::default();
        settings.a4a.notary_pubkey = Some("AB".repeat(32));
        crate::config::validate(&settings);
    }

    /// A relay with A4A disabled must not advertise the capability. A false declaration
    /// is worse than silence because clients will build unsupported queries around it.
    #[test]
    fn a4a_capabilities_are_absent_when_disabled() {
        let mut settings = Settings::default();
        settings.a4a.enabled = false;
        let info: RelayInfo = settings.into();
        assert!(info.a4a.is_none(), "disabled A4A subsystem advertised capabilities");
    }
}
