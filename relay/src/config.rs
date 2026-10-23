//! Configuration file and settings management
use config::{Config, ConfigError, File};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[allow(unused)]
pub struct Info {
    pub relay_url: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub pubkey: Option<String>,
    pub contact: Option<String>,
    pub favicon: Option<String>,
    pub relay_icon: Option<String>,
    pub relay_page: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct Database {
    pub data_directory: String,
    pub engine: String,
    pub in_memory: bool,
    pub min_conn: u32,
    pub max_conn: u32,
    pub connection: String,
    pub connection_write: Option<String>,
    /// SQLite page cache PER CONNECTION, in megabytes.
    ///
    /// Upstream used 80 MiB, which with up to eight readers consumed as much as 800 MiB
    /// for cache alone, exceeding a typical node's memory. This value is multiplied by
    /// the number of connections, not shared among them.
    pub cache_size_mb: u64,
    /// Size threshold for one-time VACUUM when switching to incremental vacuum.
    ///
    /// Rebuilding requires roughly the database size in free space and holds a lock.
    /// A large database must not be rebuilt silently at startup, so above this threshold
    /// the relay only warns and lets the operator choose the maintenance window.
    pub vacuum_max_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct Grpc {
    pub event_admission_server: Option<String>,
    pub restricts_write: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct Network {
    pub port: u16,
    pub address: String,
    pub remote_ip_header: Option<String>, // retrieve client IP from this HTTP header if present
    pub ping_interval_seconds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct Options {
    pub reject_future_seconds: Option<usize>, // if defined, reject any events with a timestamp more than X seconds in the future
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct Retention {
    /// Database size ceiling. `None` means unlimited.
    ///
    /// A per-author event limit constrains a key, not the RESOURCE. Keys are free, so
    /// disk exhaustion remains linear in key count. This ceiling limits the resource
    /// that actually runs out: disk space.
    ///
    /// Only disposable kinds are removed, oldest first. History (agreements,
    /// revocations, trust, credentials, delegations) is NEVER deleted: reputation that
    /// disappears under storage pressure is worse than refusing new writes. If deleting
    /// disposable data is insufficient, the relay emits a prominent warning.
    pub max_db_bytes: Option<u64>,
    // `max_events` and `max_bytes` are parsed solely for compatibility with upstream
    // configuration files and have no runtime enforcement. Operators must use
    // `persist_days`, `kind_persist_days`, `max_events_per_author`, and `max_db_bytes`.
    pub max_events: Option<usize>,
    pub max_bytes: Option<usize>,
    /// Delete events older than N days. This is the only setting that bounds total disk
    /// growth; `messages_per_sec` limits RATE, not accumulated volume.
    pub persist_days: Option<usize>,
    /// Per-kind retention periods, taking precedence over the global period. Kinds are
    /// not equivalent: an expired request is useless, while agreements and revocations
    /// constitute reputation. Age-deleting those erases the history the system relies on.
    pub kind_persist_days: Option<std::collections::HashMap<u64, usize>>,
    /// Event ceiling per ONE key. Age retention bounds time, not volume. Because keys
    /// are free, this makes disk exhaustion linear in key count instead of unbounded
    /// for one key, but does not make exhaustion impossible.
    pub max_events_per_author: Option<usize>,
    /// Parsed for upstream configuration compatibility only. It grants no retention
    /// exemption; protected protocol kinds are selected by relay policy, not addresses.
    pub whitelist_addresses: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct Limits {
    pub messages_per_sec: Option<u32>, // Artificially slow down event writing to limit disk consumption (averaged over 1 minute)
    pub subscriptions_per_min: Option<u32>, // Artificially slow down request (db query) creation to prevent abuse (averaged over 1 minute)
    pub db_conns_per_client: Option<u32>, // How many concurrent database queries (not subscriptions) may a client have?
    pub max_blocking_threads: usize,
    pub max_event_bytes: Option<usize>, // Maximum size of an EVENT message
    pub max_ws_message_bytes: Option<usize>,
    pub max_ws_frame_bytes: Option<usize>,
    pub broadcast_buffer: usize, // events to buffer for subscribers (prevents slow readers from consuming memory)
    pub event_persist_buffer: usize, // events to buffer for database commits (block senders if database writes are too slow)
    pub event_kind_blacklist: Option<Vec<u64>>,
    pub event_kind_allowlist: Option<Vec<u64>>,
    pub limit_scrapers: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct Authorization {
    pub pubkey_whitelist: Option<Vec<String>>, // If present, only allow these pubkeys to publish events
    pub nip42_auth: bool,                      // if true enables NIP-42 authentication
    pub nip42_dms: bool, // if true send DMs only to their authenticated recipients
}


#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct Diagnostics {
    pub tracing: bool, // enables tokio console-subscriber
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum VerifiedUsersMode {
    Enabled,
    Passive,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct VerifiedUsers {
    pub mode: VerifiedUsersMode, // Mode of operation: "enabled" (enforce) or "passive" (check only). If none, this is simply disabled.
    pub domain_whitelist: Option<Vec<String>>, // If present, only allow verified users from these domains can publish events
    pub domain_blacklist: Option<Vec<String>>, // If present, allow all verified users from any domain except these
    pub verify_expiration: Option<String>, // how long a verification is cached for before no longer being used
    pub verify_update_frequency: Option<String>, // how often to attempt to update verification
    pub verify_expiration_duration: Option<Duration>, // internal result of parsing verify_expiration
    pub verify_update_frequency_duration: Option<Duration>, // internal result of parsing verify_update_frequency
    pub max_consecutive_failures: usize, // maximum number of verification failures in a row, before ceasing future checks
}

impl VerifiedUsers {
    pub fn init(&mut self) {
        self.verify_expiration_duration = self.verify_expiration_duration();
        self.verify_update_frequency_duration = self.verify_update_duration();
    }

    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.mode == VerifiedUsersMode::Enabled
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.mode == VerifiedUsersMode::Enabled || self.mode == VerifiedUsersMode::Passive
    }

    #[must_use]
    pub fn is_passive(&self) -> bool {
        self.mode == VerifiedUsersMode::Passive
    }

    #[must_use]
    pub fn verify_expiration_duration(&self) -> Option<Duration> {
        self.verify_expiration
            .as_ref()
            .and_then(|x| humantime::parse_duration(x).ok())
    }

    #[must_use]
    pub fn verify_update_duration(&self) -> Option<Duration> {
        self.verify_update_frequency
            .as_ref()
            .and_then(|x| humantime::parse_duration(x).ok())
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.verify_expiration_duration().is_some() && self.verify_update_duration().is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct Logging {
    pub folder_path: Option<String>,
    pub file_prefix: Option<String>,
}

/// Retired notary key and its retirement time (Unix seconds, by block time).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotaryRetired {
    pub pubkey: String,
    pub until: u64,
}

/// A4A (Agent-to-Agent) delegation-checking configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct A4a {
    /// Whether REST inbox reads require PROOF of key ownership.
    ///
    /// While disabled, `/v1/inbox?recipient=<key>` returns envelopes to ANY caller: the
    /// parameter names a recipient but proves nothing. A 2026-09-14 production probe
    /// retrieved real envelopes using an unrelated key. Content is encrypted, but can
    /// be harvested now for future decryption, while recipient and timing metadata is
    /// immediately exposed.
    ///
    /// The `false` default is INTENTIONAL: enabling this breaks existing clients that do
    /// not send the header. Rollout order is clients first, then relay enforcement.
    pub inbox_auth: bool,
    /// Master flag; when `false` all A4A delegation checks are skipped
    /// entirely (stock relay behavior).
    pub enabled: bool,
    /// Event kind used for A4A delegation events. INFORMATIONAL only: admission enforces
    /// `a4a_delegation::A4A_KIND_DELEGATION` (31000) and does not read this value.
    /// Keep it equal to the constant.
    pub delegation_kind: u64,
    /// Kinds that MUST carry a valid delegation tag. `None` means a
    /// delegation is only checked when the event happens to carry one.
    pub required_for_kinds: Option<Vec<u64>>,
    /// Pubkey (64 lowercase hex) of the time notary that stamps this relay's history
    /// events by NIP-03 (kind 1040). Published in NIP-11 as `a4a.notary` so readers
    /// accept attestations from THIS key only -- any pubkey can publish a 1040, and a
    /// reader that trusted an arbitrary one could be handed a forged proof. The notary
    /// itself is a sidecar, not relay code (docs/design/2026-09-04-ots-notary-design.md).
    /// `None` -- no notary announced.
    pub notary_pubkey: Option<String>,
    /// Retired notary keys after rotation or compromise. A reader accepts such a key's
    /// timestamp only when proof block time T <= `until`. A timestamp for a PAST block
    /// cannot be forged because its digest had to be in that block's calendar tree, so
    /// the T boundary holds even against a stolen key. This list only grows because old
    /// timestamps are verified for years. docs/design/2026-09-04-notary-key-rotation.md
    #[serde(default)]
    pub notary_retired: Vec<NotaryRetired>,
    /// TTL, in seconds, for the validated-delegation cache.
    pub delegation_cache_ttl_secs: u64,
    /// Cap on the number of delegation-lookup cache MISSES (i.e. calls that
    /// fall through to a repo fetch + Schnorr verification in
    /// `check_a4a_delegation`) admitted per second, across the whole relay
    /// process. Protects `db_writer` -- the single-threaded write loop --
    /// from a cold-cache flood: a stream of events each referencing a
    /// unique, never-cached delegation id would otherwise force a DB
    /// round-trip and a full signature verification for every event,
    /// degrading write throughput for ALL clients (hardening backlog item
    /// 2). Cache HITS are never counted/limited by this.
    ///
    /// `0` is treated the same as leaving this unset: it falls back to a
    /// built-in default (`db::DEFAULT_DELEGATION_LOOKUP_RATE_PER_SEC`, 50/s)
    /// rather than meaning "unlimited" or "always blocked".
    pub delegation_lookup_rate_per_sec: u32,
    /// Gates the `/v1/*` REST surface (used by later A4A tasks; defined
    /// here so the config section is complete up front).
    pub rest_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct Settings {
    pub info: Info,
    pub diagnostics: Diagnostics,
    pub database: Database,
    pub grpc: Grpc,
    pub network: Network,
    pub limits: Limits,
    pub authorization: Authorization,
    pub verified_users: VerifiedUsers,
    pub retention: Retention,
    pub options: Options,
    pub logging: Logging,
    pub a4a: A4a,
}

impl Settings {
    /// Enforcement is ADVISORY: A4A is on, but nothing is actually required.
    ///
    /// With `enabled = true` and no `required_for_kinds`, a delegation is verified only
    /// when an event happens to carry one; an event without the tag is admitted
    /// unchecked. The operator sees "A4A enabled" and believes provenance is guarded,
    /// while it is left to whoever publishes. That half-state said nothing anywhere at
    /// runtime until this check existed, and the shipped example config makes it easy to
    /// land in: it ships `enabled = false` with `required_for_kinds` commented out, so
    /// flipping only the first line produces exactly this.
    ///
    /// A separate predicate rather than an inline condition in `main` so that it can be
    /// tested at all. A guard nobody has watched fire is not a guard.
    #[must_use]
    pub fn a4a_enforcement_is_advisory(&self) -> bool {
        self.a4a.enabled
            && self
                .a4a
                .required_for_kinds
                .as_ref()
                .is_none_or(|kinds| kinds.is_empty())
    }

    pub fn new(config_file_name: &Option<String>) -> Result<Self, ConfigError> {
        let default_settings = Self::default();
        // attempt to construct settings with file
        let from_file = Self::new_from_default(&default_settings, config_file_name);
        match from_file {
            Err(e) => {
                // pass up the parse error if the config file was specified,
                // otherwise use the default config (with a warning).
                if config_file_name.is_some() {
                    Err(e)
                } else {
                    eprintln!("Error reading config file ({:?})", e);
                    eprintln!("WARNING: Default configuration settings will be used");
                    Ok(default_settings)
                }
            }
            ok => ok,
        }
    }

    fn new_from_default(
        default: &Settings,
        config_file_name: &Option<String>,
    ) -> Result<Self, ConfigError> {
        let default_config_file_name = "config.toml".to_string();
        let config: &String = match config_file_name {
            Some(value) => value,
            None => &default_config_file_name,
        };
        let builder = Config::builder();
        let config: Config = builder
            // use defaults
            .add_source(Config::try_from(default)?)
            // override with file contents
            .add_source(File::with_name(config))
            .build()?;
        let mut settings: Settings = config.try_deserialize()?;
        // ensure connection pool size is logical
        assert!(
            !settings.a4a.enabled
                || settings.a4a.delegation_kind == crate::a4a_delegation::A4A_KIND_DELEGATION,
            "a4a.delegation_kind ({}) differs from the kind the relay actually checks ({}).              This setting is informational and does not affect enforcement; changing it would              falsely suggest that enforcement changed.",
            settings.a4a.delegation_kind,
            crate::a4a_delegation::A4A_KIND_DELEGATION
        );
        validate(&settings);
        // initialize durations for verified users
        settings.verified_users.init();


        Ok(settings)
    }
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            info: Info {
                relay_url: None,
                name: Some("A4A Relay".to_owned()),
                description: None,
                pubkey: None,
                contact: None,
                favicon: None,
                relay_icon: None,
                relay_page: None,
            },
            diagnostics: Diagnostics { tracing: false },
            database: Database {
                data_directory: ".".to_owned(),
                engine: "sqlite".to_owned(),
                in_memory: false,
                min_conn: 4,
                max_conn: 8,
                connection: "".to_owned(),
                connection_write: None,
                cache_size_mb: 8,
                vacuum_max_bytes: 2 * 1024 * 1024 * 1024,
            },
            grpc: Grpc {
                event_admission_server: None,
                restricts_write: false,
            },
            network: Network {
                port: 8080,
                ping_interval_seconds: 300,
                // Missing/unreadable implicit config must never expose an unlimited
                // relay on every interface. Public bind is an explicit operator choice.
                address: "127.0.0.1".to_owned(),
                remote_ip_header: None,
            },
            limits: Limits {
                messages_per_sec: Some(5),
                subscriptions_per_min: Some(10),
                db_conns_per_client: None,
                max_blocking_threads: 16,
                max_event_bytes: Some(2 << 17),      // 128K
                max_ws_message_bytes: Some(2 << 17), // 128K
                max_ws_frame_bytes: Some(2 << 17),   // 128K
                broadcast_buffer: 16384,
                event_persist_buffer: 4096,
                event_kind_blacklist: None,
                event_kind_allowlist: None,
                limit_scrapers: false,
            },
            authorization: Authorization {
                pubkey_whitelist: None, // Allow any address to publish
                nip42_auth: false,      // Disable NIP-42 authentication
                nip42_dms: false,       // Send DMs to everybody
            },
            verified_users: VerifiedUsers {
                mode: VerifiedUsersMode::Disabled,
                domain_whitelist: None,
                domain_blacklist: None,
                verify_expiration: Some("1 week".to_owned()),
                verify_update_frequency: Some("1 day".to_owned()),
                verify_expiration_duration: None,
                verify_update_frequency_duration: None,
                max_consecutive_failures: 20,
            },
            retention: Retention {
                kind_persist_days: None,
                max_events_per_author: None,
                max_db_bytes: None,
                max_events: None,          // max events
                max_bytes: None,           // max size
                persist_days: None,        // oldest message
                whitelist_addresses: None, // whitelisted addresses (never delete)
            },
            options: Options {
                reject_future_seconds: None, // Reject events in the future if defined
            },
            logging: Logging {
                folder_path: None,
                file_prefix: None,
            },
            a4a: A4a {
                enabled: false,
                delegation_kind: 31000,
                required_for_kinds: None,
                notary_pubkey: None,
                notary_retired: Vec::new(),
                delegation_cache_ttl_secs: 300,
                delegation_lookup_rate_per_sec: 50,
                rest_enabled: false,
                // Disabled by default because enabling it breaks clients that omit the header.
                inbox_auth: false,
            },
        }
    }
}

/// Configuration checks without which the relay must not start.
///
/// Kept separate from the loader so tests can call it directly. A validation rule that
/// cannot be invoked by tests cannot be verified, and silently skipped configuration
/// validation is exactly the failure class this function prevents.
///
/// Panicking is appropriate here because startup is the only time to reject an invalid
/// setting before it begins failing silently.
pub fn validate(settings: &Settings) {
    // NIP-11 advertises the notary key, which readers compare byte-for-byte with kind-1040
    // authors. Non-canonical case or length would silently make every timestamp foreign.
    // Fail at startup rather than during client verification a month later.
    if let Some(pk) = settings.a4a.notary_pubkey.as_deref() {
        assert!(
            crate::a4a_delegation::is_canonical_pubkey(pk),
            "a4a.notary_pubkey must be 64 lowercase hex characters, got {pk:?}"
        );
    }
    // Retired notary keys must be canonical hex, have until > 0, be unique, and differ
    // from the current key; otherwise readers could accept foreign stamps or drop ours.
    let mut seen_retired: Vec<&str> = Vec::new();
    for r in &settings.a4a.notary_retired {
        assert!(
            crate::a4a_delegation::is_canonical_pubkey(&r.pubkey),
            "a4a.notary_retired: pubkey must be 64 lowercase hex characters, got {:?}",
            r.pubkey
        );
        assert!(r.until > 0, "a4a.notary_retired: until must be > 0 for {}", r.pubkey);
        assert!(
            settings.a4a.notary_pubkey.as_deref() != Some(r.pubkey.as_str()),
            "a4a.notary_retired: key {} is both current (notary_pubkey) and retired",
            r.pubkey
        );
        assert!(
            !seen_retired.contains(&r.pubkey.as_str()),
            "a4a.notary_retired: key {} is listed twice",
            r.pubkey
        );
        seen_retired.push(&r.pubkey);
    }
    // A4A behavior exists only in the SQLite engine: replaced-delegation archive
    // (`/v1/delegation-history`), intake-time history (`/v1/history`, notary), and
    // retention-protected kinds. The other engine would answer parts of the specification
    // with empty data or 501, so refusing startup is more honest (internal finding 47).
    // Upstream Postgres without A4A (`a4a.enabled = false`) remains supported.
    assert!(
        !settings.a4a.enabled || settings.database.engine == "sqlite",
        "a4a.enabled = true is supported only with database.engine = \"sqlite\" (got \
         {:?}): delegation archive, intake-time history, and retention protection are \
         implemented only for SQLite",
        settings.database.engine
    );
    if settings.a4a.inbox_auth {
        assert!(
            settings.a4a.rest_enabled,
            "a4a.inbox_auth requires a4a.rest_enabled = true"
        );
        let relay_url = settings
            .info
            .relay_url
            .as_deref()
            .expect("a4a.inbox_auth requires info.relay_url for NIP-98 origin binding");
        let parsed = url::Url::parse(relay_url)
            .expect("info.relay_url must be a valid absolute URL when a4a.inbox_auth is enabled");
        assert!(
            matches!(parsed.scheme(), "ws" | "wss")
                && parsed.host_str().is_some()
                && parsed.username().is_empty()
                && parsed.password().is_none()
                && (parsed.path().is_empty() || parsed.path() == "/")
                && parsed.query().is_none()
                && parsed.fragment().is_none(),
            "info.relay_url must be a canonical ws/wss origin without credentials, path, query, or fragment when a4a.inbox_auth is enabled"
        );
    }
    // REST publishes with `auth_pubkey: None` because HTTP has no NIP-42 session.
    // `nip42_dms` promises that direct messages involve authenticated peers only, a
    // promise `/v1/publish` cannot keep. Reject this configuration at startup.
    assert!(
        !(settings.a4a.rest_enabled && settings.authorization.nip42_dms),
        "a4a.rest_enabled conflicts with authorization.nip42_dms: REST publication is \
         unauthenticated (auth_pubkey = None), so /v1/publish cannot uphold nip42_dms; \
         disable one of the two"
    );
    assert!(
        !settings.a4a.enabled
            || settings.a4a.delegation_kind == crate::a4a_delegation::A4A_KIND_DELEGATION,
        "a4a.delegation_kind ({}) differs from the kind the relay actually checks ({}). \
         This setting is informational and does not affect enforcement; changing it \
         would falsely suggest that enforcement changed.",
        settings.a4a.delegation_kind,
        crate::a4a_delegation::A4A_KIND_DELEGATION
    );
    // Retention is implemented only for SQLite. The Postgres backend deletes only by
    // NIP-40, so `[retention]` settings have no effect there while an operator who set
    // a disk ceiling would believe the disk protected. Security settings must never be
    // ignored silently: either they work or startup refuses with a reason (finding 47,
    // 2026-08-30).
    let retention_configured = settings.retention.persist_days.is_some()
        || settings.retention.max_events_per_author.is_some()
        || settings.retention.max_db_bytes.is_some()
        || settings
            .retention
            .kind_persist_days
            .as_ref()
            .is_some_and(|k| !k.is_empty());
    assert!(
        !retention_configured || settings.database.engine == "sqlite",
        "[retention] settings are configured but the storage engine is '{}': retention \
         is implemented only for sqlite and these settings DO NOT WORK on another engine. \
         Remove them or switch to sqlite",
        settings.database.engine
    );
    assert!(
        settings.database.min_conn <= settings.database.max_conn,
        "Database min_conn setting ({}) cannot exceed max_conn ({})",
        settings.database.min_conn,
        settings.database.max_conn
    );
    assert!(
        settings.verified_users.is_valid(),
        "VerifiedUsers time settings could not be parsed"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_config_fallback_is_loopback_and_rate_limited() {
        let settings = Settings::default();
        assert_eq!(settings.network.address, "127.0.0.1");
        assert_eq!(settings.limits.messages_per_sec, Some(5));
        assert_eq!(settings.limits.subscriptions_per_min, Some(10));
        assert!(settings.limits.max_event_bytes.is_some());
        assert!(settings.limits.max_ws_message_bytes.is_some());
        assert!(settings.limits.max_ws_frame_bytes.is_some());
    }

    /// NIP-98 proves an absolute URL. Without a configured public relay origin the
    /// server can compare only a path, so a proof intercepted from another host can be
    /// replayed against this one. Fail at startup instead of weakening the binding.
    #[test]
    #[should_panic(expected = "requires info.relay_url")]
    fn inbox_auth_without_a_public_origin_is_refused() {
        let mut settings = Settings::default();
        settings.a4a.rest_enabled = true;
        settings.a4a.inbox_auth = true;
        settings.info.relay_url = None;
        validate(&settings);
    }

    #[test]
    #[should_panic(expected = "canonical ws/wss origin")]
    fn inbox_auth_with_ambiguous_origin_is_refused() {
        let mut settings = Settings::default();
        settings.a4a.rest_enabled = true;
        settings.a4a.inbox_auth = true;
        settings.info.relay_url = Some("https://user@example.invalid/?tenant=one".to_owned());
        validate(&settings);
    }

    #[test]
    #[should_panic(expected = "canonical ws/wss origin")]
    fn inbox_auth_with_a_path_in_the_origin_is_refused() {
        let mut settings = Settings::default();
        settings.a4a.rest_enabled = true;
        settings.a4a.inbox_auth = true;
        settings.info.relay_url = Some("wss://relay.example.invalid/tenant/one".to_owned());
        validate(&settings);
    }

    #[test]
    fn inbox_auth_with_canonical_origin_is_allowed() {
        let mut settings = Settings::default();
        settings.a4a.rest_enabled = true;
        settings.a4a.inbox_auth = true;
        settings.info.relay_url = Some("wss://relay.example.invalid".to_owned());
        validate(&settings);
    }

    /// TOML keys are strings while Rust uses `HashMap<u64, usize>`. If serde cannot
    /// parse this, the setting silently disappears, per-kind retention fails, and the
    /// node keeps growing despite an apparently configured file. Test parsing directly.
    /// Retention settings on an engine that cannot enforce them must fail at startup.
    ///
    /// Retention (per-kind age, per-author ceiling, database-size ceiling) and delegation
    /// protection exist only in SQLite; Postgres deletes only under NIP-40. An operator
    /// who sets `max_db_bytes` would believe the disk protected until the node stops.
    /// Security configuration cannot be silently ignored (finding 47, 2026-08-30).
    #[test]
    #[should_panic(expected = "[retention]")]
    fn retention_on_an_engine_that_ignores_it_is_refused() {
        let mut settings = Settings::default();
        settings.database.engine = "postgres".to_owned();
        settings.retention.max_db_bytes = Some(4 * 1024 * 1024 * 1024);
        validate(&settings);
    }

    /// Postgres WITHOUT retention settings starts normally: the combination, not the
    /// engine itself, must be rejected.
    #[test]
    fn postgres_without_retention_settings_is_allowed() {
        let mut settings = Settings::default();
        settings.database.engine = "postgres".to_owned();
        settings.retention.persist_days = None;
        settings.retention.max_events_per_author = None;
        settings.retention.max_db_bytes = None;
        settings.retention.kind_persist_days = None;
        validate(&settings);
    }

    /// Positive control: the same settings pass on SQLite. Without this, a rule that
    /// always rejects retention would also make the previous test green.
    #[test]
    fn retention_on_sqlite_is_allowed() {
        let mut settings = Settings::default();
        settings.database.engine = "sqlite".to_owned();
        settings.retention.max_db_bytes = Some(4 * 1024 * 1024 * 1024);
        validate(&settings);
    }

    #[test]
    fn retention_section_is_parsed_from_toml() {
        let toml = r#"
[retention]
max_events_per_author = 5000

[retention.kind_persist_days]
31002 = 90
1059 = 60
"#;
        let default_settings = Settings::default();
        let settings: Settings = Config::builder()
            .add_source(Config::try_from(&default_settings).unwrap())
            .add_source(config::File::from_str(toml, config::FileFormat::Toml))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();
        assert_eq!(settings.retention.max_events_per_author, Some(5000));
        let kinds = settings
            .retention
            .kind_persist_days
            .expect("kind_persist_days was not parsed; per-kind retention is inactive");
        assert_eq!(kinds.get(&31002), Some(&90));
        assert_eq!(kinds.get(&1059), Some(&60));
    }

    /// A `[a4a]` section in the config file should populate every field of
    /// `Settings::a4a`, overriding the defaults.
    #[test]
    fn a4a_section_is_parsed_from_toml() {
        let default_settings = Settings::default();
        let toml = r#"
[a4a]
enabled = true
delegation_kind = 10001
required_for_kinds = [1, 30078]
delegation_cache_ttl_secs = 60
delegation_lookup_rate_per_sec = 25
rest_enabled = true
"#;
        let config = Config::builder()
            .add_source(Config::try_from(&default_settings).unwrap())
            .add_source(config::File::from_str(toml, config::FileFormat::Toml))
            .build()
            .unwrap();
        let settings: Settings = config.try_deserialize().unwrap();
        assert!(settings.a4a.enabled);
        assert_eq!(settings.a4a.delegation_kind, 10001);
        assert_eq!(settings.a4a.required_for_kinds, Some(vec![1, 30078]));
        assert_eq!(settings.a4a.delegation_cache_ttl_secs, 60);
        assert_eq!(settings.a4a.delegation_lookup_rate_per_sec, 25);
        assert!(settings.a4a.rest_enabled);
    }

    /// A config file with NO `[a4a]` section at all must fall back to the
    /// defaults (`enabled: false`), without panicking.
    /// REST publishes with `auth_pubkey: None` because HTTP has no NIP-42 session.
    /// Enabling `nip42_dms` promises authenticated direct-message peers, which
    /// `/v1/publish` cannot guarantee. The combination is rejected at startup.
    #[test]
    #[should_panic(expected = "rest_enabled")]
    fn rest_publish_together_with_nip42_dms_refuses_to_start() {
        let mut settings = Settings::default();
        settings.a4a.rest_enabled = true;
        settings.authorization.nip42_dms = true;
        validate(&settings);
    }

    fn retired(pk: &str, until: u64) -> NotaryRetired {
        NotaryRetired { pubkey: pk.to_owned(), until }
    }

    #[test]
    fn retired_notary_keys_are_accepted_when_canonical_and_distinct() {
        let mut settings = Settings::default();
        settings.a4a.notary_pubkey = Some("ab".repeat(32));
        settings.a4a.notary_retired = vec![retired(&"cd".repeat(32), 1_788_000_000), retired(&"ef".repeat(32), 1_700_000_000)];
        validate(&settings);
    }

    #[test]
    #[should_panic(expected = "notary_retired")]
    fn retired_key_in_upper_case_fails_fast() {
        let mut settings = Settings::default();
        settings.a4a.notary_retired = vec![retired(&"CD".repeat(32), 1)];
        validate(&settings);
    }

    #[test]
    #[should_panic(expected = "until")]
    fn retired_key_without_until_fails_fast() {
        let mut settings = Settings::default();
        settings.a4a.notary_retired = vec![retired(&"cd".repeat(32), 0)];
        validate(&settings);
    }

    #[test]
    #[should_panic(expected = "both current")]
    fn retired_key_equal_to_current_fails_fast() {
        let mut settings = Settings::default();
        settings.a4a.notary_pubkey = Some("ab".repeat(32));
        settings.a4a.notary_retired = vec![retired(&"ab".repeat(32), 1)];
        validate(&settings);
    }

    #[test]
    #[should_panic(expected = "listed twice")]
    fn duplicate_retired_key_fails_fast() {
        let mut settings = Settings::default();
        settings.a4a.notary_retired = vec![retired(&"cd".repeat(32), 1), retired(&"cd".repeat(32), 2)];
        validate(&settings);
    }

    /// Existing configs without `notary_retired` parse it as an empty list.
    #[test]
    fn config_without_notary_retired_loads_as_empty() {
        let toml = r#"
[a4a]
enabled = true
notary_pubkey = "abababababababababababababababababababababababababababababababab"
"#;
        let settings: Settings = config::Config::builder()
            .add_source(config::Config::try_from(&Settings::default()).unwrap())
            .add_source(config::File::from_str(toml, config::FileFormat::Toml))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();
        assert!(settings.a4a.notary_retired.is_empty());
        let toml2 = r#"
[a4a]
enabled = true
notary_retired = [{ pubkey = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", until = 1788000000 }]
"#;
        let settings: Settings = config::Config::builder()
            .add_source(config::Config::try_from(&Settings::default()).unwrap())
            .add_source(config::File::from_str(toml2, config::FileFormat::Toml))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();
        assert_eq!(settings.a4a.notary_retired, vec![retired(&"cd".repeat(32), 1_788_000_000)]);
    }

    /// A4A on Postgres fails at startup: archive, intake-time history, and history
    /// protection exist only in SQLite, so the second engine would underserve the spec.
    #[test]
    #[should_panic(expected = "sqlite")]
    fn a4a_on_postgres_refuses_to_start() {
        let mut settings = Settings::default();
        settings.a4a.enabled = true;
        settings.database.engine = "postgres".to_owned();
        validate(&settings);
    }

    #[test]
    fn plain_postgres_without_a4a_is_untouched() {
        let mut settings = Settings::default();
        settings.a4a.enabled = false;
        settings.database.engine = "postgres".to_owned();
        validate(&settings);
    }

    #[test]
    fn rest_publish_without_nip42_dms_is_fine() {
        let mut settings = Settings::default();
        settings.a4a.rest_enabled = true;
        validate(&settings);
    }

    #[test]
    fn missing_a4a_section_falls_back_to_default() {
        let default_settings = Settings::default();
        // A config file that doesn't mention `[a4a]` at all, but does
        // override something unrelated, to prove the rest of the merge
        // still works normally.
        let toml = r#"
[network]
port = 12345
"#;
        let config = Config::builder()
            .add_source(Config::try_from(&default_settings).unwrap())
            .add_source(config::File::from_str(toml, config::FileFormat::Toml))
            .build()
            .unwrap();
        let settings: Settings = config.try_deserialize().unwrap();
        assert_eq!(settings.network.port, 12345);
        assert!(!settings.a4a.enabled);
        assert_eq!(settings.a4a.delegation_kind, 31000);
        assert_eq!(settings.a4a.delegation_cache_ttl_secs, 300);
        assert_eq!(settings.a4a.delegation_lookup_rate_per_sec, 50);
        assert!(settings.a4a.required_for_kinds.is_none());
        assert!(!settings.a4a.rest_enabled);
    }

    #[test]
    fn advisory_enforcement_is_detected_and_only_then() {
        // The dangerous state is exactly half-enabled: A4A is on but requires nothing.
        // Cover all four cases so "did not trigger" differs from "cannot detect."
        let mut settings = Settings::default();

        settings.a4a.enabled = false;
        settings.a4a.required_for_kinds = None;
        assert!(!settings.a4a_enforcement_is_advisory(), "disabled A4A promises nothing");

        settings.a4a.enabled = true;
        settings.a4a.required_for_kinds = None;
        assert!(settings.a4a_enforcement_is_advisory(), "enabled without a list is only advisory");

        settings.a4a.required_for_kinds = Some(vec![]);
        assert!(settings.a4a_enforcement_is_advisory(), "an empty list is equally advisory");

        settings.a4a.required_for_kinds = Some(vec![31001]);
        assert!(!settings.a4a_enforcement_is_advisory(), "a populated list enables real enforcement");
    }
}
