//! Event persistence and querying
use crate::a4a_delegation::{delegation_rejection, validate_a4a_revocation};
use crate::config::Settings;
use crate::error::{Error, Result};
use crate::event::Event;
use crate::nauthz;
use crate::notice::Notice;
use crate::repo::postgres::{PostgresPool, PostgresRepo};
use crate::repo::sqlite::SqliteRepo;
use crate::repo::NostrRepo;
use crate::server::NostrMetrics;
use crate::utils::unix_time;
use governor::clock::Clock;
use governor::{Quota, RateLimiter};
use log::LevelFilter;
use r2d2;
use sqlx::pool::PoolOptions;
use sqlx::postgres::PgConnectOptions;
use sqlx::ConnectOptions;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, info, trace, warn, error};

pub type SqlitePool = r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>;
pub type PooledConnection = r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>;

/// Events submitted from a client, with a return channel for notices
pub struct SubmittedEvent {
    pub event: Event,
    pub notice_tx: tokio::sync::mpsc::Sender<Notice>,
    /// Capacity-1 signal owned by the WebSocket connection. A full notice
    /// channel asks that connection to close. `try_send` on this channel
    /// never waits. REST has no long-lived connection, so it leaves this
    /// empty and reports the missing answer on its own timeout.
    pub close_tx: Option<tokio::sync::mpsc::Sender<()>>,
    pub source_ip: String,
    pub origin: Option<String>,
    pub user_agent: Option<String>,
    pub auth_pubkey: Option<Vec<u8>>,
}

/// Database file
pub const DB_FILE: &str = "nostr.db";

/// Build repo
/// # Panics
///
/// Will panic if the pool could not be created.
pub async fn build_repo(settings: &Settings, metrics: NostrMetrics) -> Arc<dyn NostrRepo> {
    match settings.database.engine.as_str() {
        "sqlite" => Arc::new(build_sqlite_pool(settings, metrics).await),
        "postgres" => Arc::new(build_postgres_pool(settings, metrics).await),
        _ => panic!("Unknown database engine"),
    }
}

/// Why the node may be NOT READY, with an operator-facing explanation.
///
/// Global because `/v1/health` reads it here; threading state through the entire server
/// for one flag would add needless coupling. Set once at startup and read thereafter.
pub static NOT_READY: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Whether the node can serve traffic. `None` means ready; `Some(reason)` means not ready.
pub fn not_ready_reason() -> Option<&'static str> {
    NOT_READY.get().map(String::as_str)
}

async fn build_sqlite_pool(settings: &Settings, metrics: NostrMetrics) -> SqliteRepo {
    let repo = SqliteRepo::new(settings, metrics);
    // NEVER SWALLOW FAILURE. Both calls used `.ok()`, silently discarding startup or
    // migration errors and serving a database the node did not understand. Reproduced
    // on 2026-09-14: a build against a newer schema panicked during migration yet still
    // accepted an event that could be read back.
    //
    // Do not stop the process here because diagnostics must remain reachable. Store the
    // reason for `/v1/health` and disable event intake instead.
    if let Err(err) = repo.start().await {
        let reason = format!("storage failed to start: {err}");
        error!("NODE NOT READY: {reason}");
        let _ = NOT_READY.set(reason);
    } else if let Err(err) = repo.migrate_up().await {
        let reason = format!("schema migration failed: {err}");
        error!("NODE NOT READY: {reason}");
        let _ = NOT_READY.set(reason);
    }
    repo
}

async fn build_postgres_pool(settings: &Settings, metrics: NostrMetrics) -> PostgresRepo {
    let options: PgConnectOptions = settings.database.connection.as_str().parse().unwrap();
    // sqlx 0.7+: logging setters consume the value and return a new one.
    let options = options
        .log_statements(LevelFilter::Debug)
        .log_slow_statements(LevelFilter::Warn, Duration::from_secs(60));

    let pool: PostgresPool = PoolOptions::new()
        .max_connections(settings.database.max_conn)
        .min_connections(settings.database.min_conn)
        .idle_timeout(Duration::from_secs(60))
        .connect_with(options)
        .await
        .unwrap();

    let write_pool: PostgresPool = match &settings.database.connection_write {
        Some(cfg_write) => {
            let options_write: PgConnectOptions = cfg_write.as_str().parse().unwrap();
            let options_write = options_write
                .log_statements(LevelFilter::Debug)
                .log_slow_statements(LevelFilter::Warn, Duration::from_secs(60));

            PoolOptions::new()
                .max_connections(settings.database.max_conn)
                .min_connections(settings.database.min_conn)
                .idle_timeout(Duration::from_secs(60))
                .connect_with(options_write)
                .await
                .unwrap()
        }
        None => pool.clone(),
    };

    let repo = PostgresRepo::new(pool, write_pool, metrics);

    // Panic on migration failure
    let version = repo.migrate_up().await.unwrap();
    info!("Postgres migration completed, at v{}", version);
    // startup scheduled tasks
    repo.start().await.ok();
    repo
}

/// A cached, previously-computed A4A delegation verdict.
struct CachedA4aVerdict {
    /// Was the delegation valid?
    valid: bool,
    /// Why the verdict is negative; `None` for a positive one.
    reason: Option<&'static str>,
    /// Unix time after which this cache entry must no longer be trusted
    /// (the earlier of: `now + delegation_cache_ttl_secs` at the time it
    /// was computed, and the delegation event's own `expiration` tag).
    expires_at: u64,
    /// The same deadline on a MONOTONIC clock. Wall-clock `expires_at` prevents a verdict
    /// outliving the delegation's absolute expiration, while monotonic time prevents a
    /// backward system-clock jump from extending TTL (finding 70). The stricter wins.
    deadline: std::time::Instant,
}

/// TTL cache of validated A4A delegations, so the event-admission hot path
/// doesn't re-fetch and re-verify the referenced kind-10001 delegation
/// event on every single event a delegated agent publishes.
///
/// Keyed by `(delegation_event_id, agent_pubkey)`: the same delegation
/// event can only ever validate for the one agent pubkey it names in its
/// `delegate` tag, but keying on the pair (rather than just the delegation
/// id) keeps the cache correct even if that invariant is ever relaxed.
///
/// A cache HIT never re-runs any crypto — it just returns the previously
/// computed verdict, provided it hasn't expired. An entry's expiry is
/// capped at the delegation's own `expiration` tag, so the cache can never
/// hand out a "valid" verdict past the point the delegation itself expired
/// (see [`check_a4a_delegation`]).
/// Hard cap on the number of entries [`A4aCache`] may hold at once. Without
/// a cap, an attacker who publishes many events referencing distinct
/// `(delegation_id, pubkey)` pairs -- each only once -- would grow the
/// cache forever, since `get()` only *skips* expired entries on read and
/// never removes them. `insert()` sweeps expired entries once the map
/// exceeds this size, falling back to evicting arbitrary entries if the
/// sweep alone isn't enough (see [`A4aCache::evict_locked`]).
const MAX_A4A_CACHE_ENTRIES: usize = 100_000;

pub struct A4aCache {
    entries: Mutex<HashMap<(String, String), CachedA4aVerdict>>,
    max_entries: usize,
}

impl A4aCache {
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(MAX_A4A_CACHE_ENTRIES)
    }

    fn with_capacity(max_entries: usize) -> Self {
        A4aCache {
            entries: Mutex::new(HashMap::new()),
            max_entries,
        }
    }

    /// Test-only constructor with a small cap, so eviction tests don't need
    /// to churn through `MAX_A4A_CACHE_ENTRIES` real entries to exercise it.
    #[cfg(test)]
    fn with_capacity_for_test(max_entries: usize) -> Self {
        Self::with_capacity(max_entries)
    }

    /// Test-only accessor for the current number of cached entries.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.lock_entries().len()
    }

    /// Look up a cached, still-valid verdict for `(delegation_id, pubkey)`.
    /// Returns `None` on a miss OR on an expired entry (a lazily-expired
    /// entry is simply left in place; the next successful validation will
    /// overwrite it).
    #[cfg(test)]
    fn get(&self, delegation_id: &str, pubkey: &str) -> Option<bool> {
        self.get_verdict(delegation_id, pubkey).map(|(valid, _)| valid)
    }

    /// The cached verdict together with the reason it was negative, if any.
    /// The reason travels with the verdict so a cache HIT can still tell the
    /// client why -- without it every hit degraded to a reasonless refusal.
    fn get_verdict(&self, delegation_id: &str, pubkey: &str) -> Option<(bool, Option<&'static str>)> {
        let now = unix_time();
        let entries = self.lock_entries();
        let key = (delegation_id.to_owned(), pubkey.to_owned());
        let mono_now = std::time::Instant::now();
        entries
            .get(&key)
            .filter(|v| v.expires_at > now && mono_now < v.deadline)
            .map(|v| (v.valid, v.reason))
    }

    /// Cache a verdict for `(delegation_id, pubkey)`, valid until `expires_at`.
    /// If this insert pushes the map over `max_entries`, sweep out expired
    /// entries (and, as a backstop, arbitrary ones) to bring it back down.
    #[cfg(test)]
    fn insert(&self, delegation_id: &str, pubkey: &str, valid: bool, expires_at: u64) {
        self.insert_verdict(delegation_id, pubkey, valid, None, expires_at);
    }

    fn insert_verdict(
        &self,
        delegation_id: &str,
        pubkey: &str,
        valid: bool,
        reason: Option<&'static str>,
        expires_at: u64,
    ) {
        // Derive the monotonic deadline from wall time ONCE here. The clocks then diverge,
        // and moving wall time backward cannot affect the monotonic deadline.
        let ttl = std::time::Duration::from_secs(expires_at.saturating_sub(unix_time()));
        let deadline = std::time::Instant::now() + ttl;
        self.insert_full(delegation_id, pubkey, valid, reason, expires_at, deadline);
    }

    /// Test helper that accepts an explicit monotonic deadline.
    #[cfg(test)]
    fn insert_with_deadline(
        &self,
        delegation_id: &str,
        pubkey: &str,
        valid: bool,
        expires_at: u64,
        deadline: std::time::Instant,
    ) {
        self.insert_full(delegation_id, pubkey, valid, None, expires_at, deadline);
    }

    fn insert_full(
        &self,
        delegation_id: &str,
        pubkey: &str,
        valid: bool,
        reason: Option<&'static str>,
        expires_at: u64,
        deadline: std::time::Instant,
    ) {
        let mut entries = self.lock_entries();
        entries.insert(
            (delegation_id.to_owned(), pubkey.to_owned()),
            CachedA4aVerdict {
                valid,
                reason,
                expires_at,
                deadline,
            },
        );
        if entries.len() > self.max_entries {
            Self::evict_locked(&mut entries, self.max_entries);
        }
    }

    /// Bring `entries` back under `max_entries`. First sweeps out every
    /// entry that has already expired (the expected, common case -- every
    /// entry carries a TTL-bounded `expires_at`). If that alone isn't
    /// sufficient (e.g. a burst of still-valid, not-yet-expired entries),
    /// falls back to draining arbitrary entries until the cap is met; a
    /// plain `HashMap` has no access-order to evict "the oldest" by, and at
    /// 100k entries this is meant purely as a hard backstop against
    /// unbounded growth, not a precise LRU.
    fn evict_locked(entries: &mut HashMap<(String, String), CachedA4aVerdict>, max_entries: usize) {
        let now = unix_time();
        entries.retain(|_, v| v.expires_at > now);
        if entries.len() > max_entries {
            let excess = entries.len() - max_entries;
            let keys_to_remove: Vec<(String, String)> =
                entries.keys().take(excess).cloned().collect();
            for k in keys_to_remove {
                entries.remove(&k);
            }
        }
    }

    /// Remove all cached verdicts for `delegation_id` (across every agent
    /// pubkey). Called when a revocation for that delegation is admitted,
    /// so a stale "valid" verdict cached before the revocation cannot
    /// outlive it.
    /// Cache keys are lower-cased delegation ids (see
    /// `Event::a4a_delegation_ref`), so the id read off the revocation's `e`
    /// tag is lower-cased here too -- an upper-case `e` tag would otherwise
    /// match nothing and leave the stale "valid" verdict in place.
    pub fn invalidate_delegation(&self, delegation_id: &str) {
        let delegation_id = delegation_id.to_lowercase();
        let mut entries = self.lock_entries();
        entries.retain(|(d, _pubkey), _| *d != delegation_id);
    }

    /// Drop cached verdicts for several delegations in ONE pass over the map.
    /// A pass per id would multiply the cost finding 4 was about by the number
    /// of ids a single event can name.
    pub fn invalidate_delegations(&self, delegation_ids: &[String]) {
        let wanted: Vec<String> = delegation_ids.iter().map(|d| d.to_lowercase()).collect();
        let mut entries = self.lock_entries();
        entries.retain(|(d, _pubkey), _| !wanted.contains(d));
    }

    /// Drop every cached verdict for AGENT `delegate_pubkey`, whichever
    /// delegation each entry was keyed by.
    ///
    /// A revocation now names the agent rather than one copy of a delegation, and
    /// the cache is keyed by (delegation id, agent). Evicting by delegation id
    /// would leave verdicts cached against earlier copies alive -- exactly the
    /// gap the revocation change closes.
    pub fn invalidate_agent(&self, delegate_pubkey: &str) {
        let delegate = delegate_pubkey.to_lowercase();
        let mut entries = self.lock_entries();
        entries.retain(|(_d, pubkey), _| *pubkey != delegate);
    }

    /// Forget every cached allow.
    ///
    /// Used when a revocation was stored but the ownership read failed. Leaving
    /// the previous "valid" entries in place would keep authorizing the agent.
    /// Dropping one named agent instead would trust the revocation's `d` tag
    /// without a successful read, which is the eviction attack this cache
    /// refuses. Denies stay: they are the safe direction.
    fn drop_allows(&self) {
        let mut entries = self.lock_entries();
        entries.retain(|_, verdict| !verdict.valid);
    }

    /// Recover a poisoned mutex instead of skipping the update.
    ///
    /// `lock().ok()` treated poison as "nothing to do". Invalidation then
    /// left a cached allow in the map. The next reader that recovered the
    /// guard would serve it. Poison means a writer panicked mid-update, so
    /// the map is cleared before use: a miss rechecks the database.
    fn lock_entries(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<(String, String), CachedA4aVerdict>> {
        match self.entries.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!(
                    "A4A delegation cache mutex poisoned; dropping cached verdicts so a stale allow cannot survive"
                );
                let mut guard = poisoned.into_inner();
                guard.clear();
                guard
            }
        }
    }
}

impl Default for A4aCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Default number of delegation-lookup cache MISSES allowed per second when
/// `Settings.a4a.delegation_lookup_rate_per_sec` is `0`.
///
/// The previous default was 50/s, picked by eye. Measured (29.08.2026, release
/// build, `measure_delegation_miss_cost`): the expensive path -- DB fetch plus
/// Schnorr verification plus a revocation lookup -- runs at ~9 000/s, and the
/// path a flood actually takes (a delegation id that does not exist, so no
/// crypto at all) at ~28 000/s. A single event WRITE costs ~0.7 ms, i.e. more
/// than six times a miss, and a flood of bad-delegation events is rejected
/// before any write -- so it is cheaper for the relay than ordinary traffic.
///
/// At 50/s the limiter was therefore not protecting the write loop from a real
/// cost; it was itself the cheapest denial of service on the relay. 51 events
/// per second -- under one connection's `messages_per_sec` -- exhausted the
/// window, after which every cache MISS was refused, including the first event
/// of an honest agent that had just registered. The default is now a fifth of
/// measured capacity: still a hard ceiling on worst-case work, but far above
/// anything legitimate traffic produces.
pub const DEFAULT_DELEGATION_LOOKUP_RATE_PER_SEC: u32 = 2_000;

/// Number of independent budget shards. Fixed and small: sharding by author
/// gives fairness without a per-pubkey map, which would itself be floodable
/// state needing eviction.
const LOOKUP_SHARDS: usize = 16;

/// Bounds the rate of A4A delegation-lookup cache MISSES -- i.e. calls that
/// fall through to `repo.get_event_by_id` plus a full Schnorr verification
/// in [`check_a4a_delegation`] -- admitted per second, across the whole
/// relay process.
///
/// Cache HITS are cheap (no DB round trip, no crypto) and never pass
/// through this limiter -- only misses that would otherwise hit the repo
/// are counted/limited. Without this, an attacker flooding the relay with
/// events each referencing a unique, never-cached delegation id
/// (nonexistent or invalid) would force a DB round-trip + Schnorr
/// verification for every single event, degrading write throughput for
/// ALL clients -- `db_writer` is the relay's single-threaded write loop.
///
/// Implemented as a fixed-window counter keyed off `std::time::Instant`
/// (monotonic -- immune to wall-clock adjustments/NTP jumps, unlike
/// `unix_time()` which is used elsewhere for cache TTLs). `db_writer`
/// processes events from its channel strictly one at a time, so a plain
/// counter is all that's needed; it's still guarded by a `Mutex` (matching
/// [`A4aCache`]'s interior-mutability style) so it can be held by shared
/// reference alongside the cache rather than threaded through as `&mut`.
pub struct LookupRateLimiter {
    /// Per-shard budget, not the total: the whole-relay ceiling is this
    /// times [`LOOKUP_SHARDS`].
    limit_per_sec: u32,
    shards: Vec<Mutex<LookupWindow>>,
}

struct LookupWindow {
    window_start: Instant,
    count_in_window: u32,
}

impl LookupRateLimiter {
    /// `limit_per_sec == 0` falls back to
    /// [`DEFAULT_DELEGATION_LOOKUP_RATE_PER_SEC`] rather than meaning
    /// "unlimited" or "always blocked" -- both of which would be a silent
    /// foot-gun for an operator who leaves the config field at its zero
    /// value by mistake.
    #[must_use]
    pub fn new(limit_per_sec: u32) -> Self {
        let limit_per_sec = if limit_per_sec == 0 {
            DEFAULT_DELEGATION_LOOKUP_RATE_PER_SEC
        } else {
            limit_per_sec
        };
        let now = Instant::now();
        LookupRateLimiter {
            // Divide, do not multiply: the configured number stays the
            // relay-wide ceiling an operator asked for.
            limit_per_sec: (limit_per_sec as usize).div_ceil(LOOKUP_SHARDS) as u32,
            shards: (0..LOOKUP_SHARDS)
                .map(|_| {
                    Mutex::new(LookupWindow {
                        window_start: now,
                        count_in_window: 0,
                    })
                })
                .collect(),
        }
    }

    /// Which budget `pubkey` draws from. Author-keyed, so a flood from one key
    /// can only starve the agents that share its shard instead of the whole
    /// relay. Residual risk, stated plainly: an attacker who wants to starve a
    /// CHOSEN victim can grind keys into the victim's shard, and collateral is
    /// still 1/16 of agents. Sharding raises the cost of a broad attack; it does
    /// not make a targeted one impossible.
    fn shard_of(&self, pubkey: &str) -> &Mutex<LookupWindow> {
        let byte = pubkey
            .as_bytes()
            .first()
            .copied()
            .unwrap_or(0)
            .wrapping_add(pubkey.as_bytes().get(1).copied().unwrap_or(0));
        &self.shards[byte as usize % LOOKUP_SHARDS]
    }

    /// Returns `true` if a lookup may proceed right now (and counts it
    /// against the current window's budget), `false` if the current
    /// one-second window's budget is already exhausted.
    pub fn allow(&self, pubkey: &str) -> bool {
        let Ok(mut state) = self.shard_of(pubkey).lock() else {
            // poisoned: fail open rather than wedge db_writer forever.
            return true;
        };
        let now = Instant::now();
        if now.duration_since(state.window_start) >= Duration::from_secs(1) {
            state.window_start = now;
            state.count_in_window = 0;
        }
        if state.count_in_window >= self.limit_per_sec {
            return false;
        }
        state.count_in_window += 1;
        true
    }
}

/// Decide whether `event` is admitted per A4A delegation rules.
///
/// Returns `Ok(())` to admit the event unchanged, `Err(reason)` to block
/// it (mirroring the rejection pattern already used for nauthz/gRPC and
/// the other admission checks in [`db_writer`]).
///
/// Logic:
/// 1. If A4A checking is disabled (`settings.a4a.enabled == false`), always
///    admit — this is the stock, pre-A4A relay behavior.
/// 2. If the event carries no `["delegation", id]` tag AND its kind is not
///    in `required_for_kinds`, it is not an A4A-governed event (e.g. the
///    kind-10001 delegation events themselves have no delegation tag) —
///    admit.
/// 3. If the kind IS in `required_for_kinds` but the event has no
///    delegation tag, reject: a delegation is mandatory for this kind.
/// 4. Otherwise, resolve the referenced delegation (cache first, then a
///    repo fetch + [`validate_a4a_delegation`] on a miss), caching the
///    result. Reject if the delegation is missing or invalid/expired.
///    A cache MISS is first checked against `limiter`: if the per-second
///    lookup budget is exhausted, the event is rejected right there
///    (before the repo fetch / crypto ever runs) to protect `db_writer`
///    from a cold-cache flood (see [`LookupRateLimiter`]).
///
/// Reason for rejecting another notary's timestamp. Keep it on one source line because
/// line continuation previously leaked a run of spaces into the wire response.
const NOTARY_ONLY_REJECTION: &str =
    "kind 1040 is accepted only from this relay's declared notary (NIP-11 a4a.notary) and its retired keys";

pub async fn check_a4a_delegation(
    repo: &Arc<dyn NostrRepo>,
    cache: &A4aCache,
    limiter: &LookupRateLimiter,
    event: &Event,
    settings: &Settings,
) -> std::result::Result<(), String> {
    if !settings.a4a.enabled {
        return Ok(());
    }

    // Accept kind-1040 timestamps ONLY from the declared notary and retired keys. This is
    // about storage, not trust: readers reject forged proofs themselves. Kind 1040 is in
    // PROTECTED_KINDS, so age retention, per-author ceilings, and the size budget never
    // delete it (`kind NOT IN (protected)`). An attacker could use a fresh key per event
    // to fill disk with undeletable data at zero cost. Readers accept only NIP-11 notary
    // keys (§2.9), so foreign timestamps are useless to everyone (finding 122).
    if event.kind == crate::a4a_delegation::A4A_KIND_TIMESTAMP {
        let current = settings.a4a.notary_pubkey.as_deref();
        let allowed = current == Some(event.pubkey.as_str())
            || settings
                .a4a
                .notary_retired
                .iter()
                .any(|r| r.pubkey == event.pubkey);
        // A node with NO declared notary accepts any timestamp but treats it as disposable:
        // protected_kinds() excludes 1040, so age, per-author, and size limits apply.
        // This keeps the Docker Compose setup useful for end-to-end experimentation
        // without risking disk exhaustion (independent review follow-up to finding 122).
        if current.is_some() && !allowed {
            return Err(NOTARY_ONLY_REJECTION.to_owned());
        }
        return Ok(());
    }

    // A revocation is the one A4A event whose own shape the relay must police:
    // everything downstream trusts that its `d` and `e` tags name the same
    // delegation (see `revocation_target`). Cheap, tag-only, no lookup.
    if event.kind == crate::a4a_delegation::A4A_KIND_REVOCATION {
        let Some(delegate) = crate::a4a_delegation::revocation_target(event) else {
            // Derive the reason from the same function that decides. Text and behavior
            // previously diverged, naming an `a` tag the event did not contain.
            return Err(crate::a4a_delegation::revocation_shape_rejection(event)
                .unwrap_or("A4A revocation is malformed")
                .to_owned());
        };
        // The next two checks close ONE scenario that used to be unguarded: an owner
        // revokes an agent, receives OK=true, believes the action complete, but the
        // revocation has no effect. Silent fail-open with a false acknowledgement is the
        // worst failure mode because nobody knows it happened (audit, 2026-09-04).
        //
        // Cost: up to two database reads per kind-31007 event. Revocations are rare
        // owner actions, normally once per agent, so this is acceptable; the same limiter
        // used for delegation checks bounds the path.
        if !limiter.allow(&event.pubkey) {
            return Err("A4A revocation check rate limited, retry later".to_owned());
        }

        // (1) Legacy format: `d` names the delegation EVENT rather than the delegate.
        // Before F6, revocations were keyed by delegation id, even in this module's docs.
        // A delegation id has the same 64-hex shape as a pubkey, so shape validation
        // accepted it while `get_a4a_revocation` by delegate pubkey never found it.
        //
        // (1a) Detect by shape first, without a database read. A legacy revocation used
        // the SAME delegation id in `d` and `e`. In the new model `d` is the agent key
        // and `e` is a delegation copy, so they cannot match. This also catches the format
        // when the relay never saw the delegation or NIP-33 replacement deleted the old
        // copy, exactly the two gaps an independent run found in check (1b).
        if event
            .tag_values_by_name("e")
            .iter()
            .any(|e| e.eq_ignore_ascii_case(&delegate))
        {
            return Err(
                "A4A revocation tag d must name the delegate pubkey, not the \
                 delegation event id"
                    .to_owned(),
            );
        }
        // (1b) A legacy revocation without `e` is distinguishable only through data: if
        // `d` names a kind-31000 event from THIS SAME owner, it is an id, not a key.
        match repo.get_event_by_id(&delegate).await {
            Ok(Some(ev))
                if ev.kind == crate::a4a_delegation::A4A_KIND_DELEGATION
                    && ev.pubkey == event.pubkey =>
            {
                return Err(
                    "A4A revocation tag d must name the delegate pubkey, not the \
                     delegation event id"
                        .to_owned(),
                );
            }
            Ok(_) => {}
            // A read error is not "this is a new-format revocation". Accepting it
            // stores a legacy revocation the owner thinks succeeded (OK) while the
            // agent keeps publishing. Refuse this attempt; the client retries.
            Err(e) => {
                warn!("could not check revocation format: {:?}", e);
                return Err(
                    "could not check revocation format: database read failed, retry"
                        .to_owned(),
                );
            }
        }

        // (2) Dead revocation: the delegation exists, but this event does not revoke it.
        // Usually this is clock skew. `validate_a4a_revocation` requires
        // `revocation.created_at >= delegation.created_at`, otherwise an owner who
        // revoked and rehired an agent could never issue a working mandate. If the
        // delegation came from a fast clock and the revocation from a correct one, the
        // revocation is dead FOREVER, not merely for a cache TTL.
        //
        // If the delegation is absent, accept: a revocation may reach a relay that has
        // not seen it yet. Rejecting would break cross-relay revocation distribution,
        // the behavior required to close finding 50.
        match repo
            .get_a4a_addressable(
                crate::a4a_delegation::A4A_KIND_DELEGATION,
                &delegate,
                &event.pubkey,
            )
            .await
        {
            Ok(Some(deleg)) if !validate_a4a_revocation(event, &deleg) => {
                // Do not blame every failure on clocks. `validate_a4a_revocation` also
                // rejects delegations without `delegate`, which is not clock skew. An
                // independent run showed the old wording was false in that case.
                return Err(
                    "A4A revocation would not revoke the delegation it names: it is \
                     dated earlier than the delegation (clock skew?), or the \
                     delegation itself is malformed"
                        .to_owned(),
                );
            }
            Ok(_) => {}
            // Absent delegation stays Ok: a revocation may arrive before the
            // delegation (cross-relay). A failed read is different. Accepting
            // it can store a dead revocation and tell the owner the agent stopped.
            Err(e) => {
                warn!("could not verify revocation against delegation: {:?}", e);
                return Err(
                    "could not verify revocation against delegation: database read failed, retry"
                        .to_owned(),
                );
            }
        }
    }

    let required = settings
        .a4a
        .required_for_kinds
        .as_ref()
        .is_some_and(|kinds| kinds.contains(&event.kind));

    let Some(delegation_id) = event.a4a_delegation_ref() else {
        return if required {
            Err("A4A delegation required for this kind".to_owned())
        } else {
            Ok(())
        };
    };

    // cache hit: reuse the previously computed verdict, no crypto re-run.
    if let Some((valid, reason)) = cache.get_verdict(&delegation_id, &event.pubkey) {
        return if valid {
            Ok(())
        } else {
            // Preserve this prefix literally: the SDK (`relay.py`) searches for it to
            // provide user guidance (finding 28). Append the specific reason.
            Err(format!(
                "invalid or expired A4A delegation: {}",
                reason.unwrap_or("rejected earlier, verdict cached")
            ))
        };
    }

    // cache miss: this is the expensive path a cold-cache flood targets
    // (DB round trip + Schnorr verification below) -- rate-limit it before
    // doing any of that work.
    if !limiter.allow(&event.pubkey) {
        return Err("A4A delegation check rate limited, retry later".to_owned());
    }

    // cache miss: fetch the referenced delegation event and validate it.
    let deleg = repo
        .get_event_by_id(&delegation_id)
        .await
        .map_err(|e| format!("error looking up A4A delegation: {e:?}"))?;

    let Some(deleg) = deleg else {
        return Err("referenced A4A delegation not found".to_owned());
    };

    let mut reason = delegation_rejection(event, &deleg);
    // A structurally valid, unexpired delegation can still have been
    // revoked by its owner: check for a matching revocation before
    // trusting the verdict (and before caching it).
    if reason.is_none() {
        // Find revocation by AGENT, not delegation copy. Reissuing changes event id, so
        // id-bound revocation left every earlier copy valid (relay audit F6). The target
        // comes from the signed delegation and cannot be forged without forging the owner.
        // Use the SAME function that just validated it: rule 8 guarantees `Some` and
        // equality of `d` and `delegate`. Reading a tag directly would be equivalent today
        // but drift after the next change. Finding 54 arose exactly because two tags that
        // had to agree were read through different paths.
        let delegate = crate::a4a_delegation::delegation_target(&deleg).unwrap_or_default();
        match repo.get_a4a_revocation(&delegate, &deleg.pubkey).await {
            Ok(Some(rev)) if validate_a4a_revocation(&rev, &deleg) => {
                reason = Some("delegation revoked by its owner");
            }
            Ok(_) => {}
            Err(e) => return Err(format!("error looking up A4A revocation: {e:?}")),
        }
    }
    let valid = reason.is_none();

    let now = unix_time();
    let ttl_expiry = now.saturating_add(settings.a4a.delegation_cache_ttl_secs);
    // never cache a "valid" verdict past the delegation's own expiration.
    let expires_at = match deleg.expiration() {
        Some(exp) => ttl_expiry.min(exp),
        None => ttl_expiry,
    };
    cache.insert_verdict(&delegation_id, &event.pubkey, valid, reason, expires_at);

    if valid {
        Ok(())
    } else {
        Err(format!(
            "invalid or expired A4A delegation: {}",
            reason.unwrap_or("rejected")
        ))
    }
}

/// Evict cached verdicts for the delegation a newly-admitted revocation names --
/// but only if that revocation actually comes from the delegation's owner.
///
/// The bust used to fire on any admitted kind 31007. Delegation ids are public
/// (they travel in plain text in every event an agent publishes), so a stranger
/// could evict a chosen victim's verdict at will: each of the victim's events
/// then took the slow path, spent the shared lookup budget and eventually got
/// rejected, while every eviction walked a map of up to `MAX_A4A_CACHE_ENTRIES`
/// inside the single-threaded writer.
///
/// A revocation naming a delegation this relay has never seen is not an attack
/// and not an error: there is nothing cached to evict, so it is simply a no-op.
///
/// This lookup itself is not rate-limited, but since 04.09.2026 the admission
/// path (`check_a4a_delegation`) already charges the SENDER's lookup allowance
/// for every kind 31007 before it gets here. A revocation flood therefore
/// exhausts the flooder's own budget, not a victim's -- the limiter is keyed by
/// the publishing pubkey -- so the lever this function removed stays removed.
async fn maybe_invalidate_for_revocation(repo: &Arc<dyn NostrRepo>, cache: &A4aCache, event: &Event) {
    let Some(delegate) = crate::a4a_delegation::revocation_target(event) else {
        return;
    };
    // Ownership is checked against a delegation THIS RELAY holds, looked up by the
    // same coordinate the revocation names. The informational `e` tag would have been
    // the obvious thing to follow, and it is wrong here: it points at whichever copy
    // the owner had in hand, and in the very scenario this fix exists for the relay
    // never saw that copy. Following `e` meant the cache kept serving a stale "valid"
    // verdict for the whole TTL while the owner believed the agent was revoked
    // (caught by live run, not by unit tests).
    match repo
        .get_a4a_addressable(
            crate::a4a_delegation::A4A_KIND_DELEGATION,
            &delegate,
            &event.pubkey,
        )
        .await
    {
        Ok(Some(_)) => cache.invalidate_agent(&delegate),
        // Nothing cached for a delegation this relay has never stored.
        Ok(None) => {}
        // The revocation is already stored. Keeping cached allows would
        // authorize the agent until TTL while the owner sees OK. Drop every
        // allow. Do not evict by the unverified `d` tag: that is the
        // stranger-eviction attack, aimed at one agent.
        Err(e) => {
            warn!(
                "could not verify revocation ownership, dropping cached allows: {:?}",
                e
            );
            cache.drop_allows();
        }
    }
}

/// Cap on `e` tags looked up when a deletion arrives.
///
/// The history of this number shows how comments can lie. On 2026-09-04, a cap of 8 was
/// REMOVED on the claim that writing kind 5 already did one update per tag and was O(N).
/// That was false: writing performs ONE `UPDATE ... IN (...)` for all ids, while each
/// lookup here is a separate `spawn_blocking` query. Measurements: 1,800 unique ids made
/// eviction planning take 102 ms versus 0.43 ms at cap 8, four times the write cost;
/// 12,000 short junk tags such as `["e","x1"]`, filtered by writing but not planning,
/// took 626 ms. Kind 5 requires no mandate, so anyone can send it. At
/// `messages_per_sec = 100`, one second of intake creates tens of seconds of work for
/// the single writer. Removing the cap introduced amplification.
///
/// Why the cap needed adjustment: a delegation in the ninth `e` tag was deleted from
/// storage but not evicted from cache, letting the agent publish for the remaining TTL
/// (five minutes in production). That recreated finding 1 through tag order.
///
/// Resolution: cap at 64 instead of 8, AFTER filtering junk and duplicates. Real
/// deletions name one or two events; 64 provides ample headroom while bounding worst-case
/// cost at 64 reads (about 4 ms in review measurements). A deletion with more targets is
/// rejected rather than partly inspected: accepting it would let target 65 hide a
/// delegation without evicting its cached verdict.
const MAX_DELETION_TARGETS_CHECKED: usize = 64;

/// Delegation ids whose cached verdicts a pending deletion should invalidate.
///
/// Deleting the delegation is a legitimate way for an owner to stop an agent:
/// the event is hidden and every later lookup returns "not found". But the cache
/// bust only ever fired on a revocation, so a verdict cached before the deletion
/// kept the agent publishing for the whole TTL — five minutes in production, and
/// when the deletion answers a compromised key those are exactly the minutes
/// that matter.
///
/// Runs BEFORE the write on purpose: afterwards the delegation is hidden, and
/// the very lookup needed to prove the deleter owns it would come back empty.
/// Checking ownership is what keeps this from becoming the lever finding 4 was
/// about — deletion ids are public, and a `retain` over a map of up to
/// [`MAX_A4A_CACHE_ENTRIES`] entries is not something a stranger should be able
/// to trigger.
async fn plan_cache_eviction_for_deletion(
    repo: &Arc<dyn NostrRepo>,
    event: &Event,
) -> std::result::Result<Vec<String>, String> {
    let mut ids = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for target in event.tag_values_by_name("e").iter() {
        // Match `write_event` filtering: storage ignores anything that does not look like
        // an id, so planning need not query it. Without this filter, short junk tags were
        // the cheapest way to multiply reads.
        if !(crate::utils::is_hex(target) && target.len() == 64) {
            continue;
        }
        let target = target.to_lowercase();
        if !seen.insert(target.clone()) {
            continue;
        }
        if seen.len() > MAX_DELETION_TARGETS_CHECKED {
            return Err(format!(
                "deletion names more than {MAX_DELETION_TARGETS_CHECKED} unique event ids"
            ));
        }
        match repo.get_event_by_id(&target).await {
            Ok(Some(ev))
                if ev.kind == crate::a4a_delegation::A4A_KIND_REVOCATION
                    && ev.pubkey == event.pubkey =>
            {
                return Err(
                    "A4A revocations cannot be deleted; publish a newer delegation to reauthorize the agent"
                        .to_owned(),
                );
            }
            Ok(Some(ev))
                if ev.kind == crate::a4a_delegation::A4A_KIND_DELEGATION
                    && ev.pubkey == event.pubkey =>
            {
                ids.push(target);
            }
            Ok(_) => {}
            Err(e) => {
                warn!("could not inspect deletion target: {:?}", e);
                return Err("could not inspect every deletion target; deletion refused".to_owned());
            }
        }
    }
    Ok(ids)
}

/// Apply a plan from [`plan_cache_eviction_for_deletion`] in a single pass.
fn apply_cache_eviction(cache: &A4aCache, delegation_ids: &[String]) {
    if !delegation_ids.is_empty() {
        cache.invalidate_delegations(delegation_ids);
    }
}

/// Translate the optional external admission service into a fail-closed decision.
///
/// Configuring `grpc.event_admission_server` declares that its answer is part of the
/// write policy. Treating a timeout or disconnected service as permission silently
/// removes that policy at exactly the moment operators are least able to observe it.
fn nauthz_rejection(
    result: crate::error::Result<Box<dyn nauthz::AuthzDecision>>,
) -> Option<String> {
    match result {
        Ok(decision) if decision.permitted() => None,
        Ok(decision) => Some(
            decision
                .message()
                .filter(|message| !message.trim().is_empty())
                .unwrap_or_else(|| "event rejected by authorization service".to_owned()),
        ),
        Err(error) => {
            warn!("GRPC authorization service error: {:?}", error);
            Some("authorization service unavailable; event refused".to_owned())
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum NoticeDelivery {
    Delivered,
    ClientGone,
    NotDelivered,
}

/// Deliver the writer's decision without waiting.
///
/// `db_writer` is the relay's only write loop. A client that stops reading
/// fills its notice channel (128 slots) while its socket write sits in
/// `WRITE_TIMEOUT` (30s). Waiting here, even for two seconds, lets that one
/// client stall every publish. A full channel is a fact about the client:
/// the decision was not delivered, and the connection is asked to close.
/// The close signal is capacity 1, so this returns immediately either way.
/// A closed notice channel means the client is already gone.
fn deliver_notice(
    tx: &tokio::sync::mpsc::Sender<Notice>,
    close_tx: Option<&tokio::sync::mpsc::Sender<()>>,
    notice: Notice,
) -> NoticeDelivery {
    use tokio::sync::mpsc::error::TrySendError;
    match tx.try_send(notice) {
        Ok(()) => NoticeDelivery::Delivered,
        Err(TrySendError::Closed(_)) => {
            debug!("client disconnected before the relay could deliver its decision");
            NoticeDelivery::ClientGone
        }
        Err(TrySendError::Full(_)) => {
            warn!("client notice channel is full; decision not delivered, closing the connection");
            if let Some(close_tx) = close_tx {
                let _ = close_tx.try_send(());
            }
            NoticeDelivery::NotDelivered
        }
    }
}

/// Spawn a database writer that persists events to the `SQLite` store.
pub async fn db_writer(
    repo: Arc<dyn NostrRepo>,
    settings: Settings,
    mut event_rx: tokio::sync::mpsc::Receiver<SubmittedEvent>,
    bcast_tx: tokio::sync::broadcast::Sender<Event>,
    metadata_tx: tokio::sync::broadcast::Sender<Event>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) -> Result<()> {
    // are we performing NIP-05 checking?
    let nip05_active = settings.verified_users.is_active();
    // are we requriing NIP-05 user verification?
    let nip05_enabled = settings.verified_users.is_enabled();


    //upgrade_db(&mut pool.get()?)?;

    // Make a copy of the whitelist
    let whitelist = &settings.authorization.pubkey_whitelist.clone();

    // get rate limit settings
    let rps_setting = settings.limits.messages_per_sec;
    let mut most_recent_rate_limit = Instant::now();
    let mut lim_opt = None;
    let clock = governor::clock::QuantaClock::default();
    if let Some(rps) = rps_setting {
        if rps > 0 {
            info!("Enabling rate limits for event creation ({}/sec)", rps);
            let quota = core::num::NonZeroU32::new(rps * 60).unwrap();
            lim_opt = Some(RateLimiter::direct(Quota::per_minute(quota)));
        }
    }
    // create a client if GRPC is enabled.
    // Check with externalized event admitter service, if one is defined.
    let mut grpc_client = if let Some(svr) = settings.grpc.event_admission_server.clone() {
        Some(nauthz::EventAuthzService::connect(&svr).await)
    } else {
        None
    };

    //let gprc_client = settings.grpc.event_admission_server.map(|s| {
    //        event_admitter_connect(&s);
    //    });

    // TTL cache of validated A4A delegations, constructed once for the
    // lifetime of this database-writer task (see `check_a4a_delegation`).
    let a4a_cache = A4aCache::new();
    // Rate limiter over delegation-lookup cache MISSES, guarding db_writer
    // against a cold-cache flood (see `LookupRateLimiter`, hardening
    // backlog item 2). Constructed once, alongside `a4a_cache`.
    let a4a_lookup_limiter = LookupRateLimiter::new(settings.a4a.delegation_lookup_rate_per_sec);

    loop {
        if shutdown.try_recv().is_ok() {
            info!("shutting down database writer");
            break;
        }
        // call blocking read on channel
        let next_event = event_rx.recv().await;
        // if the channel has closed, we will never get work
        if next_event.is_none() {
            break;
        }
        // track if an event write occurred; this is used to
        // update the rate limiter
        let mut event_write = false;
        let subm_event = next_event.unwrap();
        let event = subm_event.event;
        let notice_tx = subm_event.notice_tx;
        let close_tx = subm_event.close_tx;

        // Startup failure sets NOT_READY. Health reports it. This is the
        // write path those checks were supposed to close: without it, EVENT
        // and /v1/publish still persisted into a database the node does not
        // understand. WebSocket and REST also refuse before queueing.
        if let Some(reason) = not_ready_reason() {
            deliver_notice(&notice_tx, close_tx.as_ref(), Notice::error(event.id, reason));
            continue;
        }

        // Check that event kind isn't blacklisted
        let kinds_blacklist = &settings.limits.event_kind_blacklist.clone();
        if let Some(event_kind_blacklist) = kinds_blacklist {
            if event_kind_blacklist.contains(&event.kind) {
                debug!(
                    "rejecting event: {}, blacklisted kind: {}",
                    &event.get_event_id_prefix(),
                    &event.kind
                );
                deliver_notice(
                    &notice_tx,
                    close_tx.as_ref(),
                    Notice::blocked(event.id, "event kind is blocked by relay"),
                );
                continue;
            }
        }

        // Check that event kind isn't allowlisted
        let kinds_allowlist = &settings.limits.event_kind_allowlist.clone();
        if let Some(event_kind_allowlist) = kinds_allowlist {
            if !event_kind_allowlist.contains(&event.kind) {
                debug!(
                    "rejecting event: {}, allowlist kind: {}",
                    &event.get_event_id_prefix(),
                    &event.kind
                );
                deliver_notice(
                    &notice_tx,
                    close_tx.as_ref(),
                    Notice::blocked(event.id, "event kind is blocked by relay"),
                );
                continue;
            }
        }

        // Publication authorization through a key allowlist. The paid-relay subsystem was
        // removed on 2026-08-28 (docs/design/2026-08-28-relay-network-strategy.md), so
        // paid/free branching is gone and only the direct list remains.
        if let Some(allowed_addrs) = whitelist {
            // Known limitation: the author whitelist matches the event signer, not a
            // delegation owner. Deployments using this optional whitelist must list
            // every delegate that is allowed to publish.
            if !allowed_addrs.contains(&event.pubkey) {
                debug!(
                    "rejecting event: {}, unauthorized author",
                    event.get_event_id_prefix()
                );
                deliver_notice(
                    &notice_tx,
                    close_tx.as_ref(),
                    Notice::blocked(
                        event.id,
                        "pubkey is not allowed to publish to this relay",
                    ),
                );
                continue;
            }
        }

        // get a validation result for use in verification and GPRC
        let validation = if nip05_active {
            Some(repo.get_latest_user_verification(&event.pubkey).await)
        } else {
            None
        };

        // check for  NIP-05 verification
        if let (true, Some(validation)) = (nip05_enabled, validation.as_ref()) {
            match validation {
                Ok(uv) => {
                    if uv.is_valid(&settings.verified_users) {
                        info!(
                            "new event from verified author ({:?},{:?})",
                            uv.name.to_string(),
                            event.get_author_prefix()
                        );
                    } else {
                        info!(
                            "rejecting event, author ({:?} / {:?}) verification invalid (expired/wrong domain)",
                            uv.name.to_string(),
                            event.get_author_prefix()
                        );
                        deliver_notice(
                            &notice_tx,
                            close_tx.as_ref(),
                            Notice::blocked(
                                event.id,
                                "NIP-05 verification is no longer valid (expired/wrong domain)",
                            ),
                        );
                        continue;
                    }
                }
                Err(
                    Error::SqlError(rusqlite::Error::QueryReturnedNoRows)
                    | Error::SqlxError(sqlx::Error::RowNotFound),
                ) => {
                    debug!(
                        "no verification records found for pubkey: {:?}",
                        event.get_author_prefix()
                    );
                    deliver_notice(
                        &notice_tx,
                        close_tx.as_ref(),
                        Notice::blocked(
                            event.id,
                            "NIP-05 verification needed to publish events",
                        ),
                    );
                    continue;
                }
                Err(e) => {
                    // Not "unverified" and not "verified". The client used to
                    // wait until its own timeout because this arm sent nothing.
                    warn!("checking nip05 verification status failed: {:?}", e);
                    deliver_notice(
                        &notice_tx,
                        close_tx.as_ref(),
                        Notice::error(
                            event.id.clone(),
                            "could not read NIP-05 verification; retry",
                        ),
                    );
                    continue;
                }
            }
        }

        // nip05 address
        let nip05_address: Option<crate::nip05::Nip05Name> =
            validation.and_then(|x| x.ok().map(|y| y.name));

        // GRPC check
        if let Some(ref mut c) = grpc_client {
            trace!("checking if grpc permits");
            let grpc_start = Instant::now();
            let decision_res = c
                .admit_event(
                    &event,
                    &subm_event.source_ip,
                    subm_event.origin,
                    subm_event.user_agent,
                    nip05_address,
                    subm_event.auth_pubkey,
                )
                .await;
            if let Some(reason) = nauthz_rejection(decision_res) {
                info!(
                    "GRPC refused event: {:?} (kind: {}) from: {:?} in: {:?} (IP: {:?})",
                    event.get_event_id_prefix(),
                    event.kind,
                    event.get_author_prefix(),
                    grpc_start.elapsed(),
                    subm_event.source_ip
                );
                deliver_notice(&notice_tx, close_tx.as_ref(), Notice::blocked(event.id, &reason));
                continue;
            }
        }

        // A4A delegation check: block events that require, but lack, a
        // valid delegation chain (see `check_a4a_delegation` docs). Runs
        // after nauthz/GRPC and before the event is persisted.
        if let Err(reason) =
            check_a4a_delegation(&repo, &a4a_cache, &a4a_lookup_limiter, &event, &settings).await
        {
            debug!(
                "rejecting event: {}, A4A delegation check failed: {}",
                event.get_event_id_prefix(),
                reason
            );
            deliver_notice(&notice_tx, close_tx.as_ref(), Notice::blocked(event.id, &reason));
            continue;
        }

        // send any metadata events to the NIP-05 verifier
        if nip05_active && event.is_kind_metadata() {
            // we are sending this prior to even deciding if we
            // persist it.  this allows the nip05 module to
            // inspect it, update if necessary, or persist a new
            // event and broadcast it itself.
            metadata_tx.send(event.clone()).ok();
        }

        // Performance note: this deliberately performs the repository lookup on each
        // event; there is no author cache whose invalidation could become stale.
        let start = Instant::now();
        if event.is_ephemeral() {
            bcast_tx.send(event.clone()).ok();
            debug!(
                "published ephemeral event: {:?} from: {:?} in: {:?}",
                event.get_event_id_prefix(),
                event.get_author_prefix(),
                start.elapsed()
            );
            event_write = true;

            // send OK message
            deliver_notice(&notice_tx, close_tx.as_ref(), Notice::saved(event.id));
        } else {
            // Build the eviction plan BEFORE writing. Afterwards the deleted delegation
            // is hidden, leaving no evidence that the deleting author owns it.
            let eviction_plan = if event.kind == 5 {
                match plan_cache_eviction_for_deletion(&repo, &event).await {
                    Ok(plan) => plan,
                    Err(reason) => {
                        deliver_notice(&notice_tx, close_tx.as_ref(), Notice::blocked(event.id, &reason));
                        continue;
                    }
                }
            } else {
                Vec::new()
            };
            match repo.write_event(&event).await {
                Ok(updated) => {
                    if updated == 0 {
                        trace!("ignoring duplicate or deleted event");
                        deliver_notice(&notice_tx, close_tx.as_ref(), Notice::duplicate(event.id));
                    } else {
                        info!(
                            "persisted event: {:?} (kind: {}) from: {:?} in: {:?} (IP: {:?})",
                            event.get_event_id_prefix(),
                            event.kind,
                            event.get_author_prefix(),
                            start.elapsed(),
                            subm_event.source_ip,
                        );
                        event_write = true;
                        // A newly-admitted revocation may invalidate a
                        // verdict already cached (as valid) for the
                        // delegation it references; evict it so the next
                        // lookup re-checks against the repo instead of
                        // riding out the cache TTL on stale data.
                        if event.kind == crate::a4a_delegation::A4A_KIND_REVOCATION {
                            maybe_invalidate_for_revocation(&repo, &a4a_cache, &event).await;
                        }
                        // NIP-09 deletion terminates a delegation just like revocation;
                        // cached verdicts must not outlive it.
                        apply_cache_eviction(&a4a_cache, &eviction_plan);
                        // send this out to all clients
                        bcast_tx.send(event.clone()).ok();
                        deliver_notice(&notice_tx, close_tx.as_ref(), Notice::saved(event.id));
                    }
                }
                Err(err) => {
                    warn!("event insert failed: {:?}", err);
                    let msg = "relay experienced an error trying to publish the latest event";
                    deliver_notice(&notice_tx, close_tx.as_ref(), Notice::error(event.id, msg));
                }
            }
        }

        // use rate limit, if defined, and if an event was actually written.
        if event_write {
            if let Some(ref lim) = lim_opt {
                if let Err(n) = lim.check() {
                    let wait_for = n.wait_time_from(clock.now());
                    // check if we have recently logged rate
                    // limits, but print out a message only once
                    // per second.
                    if most_recent_rate_limit.elapsed().as_secs() > 10 {
                        warn!(
                            "rate limit reached for event creation (sleep for {:?}) (suppressing future messages for 10 seconds)",
                            wait_for
                        );
                        // reset last rate limit message
                        most_recent_rate_limit = Instant::now();
                    }
                    // block event writes, allowing them to queue up.
                    // Use tokio::time::sleep, NOT thread::sleep. db_writer is an async task,
                    // and blocking sleep stalls the executor thread with every task on it,
                    // making write throttling slow reads and WebSockets too.
                    tokio::time::sleep(wait_for).await;
                    continue;
                }
            }
        }
    }
    info!("database connection closed");
    Ok(())
}

/// Serialized event associated with a specific subscription request.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct QueryResult {
    /// Subscription identifier
    pub sub_id: String,
    /// Serialized event
    pub event: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::a4a_delegation::{A4A_KIND_DELEGATION, A4A_KIND_REVOCATION};
    use bitcoin_hashes::{sha256, Hash};
    use prometheus::{Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, Opts};
    use secp256k1::{Keypair, Secp256k1};

    struct TestAuthzDecision {
        permitted: bool,
        message: Option<String>,
    }

    impl nauthz::AuthzDecision for TestAuthzDecision {
        fn permitted(&self) -> bool {
            self.permitted
        }

        fn message(&self) -> Option<String> {
            self.message.clone()
        }
    }

    /// An explicitly configured policy service is an authorization boundary, not an
    /// advisory observer. Outage must reject writes; permit and deny responses retain
    /// their normal meaning.
    #[test]
    fn external_admission_service_fails_closed() {
        assert!(nauthz_rejection(Ok(Box::new(TestAuthzDecision {
            permitted: true,
            message: None,
        })))
        .is_none());
        assert_eq!(
            nauthz_rejection(Ok(Box::new(TestAuthzDecision {
                permitted: false,
                message: Some("policy denied".to_owned()),
            })))
            .as_deref(),
            Some("policy denied")
        );
        assert_eq!(
            nauthz_rejection(Err(crate::error::Error::AuthzError)).as_deref(),
            Some("authorization service unavailable; event refused")
        );
    }

    fn test_metrics() -> NostrMetrics {
        NostrMetrics {
            query_sub: Histogram::with_opts(HistogramOpts::new("db_test_query_seconds", "test"))
                .unwrap(),
            query_db: Histogram::with_opts(HistogramOpts::new("db_test_filter_seconds", "test"))
                .unwrap(),
            connections_active: IntGauge::with_opts(
                Opts::new("db_test_connections_active", "test")).unwrap(),
            db_connections: IntGauge::with_opts(Opts::new("db_test_db_connections", "test"))
                .unwrap(),
            write_events: Histogram::with_opts(HistogramOpts::new(
                "db_test_events_write_seconds",
                "test",
            ))
            .unwrap(),
            sent_events: IntCounterVec::new(
                Opts::new("db_test_events_sent_total", "test"),
                &["source"],
            )
            .unwrap(),
            connections: IntCounter::with_opts(Opts::new("db_test_connections_total", "test"))
                .unwrap(),
            disconnects: IntCounterVec::new(
                Opts::new("db_test_disconnects_total", "test"),
                &["reason"],
            )
            .unwrap(),
            query_aborts: IntCounterVec::new(
                Opts::new("db_test_query_abort_total", "test"),
                &["reason"],
            )
            .unwrap(),
            cmd_req: IntCounter::with_opts(Opts::new("db_test_cmd_req_total", "test")).unwrap(),
            cmd_event: IntCounter::with_opts(Opts::new("db_test_cmd_event_total", "test")).unwrap(),
            cmd_close: IntCounter::with_opts(Opts::new("db_test_cmd_close_total", "test")).unwrap(),
            cmd_auth: IntCounter::with_opts(Opts::new("db_test_cmd_auth_total", "test")).unwrap(),
        }
    }

    /// Build a `SqliteRepo` backed by a fresh, uniquely-named temp directory
    /// (mirrors `repo::sqlite::tests::test_repo`, duplicated here since that
    /// helper is private to its own module).
    async fn test_repo() -> SqliteRepo {
        use std::sync::atomic::{AtomicU64, Ordering};
        static TEST_DB_COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = TEST_DB_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "nostr_rs_relay_db_test_{}_{}",
            std::process::id(),
            n
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut settings = Settings::default();
        settings.database.data_directory = dir.to_string_lossy().to_string();
        settings.database.min_conn = 1;
        settings.database.max_conn = 4;
        let repo = SqliteRepo::new(&settings, test_metrics());
        repo.migrate_up().await.unwrap();
        repo
    }

    fn a4a_settings(required_for_kinds: Option<Vec<u64>>) -> Settings {
        let mut settings = Settings::default();
        settings.a4a.enabled = true;
        settings.a4a.required_for_kinds = required_for_kinds;
        settings.a4a.delegation_cache_ttl_secs = 300;
        settings
    }

    /// A `LookupRateLimiter` with a budget generous enough that ordinary
    /// functional tests (which perform at most a couple of lookups) never
    /// trip it -- rate-limiting behavior itself is exercised separately,
    /// with its own low-budget limiters.
    fn test_limiter() -> LookupRateLimiter {
        LookupRateLimiter::new(1_000)
    }

    fn make_event(pubkey: String, kind: u64, tags: Vec<Vec<String>>) -> Event {
        Event {
            id: String::new(),
            pubkey,
            delegated_by: None,
            created_at: 1_000,
            kind,
            tags,
            content: String::new(),
            sig: String::new(),
            tagidx: None,
        }
    }

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

    fn delegation_event(chain: &Chain, expiration: u64) -> Event {
        let delegation = make_event(
            chain.owner_pubkey.clone(),
            A4A_KIND_DELEGATION,
            vec![
                // `d` is required: kind 31000 is addressed by delegate and its revocation
                // is looked up through the same coordinate.
                vec!["d".to_owned(), chain.agent_pubkey.clone()],
                vec!["delegate".to_owned(), chain.agent_pubkey.clone()],
                vec!["owner".to_owned(), chain.owner_pubkey.clone()],
                vec!["expiration".to_owned(), expiration.to_string()],
            ],
        );
        sign_event(delegation, &chain.owner_keypair)
    }

    fn agent_event(chain: &Chain, delegation_id: &str) -> Event {
        let event = make_event(
            chain.agent_pubkey.clone(),
            1,
            vec![vec![
                "delegation".to_owned(),
                delegation_id.to_owned(),
            ]],
        );
        sign_event(event, &chain.agent_keypair)
    }

    /// A valid, owner-signed revocation of the AGENT (not of one copy of the
    /// delegation) -- `d` is the delegate pubkey, `a` the addressable coordinate,
    /// `e` informational.
    fn revocation_event(chain: &Chain, delegation: &Event) -> Event {
        let revocation = make_event(
            chain.owner_pubkey.clone(),
            A4A_KIND_REVOCATION,
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

    fn future_expiration() -> u64 {
        unix_time() + 3600
    }

    fn past_expiration() -> u64 {
        unix_time().saturating_sub(3600)
    }

    /// Finding 122: kind 1040 is protected from deletion (`PROTECTED_KINDS`) but was
    /// accepted from any key. An attacker using a fresh key per event could fill disk
    /// with data untouched by age, per-author, or size limits. Readers accept timestamps
    /// only from the declared notary, so storing foreign ones serves no purpose.
    #[tokio::test]
    async fn timestamp_attestations_only_from_the_declared_notary() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let cache = A4aCache::new();
        let limiter = test_limiter();
        let mut settings = a4a_settings(None);
        settings.a4a.notary_pubkey = Some("ab".repeat(32));
        settings.a4a.notary_retired = vec![crate::config::NotaryRetired {
            pubkey: "cd".repeat(32),
            until: 1_788_000_000,
        }];

        let from_notary = make_event("ab".repeat(32), 1040, vec![]);
        assert!(
            check_a4a_delegation(&repo, &cache, &limiter, &from_notary, &settings).await.is_ok(),
            "the declared notary's timestamp must be accepted"
        );

        let from_retired = make_event("cd".repeat(32), 1040, vec![]);
        assert!(
            check_a4a_delegation(&repo, &cache, &limiter, &from_retired, &settings).await.is_ok(),
            "a retired key's timestamp must be accepted because its older proofs remain valid"
        );

        let stranger = make_event("ef".repeat(32), 1040, vec![]);
        let err = check_a4a_delegation(&repo, &cache, &limiter, &stranger, &settings)
            .await
            .expect_err("foreign timestamp accepted, allowing free undeletable disk growth");
        assert!(err.contains("notary"), "reason does not name the notary: {err}");

        // A node without a declared notary accepts all timestamps but stores them as
        // disposable (see protected_kinds). Otherwise this half of the protocol could
        // not be tested locally and operators would first encounter it in production.
        let mut without = a4a_settings(None);
        without.a4a.notary_pubkey = None;
        assert!(
            check_a4a_delegation(&repo, &cache, &limiter, &stranger, &without).await.is_ok(),
            "a node without a notary rejected a timestamp, preventing local testing"
        );

        // This path does not affect ordinary events from unrelated authors.
        let ordinary = make_event("ef".repeat(32), 1, vec![]);
        assert!(check_a4a_delegation(&repo, &cache, &limiter, &ordinary, &settings).await.is_ok());
    }

    // (a) enabled=false -> Ok, even with no delegation tag at all.
    #[tokio::test]
    async fn disabled_admits_everything() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let cache = A4aCache::new();
        let limiter = test_limiter();
        let settings = Settings::default(); // a4a.enabled = false
        let chain = make_chain();
        let event = make_event(chain.agent_pubkey, 1, vec![]);
        let result = check_a4a_delegation(&repo, &cache, &limiter, &event, &settings).await;
        assert!(result.is_ok());
    }

    // (b) event with a valid delegation present in the repo -> Ok.
    #[tokio::test]
    async fn valid_delegation_is_admitted() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let cache = A4aCache::new();
        let limiter = test_limiter();
        let settings = a4a_settings(None);
        let chain = make_chain();
        let delegation = delegation_event(&chain, future_expiration());
        repo.write_event(&delegation).await.unwrap();
        let event = agent_event(&chain, &delegation.id);

        let result = check_a4a_delegation(&repo, &cache, &limiter, &event, &settings).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    // (c) delegation id absent from repo -> Err.
    #[tokio::test]
    async fn missing_delegation_is_rejected() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let cache = A4aCache::new();
        let limiter = test_limiter();
        let settings = a4a_settings(None);
        let chain = make_chain();
        let event = agent_event(&chain, &"0".repeat(64));

        let result = check_a4a_delegation(&repo, &cache, &limiter, &event, &settings).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "referenced A4A delegation not found");
    }

    // (d) delegation that fails validate_a4a_delegation (expired) -> Err.
    #[tokio::test]
    async fn expired_delegation_is_rejected() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let cache = A4aCache::new();
        let limiter = test_limiter();
        let settings = a4a_settings(None);
        let chain = make_chain();
        let delegation = delegation_event(&chain, past_expiration());
        repo.write_event(&delegation).await.unwrap();
        let event = agent_event(&chain, &delegation.id);

        let result = check_a4a_delegation(&repo, &cache, &limiter, &event, &settings).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.starts_with("invalid or expired A4A delegation: "), "reason missing: {err}");
    }

    // (d2b) The cache bust runs off the revocation's `e` tag, whose spelling
    // the publisher controls, while cache keys are canonical (lower-case). An
    // upper-case `e` tag matched no key and left the pre-revocation "valid"
    // verdict alive for the whole cache TTL.
    #[tokio::test]
    async fn cache_bust_ignores_hex_case_of_the_revocation_tag() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let limiter = test_limiter();
        let settings = a4a_settings(None);
        let chain = make_chain();
        let delegation = delegation_event(&chain, future_expiration());
        repo.write_event(&delegation).await.unwrap();
        let event = agent_event(&chain, &delegation.id);

        let cache = A4aCache::new();
        assert!(
            check_a4a_delegation(&repo, &cache, &limiter, &event, &settings)
                .await
                .is_ok(),
            "delegation should be valid before revocation"
        );

        repo.write_event(&revocation_event(&chain, &delegation))
            .await
            .unwrap();
        cache.invalidate_delegation(&delegation.id.to_uppercase());

        let result = check_a4a_delegation(&repo, &cache, &limiter, &event, &settings).await;
        assert!(
            result.is_err(),
            "stale valid verdict survived a revocation whose e tag was upper-case"
        );
    }

    // (d3b) The fix normalizes the id rather than rejecting odd spellings, so an
    // upper-case (but unrevoked) delegation must still be ADMITTED. Without this
    // the suite would be equally green if the relay simply refused every
    // non-canonical id -- a different, and needlessly breaking, policy.
    #[tokio::test]
    async fn upper_case_delegation_id_still_works_when_not_revoked() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let cache = A4aCache::new();
        let limiter = test_limiter();
        let settings = a4a_settings(None);
        let chain = make_chain();
        let delegation = delegation_event(&chain, future_expiration());
        repo.write_event(&delegation).await.unwrap();

        let event = agent_event(&chain, &delegation.id.to_uppercase());
        let result = check_a4a_delegation(&repo, &cache, &limiter, &event, &settings).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    /// A counterpart observed on the wire that a revocation with uppercase `d` and no
    /// `a` tag was rejected with "must name a delegate consistently in d and a," naming
    /// a tag the event did not contain. An implementer would fix `a` while the real issue
    /// was `d` case. This is the same class as finding 63.
    #[tokio::test]
    async fn rejection_of_non_canonical_revocation_d_names_the_real_reason() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let cache = A4aCache::new();
        let limiter = test_limiter();
        let settings = a4a_settings(None);
        let chain = make_chain();
        let ev = make_event(
            chain.owner_pubkey.clone(),
            A4A_KIND_REVOCATION,
            vec![vec!["d".to_owned(), chain.agent_pubkey.to_uppercase()]],
        );
        let ev = sign_event(ev, &chain.owner_keypair);
        let err = check_a4a_delegation(&repo, &cache, &limiter, &ev, &settings)
            .await
            .expect_err("revocation with non-canonical d was accepted");
        assert!(err.contains("lowercase hex"), "reason does not identify case: {err}");
        assert!(!err.contains("and a"), "rejection names an absent a tag: {err}");
    }

    /// A revocation is permanent history and has no lifetime. With `expiration`, NIP-40
    /// makes it disappear from REQ results, which is how SDK counterparties discover
    /// revocations, so the agent appears authorized again; another relay may delete it.
    /// An owner would not intend this, but a library that adds deadlines indiscriminately
    /// could. Review found it while applying our own deadline policy to live probes
    /// (internal finding 79).
    #[tokio::test]
    async fn revocation_carrying_an_expiration_tag_is_refused() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let cache = A4aCache::new();
        let limiter = test_limiter();
        let settings = a4a_settings(None);
        let chain = make_chain();
        let delegation = delegation_event(&chain, future_expiration());
        repo.write_event(&delegation).await.unwrap();
        let mut rev = revocation_event(&chain, &delegation);
        rev.tags.push(vec!["expiration".to_owned(), future_expiration().to_string()]);
        let rev = sign_event(rev, &chain.owner_keypair);
        let err = check_a4a_delegation(&repo, &cache, &limiter, &rev, &settings)
            .await
            .expect_err("revocation with a lifetime was accepted");
        assert!(err.contains("expiration"), "reason missing: {err}");
        // Positive control: the same revocation without a deadline is accepted.
        let plain = revocation_event(&chain, &delegation);
        assert!(check_a4a_delegation(&repo, &cache, &limiter, &plain, &settings).await.is_ok());
    }

    // ---- Finding 63: rejection names the reason, including on cache hits ----

    /// Seven distinct failures collapsed into "invalid or expired A4A delegation," so
    /// another client could not determine a remedy. Found by an agent implementing a
    /// client strictly from the specification (internal finding 63).
    #[tokio::test]
    async fn rejection_names_the_reason_expired() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let cache = A4aCache::new();
        let limiter = test_limiter();
        let settings = a4a_settings(None);
        let chain = make_chain();
        let delegation = delegation_event(&chain, past_expiration());
        repo.write_event(&delegation).await.unwrap();
        let event = agent_event(&chain, &delegation.id);
        let err = check_a4a_delegation(&repo, &cache, &limiter, &event, &settings)
            .await
            .expect_err("expired delegation was accepted");
        assert!(err.contains("has expired"), "reason missing: {err}");
    }

    /// Revocation is the most common real-world failure and the most important for a
    /// client: the agent must learn that the owner stopped it, not reissue a mandate.
    #[tokio::test]
    async fn rejection_names_the_reason_revoked_also_from_cache() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let cache = A4aCache::new();
        let limiter = test_limiter();
        let settings = a4a_settings(None);
        let chain = make_chain();
        let delegation = delegation_event(&chain, future_expiration());
        repo.write_event(&delegation).await.unwrap();
        repo.write_event(&revocation_event(&chain, &delegation))
            .await
            .unwrap();
        let event = agent_event(&chain, &delegation.id);
        let err = check_a4a_delegation(&repo, &cache, &limiter, &event, &settings)
            .await
            .expect_err("revoked delegation was accepted");
        assert!(err.contains("revoked"), "reason missing: {err}");
        // Second check is a cache hit. The reason must survive caching; the old cache
        // stored only yes/no and returned a generic message on hits.
        let err = check_a4a_delegation(&repo, &cache, &limiter, &event, &settings)
            .await
            .expect_err("revoked delegation was accepted from cache");
        assert!(err.contains("revoked"), "cache hit lost the reason: {err}");
    }

    // ---- Kind-31007 intake: two checks added by audit on 2026-09-04 ----
    //
    // Both close one scenario: the owner revokes an agent, the relay returns OK=true,
    // but the revocation has no effect. Review showed neither was tested: disabling both
    // still produced 186 passing tests.

    /// In the legacy format, `d` and `e` name the same delegation id. Shape alone can
    /// detect it, so rejection must also work when the relay has NOT seen the delegation
    /// because it was reissued or arrived elsewhere. Review demonstrated that a
    /// data-only check missed exactly those two cases.
    #[tokio::test]
    async fn old_format_revocation_is_refused_by_shape_even_for_an_unseen_delegation() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let cache = A4aCache::new();
        let limiter = test_limiter();
        let settings = a4a_settings(None);
        let chain = make_chain();
        let delegation = delegation_event(&chain, future_expiration());
        // Do NOT store the delegation; the relay has never seen it.
        let old_style = raw_revocation(
            &chain.owner_keypair,
            &chain.owner_pubkey,
            &delegation.id,
            &delegation.id,
        );
        let result = check_a4a_delegation(&repo, &cache, &limiter, &old_style, &settings).await;
        assert!(
            result.as_ref().is_err_and(|e| e.contains("not the delegation event id")),
            "legacy revocation was accepted for an unseen delegation: {result:?}"
        );
    }

    /// Positive control: a NEW-format revocation for an unseen delegation must be
    /// accepted, or cross-relay revocation distribution breaks (finding 50).
    #[tokio::test]
    async fn proper_revocation_for_an_unseen_delegation_is_still_admitted() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let cache = A4aCache::new();
        let limiter = test_limiter();
        let settings = a4a_settings(None);
        let chain = make_chain();
        let delegation = delegation_event(&chain, future_expiration());
        let revocation = revocation_event(&chain, &delegation);
        let result = check_a4a_delegation(&repo, &cache, &limiter, &revocation, &settings).await;
        assert!(result.is_ok(), "cross-relay revocation distribution broke: {result:?}");
    }

    /// The format lookup failed. The old path logged and accepted the revocation,
    /// so the owner received OK for an event the relay had not checked.
    #[tokio::test]
    async fn revocation_is_not_accepted_when_the_format_lookup_fails() {
        let repo = test_repo().await;
        repo.write_pool()
            .get()
            .unwrap()
            .execute_batch("DROP TABLE event;")
            .unwrap();
        let repo: Arc<dyn NostrRepo> = Arc::new(repo);
        let cache = A4aCache::new();
        let limiter = test_limiter();
        let settings = a4a_settings(None);
        let chain = make_chain();
        let delegation = delegation_event(&chain, future_expiration());
        let revocation = raw_revocation(
            &chain.owner_keypair,
            &chain.owner_pubkey,
            &chain.agent_pubkey,
            &delegation.id,
        );
        let result = check_a4a_delegation(&repo, &cache, &limiter, &revocation, &settings).await;
        let err = result.expect_err("database failure was accepted as a successful revocation");
        assert!(
            err.contains("could not check revocation format"),
            "{err}"
        );
    }

    /// The live delegation read failed. Absence is still accepted (the delegation
    /// may not have arrived). A failed read must not be treated as absence.
    #[tokio::test]
    async fn revocation_is_not_accepted_when_the_delegation_lookup_fails() {
        let repo = test_repo().await;
        repo.write_pool()
            .get()
            .unwrap()
            .execute_batch("DROP TABLE tag;")
            .unwrap();
        let repo: Arc<dyn NostrRepo> = Arc::new(repo);
        let cache = A4aCache::new();
        let limiter = test_limiter();
        let settings = a4a_settings(None);
        let chain = make_chain();
        let delegation = delegation_event(&chain, future_expiration());
        let revocation = raw_revocation(
            &chain.owner_keypair,
            &chain.owner_pubkey,
            &chain.agent_pubkey,
            &delegation.id,
        );
        let result = check_a4a_delegation(&repo, &cache, &limiter, &revocation, &settings).await;
        let err = result.expect_err("database failure was accepted as a successful revocation");
        assert!(
            err.contains("could not verify revocation against delegation"),
            "{err}"
        );
    }

    /// The revocation is already stored. A failed ownership read must not leave
    /// the previous allow in the cache until TTL.
    #[tokio::test]
    async fn failed_revocation_ownership_read_drops_cached_allows() {
        let repo = test_repo().await;
        let cache = A4aCache::new();
        let chain = make_chain();
        let delegation = delegation_event(&chain, future_expiration());
        cache.insert(
            &delegation.id,
            &chain.agent_pubkey,
            true,
            unix_time() + 3_600,
        );
        repo.write_pool()
            .get()
            .unwrap()
            .execute_batch("DROP TABLE tag;")
            .unwrap();
        let repo: Arc<dyn NostrRepo> = Arc::new(repo);
        let revocation = revocation_event(&chain, &delegation);
        maybe_invalidate_for_revocation(&repo, &cache, &revocation).await;
        assert!(
            cache.get(&delegation.id, &chain.agent_pubkey).is_none(),
            "cached allow survived a failed ownership read"
        );
    }

    #[test]
    fn poisoned_cache_lock_does_not_keep_an_allow() {
        let cache = A4aCache::new();
        cache.insert("deleg", "agent", true, unix_time() + 3_600);
        let cache_ref = &cache;
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = cache_ref.entries.lock().unwrap();
            panic!("poison the delegation cache");
        }));
        cache.invalidate_agent("agent");
        let guard = cache.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(
            !guard.values().any(|verdict| verdict.valid),
            "poisoned mutex skipped invalidation and kept an allow"
        );
    }

    /// A full notice channel must not stall `db_writer`. That task is the
    /// relay's only write loop. Waiting for one client that is not reading
    /// stops every other client's publish.
    ///
    /// This calls `deliver_notice` itself, the function the writer uses.
    /// A helper that accepts a shorter timeout would stay green while the
    /// writer still slept for seconds.
    #[tokio::test]
    async fn a_full_notice_channel_does_not_stall_the_writer() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        tx.try_send(Notice::saved("1".repeat(64))).unwrap();
        let (close_tx, mut close_rx) = tokio::sync::mpsc::channel(1);
        let started = std::time::Instant::now();
        let outcome = deliver_notice(
            &tx,
            Some(&close_tx),
            Notice::error("2".repeat(64), "could not tell the client"),
        );
        let elapsed = started.elapsed();
        assert_eq!(outcome, NoticeDelivery::NotDelivered);
        assert!(
            elapsed < std::time::Duration::from_millis(50),
            "a client that is not reading stalled the single writer for {elapsed:?}"
        );
        assert!(
            close_rx.try_recv().is_ok(),
            "the connection was not asked to close"
        );
        // The close signal is already queued. The next decision must still
        // return at once: this is the repeat that used to cost two seconds
        // per event.
        let started_again = std::time::Instant::now();
        let again = deliver_notice(
            &tx,
            Some(&close_tx),
            Notice::error("3".repeat(64), "still not reading"),
        );
        assert_eq!(again, NoticeDelivery::NotDelivered);
        let elapsed_again = started_again.elapsed();
        assert!(
            elapsed_again < std::time::Duration::from_millis(50),
            "a second undelivered decision stalled the writer for {elapsed_again:?}"
        );
    }

    /// A revocation dated before its delegation never revokes it; the
    /// `>= created_at` rule protects rehiring. The relay used to ACCEPT such an event
    /// with OK=true, leading the owner to believe the agent stopped while it could
    /// publish indefinitely. Found by a live race probe with a positive control.
    #[tokio::test]
    async fn revocation_dated_before_its_delegation_is_refused_instead_of_silently_dead() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let cache = A4aCache::new();
        let limiter = test_limiter();
        let settings = a4a_settings(None);
        let chain = make_chain();
        let delegation = delegation_event(&chain, future_expiration());
        repo.write_event(&delegation).await.unwrap();

        let mut skewed = revocation_event(&chain, &delegation);
        skewed.created_at = delegation.created_at.saturating_sub(90);
        let skewed = sign_event(skewed, &chain.owner_keypair);
        assert!(skewed.validate().is_ok(), "invalid setup: signature must verify");
        // Precondition: validation rules really do consider this revocation dead.
        assert!(!validate_a4a_revocation(&skewed, &delegation), "invalid test setup");

        let result = check_a4a_delegation(&repo, &cache, &limiter, &skewed, &settings).await;
        assert!(
            result.as_ref().is_err_and(|e| e.contains("would not revoke")),
            "dead revocation received OK, leaving the owner unaware forever: {result:?}"
        );

        // Positive control in the same run: a correctly dated revocation is accepted.
        let proper = revocation_event(&chain, &delegation);
        let result = check_a4a_delegation(&repo, &cache, &limiter, &proper, &settings).await;
        assert!(result.is_ok(), "valid revocation was rejected: {result:?}");
    }

    // ---- Deletion-target cap: 64 after filtering junk and duplicates ----

    fn deletion_naming(signer: &secp256k1::Keypair, pubkey: &str, targets: Vec<String>) -> Event {
        let tags = targets.into_iter().map(|t| vec!["e".to_owned(), t]).collect();
        sign_event(make_event(pubkey.to_owned(), 5, tags), signer)
    }

    /// Junk `e` tags must neither cost database reads nor consume the cap. A delegation
    /// after one hundred short junk tags must still enter the plan.
    #[tokio::test]
    async fn junk_deletion_targets_do_not_consume_the_lookup_cap() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let chain = make_chain();
        let delegation = delegation_event(&chain, future_expiration());
        repo.write_event(&delegation).await.unwrap();

        let mut targets: Vec<String> = (0..200).map(|i| format!("x{i}")).collect();
        targets.push(delegation.id.clone());
        let deletion = deletion_naming(&chain.owner_keypair, &chain.owner_pubkey, targets);
        let plan = plan_cache_eviction_for_deletion(&repo, &deletion).await.unwrap();
        assert_eq!(plan, vec![delegation.id.clone()], "junk displaced the delegation from the plan");
    }

    /// Duplicates do not consume the cap either. Repeating one id two hundred times is
    /// the cheapest way to multiply reads and must not work.
    #[tokio::test]
    async fn duplicate_deletion_targets_do_not_consume_the_lookup_cap() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let chain = make_chain();
        let delegation = delegation_event(&chain, future_expiration());
        repo.write_event(&delegation).await.unwrap();

        let filler = "f".repeat(64);
        let mut targets: Vec<String> = std::iter::repeat_n(filler, 200).collect();
        targets.push(delegation.id.clone());
        let deletion = deletion_naming(&chain.owner_keypair, &chain.owner_pubkey, targets);
        let plan = plan_cache_eviction_for_deletion(&repo, &deletion).await.unwrap();
        assert_eq!(plan, vec![delegation.id.clone()], "duplicates displaced the delegation from the plan");
    }

    /// The cap is real: a delegation AFTER 64 unique valid ids does not enter the plan.
    /// This documented, owner-self-inflicted residual keeps the number pinned so it
    /// cannot be removed again on a false premise.
    #[tokio::test]
    async fn deletion_targets_beyond_the_cap_are_not_looked_up() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let chain = make_chain();
        let delegation = delegation_event(&chain, future_expiration());
        repo.write_event(&delegation).await.unwrap();

        // Use a literal, not the constant. A test built from the constant moves with it
        // and misses changes; a mutation to 100,000 passed and increased runtime from
        // one second to fourteen. Pin the number so raising it requires conscious review.
        assert_eq!(MAX_DELETION_TARGETS_CHECKED, 64, "cap changed; review the rationale");
        let unique = |n: usize| -> Vec<String> {
            (0..n).map(|i| format!("{i:064x}")).collect()
        };
        // Exactly at the cap is included.
        let mut at_cap = unique(63);
        at_cap.push(delegation.id.clone());
        let deletion = deletion_naming(&chain.owner_keypair, &chain.owner_pubkey, at_cap);
        assert_eq!(
            plan_cache_eviction_for_deletion(&repo, &deletion).await,
            Ok(vec![delegation.id.clone()]),
            "the delegation at position 64 must enter the plan"
        );
        // Beyond the cap is rejected, not partially applied. Partial inspection would
        // let a delegation after the cap disappear from storage but remain valid in cache.
        let mut past_cap = unique(64);
        past_cap.push(delegation.id.clone());
        let deletion = deletion_naming(&chain.owner_keypair, &chain.owner_pubkey, past_cap);
        assert!(
            plan_cache_eviction_for_deletion(&repo, &deletion).await.is_err(),
            "oversized deletion was partly accepted"
        );
    }

    /// A revocation is irreversible. Deleting it would make the repository lookup stop
    /// finding it and silently restore every older delegation for that agent. Rehiring
    /// is represented by a newer delegation, which the timestamp rule already permits.
    #[tokio::test]
    async fn deleting_a_revocation_is_refused() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let chain = make_chain();
        let delegation = delegation_event(&chain, future_expiration());
        let revocation = revocation_event(&chain, &delegation);
        repo.write_event(&delegation).await.unwrap();
        repo.write_event(&revocation).await.unwrap();
        let deletion = deletion_naming(
            &chain.owner_keypair,
            &chain.owner_pubkey,
            vec![revocation.id.clone()],
        );

        let reason = plan_cache_eviction_for_deletion(&repo, &deletion)
            .await
            .unwrap_err();
        assert!(reason.contains("revocations cannot be deleted"), "{reason}");
        assert!(repo.get_event_by_id(&revocation.id).await.unwrap().is_some());
    }

    /// A kind-31007 event signed by `signer`, carrying the given `d`/`e` tags
    /// verbatim -- used to probe what the relay accepts, so the tags must NOT be
    /// normalized by the helper.
    fn raw_revocation(signer: &secp256k1::Keypair, pubkey: &str, d: &str, e: &str) -> Event {
        let ev = make_event(
            pubkey.to_owned(),
            A4A_KIND_REVOCATION,
            vec![
                vec!["d".to_owned(), d.to_owned()],
                vec!["e".to_owned(), e.to_owned()],
            ],
        );
        sign_event(ev, signer)
    }

    // (e1) FINDING 6 -- a revocation names the AGENT, and its `a` coordinate must
    // agree with its `d` tag. While the two could drift, the same event meant
    // different things to different call sites, and the owner still got OK=true.
    #[tokio::test]
    async fn revocation_with_contradictory_coordinate_is_rejected() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let cache = A4aCache::new();
        let limiter = test_limiter();
        let settings = a4a_settings(None);
        let chain = make_chain();

        let bad = make_event(
            chain.owner_pubkey.clone(),
            A4A_KIND_REVOCATION,
            vec![
                vec!["d".to_owned(), chain.agent_pubkey.clone()],
                // Coordinate names a DIFFERENT delegate.
                vec![
                    "a".to_owned(),
                    format!("{}:{}:{}", A4A_KIND_DELEGATION, chain.owner_pubkey, "f".repeat(64)),
                ],
            ],
        );
        let bad = sign_event(bad, &chain.owner_keypair);
        let result = check_a4a_delegation(&repo, &cache, &limiter, &bad, &settings).await;
        assert!(
            result.is_err(),
            "revocation with a contradictory coordinate was accepted"
        );
    }

    // (e2) FINDING 4 -- the cache bust fired on ANY admitted kind 31007, with no
    // check that its author owns the delegation. The delegation id is public (it
    // sits in plain text in every event the agent publishes), so a stranger could
    // evict a victim's cached verdict at will: every subsequent event of theirs
    // takes the slow path, spends the global lookup budget and starts getting
    // rejected, while each eviction walks a map of up to 100 000 entries inside
    // the single-threaded writer.
    #[tokio::test]
    async fn stranger_cannot_evict_someone_elses_cached_delegation() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let cache = A4aCache::new();
        let limiter = test_limiter();
        let settings = a4a_settings(None);
        let chain = make_chain();
        let delegation = delegation_event(&chain, future_expiration());
        repo.write_event(&delegation).await.unwrap();
        let event = agent_event(&chain, &delegation.id);
        assert!(
            check_a4a_delegation(&repo, &cache, &limiter, &event, &settings)
                .await
                .is_ok(),
            "delegation should be cached as valid first"
        );

        let stranger = make_chain(); // Another owner with no authority over this delegation.
        let forged = raw_revocation(
            &stranger.owner_keypair,
            &stranger.owner_pubkey,
            &delegation.id,
            &delegation.id,
        );
        maybe_invalidate_for_revocation(&repo, &cache, &forged).await;

        assert!(
            cache.get(&delegation.id, &chain.agent_pubkey).is_some(),
            "an unrelated revocation evicted the victim's cache entry"
        );
    }

    // (e3) The owner's own revocation must still evict -- otherwise (e2) would be
    // equally green if the bust were simply deleted, and a real revocation would
    // ride out the cache TTL.
    #[tokio::test]
    async fn owner_revocation_still_evicts_the_cache() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let cache = A4aCache::new();
        let limiter = test_limiter();
        let settings = a4a_settings(None);
        let chain = make_chain();
        let delegation = delegation_event(&chain, future_expiration());
        repo.write_event(&delegation).await.unwrap();
        let event = agent_event(&chain, &delegation.id);
        check_a4a_delegation(&repo, &cache, &limiter, &event, &settings)
            .await
            .unwrap();

        let real = revocation_event(&chain, &delegation);
        maybe_invalidate_for_revocation(&repo, &cache, &real).await;

        assert!(
            cache.get(&delegation.id, &chain.agent_pubkey).is_none(),
            "the owner's genuine revocation did not clear the cache"
        );
    }

    /// A delegation WITHOUT `d` that is otherwise valid.
    fn delegation_without_d(chain: &Chain, expiration: u64) -> Event {
        let delegation = make_event(
            chain.owner_pubkey.clone(),
            A4A_KIND_DELEGATION,
            vec![
                vec!["delegate".to_owned(), chain.agent_pubkey.clone()],
                vec!["owner".to_owned(), chain.owner_pubkey.clone()],
                vec!["expiration".to_owned(), expiration.to_string()],
            ],
        );
        sign_event(delegation, &chain.owner_keypair)
    }

    // (f7) FINDING 54 -- a delegation without `d` must NEVER be accepted.
    //
    // Before the fix it passed because validation required only `delegate`. Two paths
    // then diverged: authorization used `delegate`, while revocation cache invalidation
    // searched `d` and silently found nothing. The owner revoked the agent, the relay
    // accepted the revocation, and the agent published for the remaining cache TTL,
    // five minutes in production. A 2026-08-31 probe reproduced this before the fix.
    //
    // This test closes both ends: intake rejects the delegation, leaving no positive
    // cache verdict for a later revocation to invalidate.
    #[tokio::test]
    async fn delegation_without_d_tag_is_refused_so_nothing_can_go_stale() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let cache = A4aCache::new();
        let limiter = test_limiter();
        let settings = a4a_settings(None);
        let chain = make_chain();
        let delegation = delegation_without_d(&chain, future_expiration());
        repo.write_event(&delegation).await.unwrap();
        let event = agent_event(&chain, &delegation.id);

        assert!(
            check_a4a_delegation(&repo, &cache, &limiter, &event, &settings)
                .await
                .is_err(),
            "delegation without `d` was accepted but cannot later be revoked by `d`"
        );
        assert!(
            cache.get(&delegation.id, &chain.agent_pubkey) == Some(false),
            "verdict must be cached as NEGATIVE or every event from this agent \
             will query storage again"
        );
    }

    // (f7b) Positive side: a proper delegation with `d` remains accepted. Without this,
    // rule 8 could reject everything while all negative tests above stayed green.
    #[tokio::test]
    async fn proper_delegation_with_d_tag_is_still_admitted() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let cache = A4aCache::new();
        let limiter = test_limiter();
        let settings = a4a_settings(None);
        let chain = make_chain();
        let delegation = delegation_event(&chain, future_expiration());
        repo.write_event(&delegation).await.unwrap();
        let event = agent_event(&chain, &delegation.id);

        check_a4a_delegation(&repo, &cache, &limiter, &event, &settings)
            .await
            .expect("rule 8 rejected a valid delegation");
    }

    // (f1) FINDING 3 -- one loud key must not spend the whole relay's lookup
    // budget. The limiter was a single process-wide counter, so a flood from one
    // pubkey referencing unique delegation ids exhausted the window and every
    // subsequent MISS was refused -- including the first event of an honest agent
    // that had just registered. Budget is now sharded by the event author, so a
    // single key can only starve its own share.
    #[test]
    fn one_key_cannot_spend_the_whole_lookup_budget() {
        let limiter = LookupRateLimiter::new(64);
        let loud = "aa".repeat(32);
        let mut spent = 0;
        for _ in 0..1000 {
            if limiter.allow(&loud) {
                spent += 1;
            }
        }
        assert!(
            spent < 64,
            "one noisy party consumed the entire budget ({spent} of 64)"
        );

        // An honest agent in another shard must still pass after this flood.
        let quiet = "bb".repeat(32);
        assert!(
            limiter.allow(&quiet),
            "honest agent was rejected because of another party's traffic"
        );
    }

    /// Benchmark rather than a test: delegation-cache misses per second. The default
    /// limiter budget of 50/s was initially estimated; measure the protected cost before
    /// debating fairness. Run with:
    /// `cargo test --lib measure_delegation_miss_cost -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore]
    async fn measure_delegation_miss_cost() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let limiter = LookupRateLimiter::new(u32::MAX);
        let settings = a4a_settings(None);
        let chain = make_chain();
        let delegation = delegation_event(&chain, future_expiration());
        repo.write_event(&delegation).await.unwrap();
        let event = agent_event(&chain, &delegation.id);

        const N: u32 = 300;
        // Existing delegation: full path through database, Schnorr verification, and
        // revocation lookup. This is the expensive case.
        let start = Instant::now();
        for _ in 0..N {
            let cache = A4aCache::new(); // Cold each time to model a miss.
            check_a4a_delegation(&repo, &cache, &limiter, &event, &settings)
                .await
                .unwrap();
        }
        let hit = start.elapsed();

        // Missing delegation: database read only, without cryptography. This is the
        // flood pattern from finding 3.
        let missing = agent_event(&chain, &"0".repeat(64));
        let start = Instant::now();
        for _ in 0..N {
            let cache = A4aCache::new();
            let _ = check_a4a_delegation(&repo, &cache, &limiter, &missing, &settings).await;
        }
        let absent = start.elapsed();

        println!(
            "existing-delegation miss: {:?}/item, {:.0}/s",
            hit / N,
            f64::from(N) / hit.as_secs_f64()
        );
        println!(
            "missing-delegation miss (attacker traffic): {:?}/item, {:.0}/s",
            absent / N,
            f64::from(N) / absent.as_secs_f64()
        );
    }

    /// A kind-5 deletion (NIP-09) referencing `target`, signed by `signer`.
    fn deletion_event(signer: &secp256k1::Keypair, pubkey: &str, target: &str) -> Event {
        let ev = make_event(
            pubkey.to_owned(),
            5,
            vec![vec!["e".to_owned(), target.to_owned()]],
        );
        sign_event(ev, signer)
    }

    // (e4) NIP-09 DELETION vs THE VERDICT CACHE. Deleting the delegation is a
    // legitimate way for an owner to stop an agent -- the event is hidden, and
    // every lookup afterwards returns "not found". But the cache bust only ever
    // fired on a revocation, so a verdict cached before the deletion kept the
    // agent publishing for the whole TTL (five minutes in production). When the
    // deletion is a response to a compromised key, those minutes are the point.
    #[tokio::test]
    async fn deleting_a_delegation_evicts_its_cached_verdict() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let cache = A4aCache::new();
        let limiter = test_limiter();
        let settings = a4a_settings(None);
        let chain = make_chain();
        let delegation = delegation_event(&chain, future_expiration());
        repo.write_event(&delegation).await.unwrap();
        let event = agent_event(&chain, &delegation.id);
        check_a4a_delegation(&repo, &cache, &limiter, &event, &settings)
            .await
            .unwrap();

        let deletion = deletion_event(&chain.owner_keypair, &chain.owner_pubkey, &delegation.id);
        let planned = plan_cache_eviction_for_deletion(&repo, &deletion).await.unwrap();
        repo.write_event(&deletion).await.unwrap();
        apply_cache_eviction(&cache, &planned);

        assert!(
            cache.get(&delegation.id, &chain.agent_pubkey).is_none(),
            "deleted delegation remained valid in cache"
        );
    }

    // (e5) The eviction must not become a free lever for a stranger: deletion ids
    // are public, and a `retain` over a map of up to MAX_A4A_CACHE_ENTRIES inside
    // the single-threaded writer is exactly the cost finding 4 was about.
    #[tokio::test]
    async fn a_strangers_deletion_evicts_nothing() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let cache = A4aCache::new();
        let limiter = test_limiter();
        let settings = a4a_settings(None);
        let chain = make_chain();
        let delegation = delegation_event(&chain, future_expiration());
        repo.write_event(&delegation).await.unwrap();
        let event = agent_event(&chain, &delegation.id);
        check_a4a_delegation(&repo, &cache, &limiter, &event, &settings)
            .await
            .unwrap();

        let stranger = make_chain();
        let deletion =
            deletion_event(&stranger.owner_keypair, &stranger.owner_pubkey, &delegation.id);
        let planned = plan_cache_eviction_for_deletion(&repo, &deletion).await.unwrap();

        assert!(
            planned.is_empty(),
            "another owner's deletion would evict the victim's cache entry"
        );
    }

    // (d3) REVOCATION BYPASS VIA HEX CASE. The delegation id travels inside the
    // event's own signed tag, so the agent controls its spelling. Hex decodes
    // case-insensitively, so `get_event_by_id` finds the delegation whichever case
    // is used -- but the revocation lookup matches the `d` tag as a STRING, and the
    // owner's revocation stores it lowercase. Upper-case the id and the revocation
    // simply is not found: the relay keeps admitting events from a delegation its
    // owner has revoked. Nothing else in the chain catches it, because
    // `validate_a4a_delegation` never compares the delegation it fetched with the
    // id that was asked for.
    #[tokio::test]
    async fn revoked_delegation_is_rejected_regardless_of_hex_case() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let limiter = test_limiter();
        let settings = a4a_settings(None);
        let chain = make_chain();
        let delegation = delegation_event(&chain, future_expiration());
        repo.write_event(&delegation).await.unwrap();
        repo.write_event(&revocation_event(&chain, &delegation))
            .await
            .unwrap();

        let event = agent_event(&chain, &delegation.id.to_uppercase());
        let cache = A4aCache::new();
        let result = check_a4a_delegation(&repo, &cache, &limiter, &event, &settings).await;
        assert!(
            result.is_err(),
            "revoked delegation admitted when its id is spelled in upper-case hex"
        );
    }

    // (d2) a delegation that is otherwise valid and unexpired, but has since
    // been revoked by its owner (kind 31007, referencing the delegation via
    // its "e" tag), must be rejected -- even though `validate_a4a_delegation`
    // alone would accept it. Uses a fresh cache for the post-revocation call
    // to force the repo path (a real cache-hit scenario is covered by
    // `db_writer`'s own cache-bust on revocation admission, not by this
    // function in isolation).
    #[tokio::test]
    async fn revoked_delegation_is_rejected() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let limiter = test_limiter();
        let settings = a4a_settings(None);
        let chain = make_chain();
        let delegation = delegation_event(&chain, future_expiration());
        repo.write_event(&delegation).await.unwrap();
        let event = agent_event(&chain, &delegation.id);

        // Before any revocation exists, the delegation is admitted.
        let cache = A4aCache::new();
        let result = check_a4a_delegation(&repo, &cache, &limiter, &event, &settings).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");

        // Owner revokes the delegation.
        let revocation = revocation_event(&chain, &delegation);
        repo.write_event(&revocation).await.unwrap();

        // Fresh cache, so this call hits the repo path (and thus the
        // revocation lookup) rather than serving a stale cached verdict.
        let cache = A4aCache::new();
        let result = check_a4a_delegation(&repo, &cache, &limiter, &event, &settings).await;
        assert!(
            result.is_err(),
            "expected Err after revocation, got {result:?}"
        );
    }

    // (e) cache hit path: once cached, a second call must still return the
    // *cached* verdict even though the delegation event has been made
    // unavailable in the repo (hidden) between the two calls. A repo fetch
    // at that point would return `None` -> `Err("referenced A4A delegation
    // not found")`, so the only way the second call can still be `Ok(())`
    // is if `check_a4a_delegation` never asked the repo at all and served
    // the answer straight from `cache`. This is what actually distinguishes
    // a cache hit from the repo silently being re-fetched.
    #[tokio::test]
    async fn cache_hit_reuses_previous_verdict() {
        let sqlite_repo = test_repo().await;
        let write_pool = sqlite_repo.write_pool();
        let repo: Arc<dyn NostrRepo> = Arc::new(sqlite_repo);
        let cache = A4aCache::new();
        let limiter = test_limiter();
        let settings = a4a_settings(None);
        let chain = make_chain();
        let delegation = delegation_event(&chain, future_expiration());
        repo.write_event(&delegation).await.unwrap();
        let event = agent_event(&chain, &delegation.id);

        let first = check_a4a_delegation(&repo, &cache, &limiter, &event, &settings).await;
        assert!(first.is_ok(), "expected Ok, got {first:?}");

        // Directly assert the cache was actually populated with the
        // expected verdict for this exact key (delegation_id, pubkey) --
        // demonstrating the cache is consulted rather than incidentally
        // matching due to a fresh repo fetch.
        assert_eq!(cache.get(&delegation.id, &event.pubkey), Some(true));

        // Now make the delegation event unavailable in the repo: hide it
        // so `get_event_by_id` (which filters `hidden!=TRUE`) can no
        // longer find it, via a direct SQL write against the repo's own
        // write pool.
        let id_blob = hex::decode(&delegation.id).expect("delegation id is valid hex");
        let conn = write_pool.get().expect("get pooled sqlite connection");
        conn.execute(
            "UPDATE event SET hidden=TRUE WHERE event_hash=?",
            rusqlite::params![id_blob],
        )
        .expect("hide delegation event");
        drop(conn);

        // Sanity check: the repo itself can no longer serve this event --
        // if the cache didn't exist, `check_a4a_delegation` would now
        // reject the event as "referenced A4A delegation not found".
        assert!(
            repo.get_event_by_id(&delegation.id).await.unwrap().is_none(),
            "sanity check: delegation event must be unfetchable from repo now"
        );

        // Second call for the same key must still be Ok(()) -- the only
        // way that's possible now is if the verdict came from the cache.
        let second = check_a4a_delegation(&repo, &cache, &limiter, &event, &settings).await;
        assert!(
            second.is_ok(),
            "expected Ok from cache even though repo can no longer serve the delegation, got {second:?}"
        );
    }

    // (f) required_for_kinds includes the event's kind, but the event has
    // no delegation tag at all -> Err.
    #[tokio::test]
    async fn required_kind_without_delegation_is_rejected() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let cache = A4aCache::new();
        let limiter = test_limiter();
        let settings = a4a_settings(Some(vec![1]));
        let chain = make_chain();
        let event = make_event(chain.agent_pubkey, 1, vec![]);

        let result = check_a4a_delegation(&repo, &cache, &limiter, &event, &settings).await;
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "A4A delegation required for this kind"
        );
    }

    // kind-10001 delegation events themselves (no delegation tag, and not
    // typically listed in required_for_kinds) must pass through untouched.
    #[tokio::test]
    async fn delegation_event_itself_passes_through() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let cache = A4aCache::new();
        let limiter = test_limiter();
        let settings = a4a_settings(None);
        let chain = make_chain();
        let delegation = delegation_event(&chain, future_expiration());

        let result = check_a4a_delegation(&repo, &cache, &limiter, &delegation, &settings).await;
        assert!(result.is_ok());
    }

    // --- LookupRateLimiter (hardening item 2: cold-cache flood) ---

    /// The configured number is the RELAY-WIDE ceiling; it is split across
    /// `LOOKUP_SHARDS` budgets keyed by author. One author therefore gets
    /// `limit / LOOKUP_SHARDS` lookups per window, then blocks.
    #[test]
    fn rate_limiter_allows_up_to_budget_then_blocks() {
        let limiter = LookupRateLimiter::new(3 * LOOKUP_SHARDS as u32);
        let who = "aa".repeat(32);
        assert!(limiter.allow(&who));
        assert!(limiter.allow(&who));
        assert!(limiter.allow(&who));
        assert!(
            !limiter.allow(&who),
            "4th lookup within the same window must be blocked"
        );
    }

    /// After the one-second window elapses, the budget must replenish --
    /// this is what lets legitimate traffic recover once a flood subsides.
    #[test]
    fn rate_limiter_recovers_after_window_elapses() {
        let limiter = LookupRateLimiter::new(3 * LOOKUP_SHARDS as u32);
        let who = "aa".repeat(32);
        for _ in 0..3 {
            assert!(limiter.allow(&who));
        }
        assert!(!limiter.allow(&who));

        std::thread::sleep(Duration::from_millis(1100));

        assert!(
            limiter.allow(&who),
            "budget should have replenished in a new window"
        );
    }

    /// `0` must not mean "unlimited" (that would defeat the point of the
    /// setting) nor "always blocked" (a foot-gun for a misconfigured
    /// relay) -- it falls back to the built-in default rate.
    #[test]
    fn rate_limiter_zero_falls_back_to_default() {
        let limiter = LookupRateLimiter::new(0);
        let who = "aa".repeat(32);
        let per_shard = DEFAULT_DELEGATION_LOOKUP_RATE_PER_SEC / LOOKUP_SHARDS as u32;
        for _ in 0..per_shard {
            assert!(limiter.allow(&who));
        }
        assert!(
            !limiter.allow(&who),
            "budget should be exhausted at the default rate"
        );
    }

    /// End-to-end: a flood of events each referencing a distinct,
    /// never-cached (and nonexistent) delegation id -- the exact
    /// cold-cache-flood scenario from hardening backlog item 2 -- gets cut
    /// off by the rate limiter once its budget is exhausted, rejecting the
    /// event WITHOUT ever reaching the repo. This is what distinguishes a
    /// rate-limited rejection from an ordinary "delegation not found" one.
    #[tokio::test]
    async fn cold_cache_flood_is_rate_limited() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let cache = A4aCache::new();
        let limiter = LookupRateLimiter::new(2 * LOOKUP_SHARDS as u32);
        let settings = a4a_settings(None);
        let chain = make_chain();

        // Two distinct, never-cached, nonexistent delegation ids: both
        // consume the limiter's budget of 2 and are rejected the ordinary
        // way (repo fetch happens, finds nothing).
        for i in 0..2 {
            let event = agent_event(&chain, &format!("nonexistent-delegation-{i}"));
            let result = check_a4a_delegation(&repo, &cache, &limiter, &event, &settings).await;
            assert_eq!(
                result.unwrap_err(),
                "referenced A4A delegation not found"
            );
        }

        // A third distinct miss in the same window must be rejected by the
        // rate limiter itself, before ever reaching the repo.
        let event = agent_event(&chain, "nonexistent-delegation-2");
        let result = check_a4a_delegation(&repo, &cache, &limiter, &event, &settings).await;
        assert_eq!(
            result.unwrap_err(),
            "A4A delegation check rate limited, retry later"
        );
    }

    /// A legitimate single valid delegation must NOT be rate-limited under
    /// the default rate (`valid_delegation_is_admitted` above already uses
    /// `test_limiter()`'s generous budget; this test additionally pins down
    /// that the actual *default* config rate -- as an operator would run it
    /// -- doesn't reject ordinary, low-volume traffic).
    #[tokio::test]
    async fn valid_delegation_not_rate_limited_under_default_rate() {
        let repo: Arc<dyn NostrRepo> = Arc::new(test_repo().await);
        let cache = A4aCache::new();
        let limiter = LookupRateLimiter::new(DEFAULT_DELEGATION_LOOKUP_RATE_PER_SEC);
        let settings = a4a_settings(None);
        let chain = make_chain();
        let delegation = delegation_event(&chain, future_expiration());
        repo.write_event(&delegation).await.unwrap();
        let event = agent_event(&chain, &delegation.id);

        let result = check_a4a_delegation(&repo, &cache, &limiter, &event, &settings).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    // --- A4aCache eviction (hardening item 1) ---

    /// Inserting past the cap, with every entry already expired, must sweep
    /// the expired entries back out -- the map stays bounded rather than
    /// growing forever, which is exactly the unbounded-growth scenario an
    /// attacker publishing many one-off delegation references would hit.
    /// Verdict TTL used wall time only. Moving the system clock backward, manually or
    /// through a large NTP correction, pushed `expires_at` farther into the future and
    /// kept a cached valid verdict alive beyond its nominal lifetime precisely while the
    /// node clock was wrong (finding 70). A monotonic deadline prevents this: an entry
    /// with distant wall time but an expired monotonic deadline is dead.
    #[test]
    fn cache_verdict_dies_by_monotonic_deadline_even_if_wall_clock_says_otherwise() {
        let cache = A4aCache::new();
        let far_future = unix_time() + 3600;
        let already_passed = std::time::Instant::now() - std::time::Duration::from_secs(1);
        cache.insert_with_deadline("deleg", "pk", true, far_future, already_passed);
        assert_eq!(cache.get("deleg", "pk"), None, "monotonic deadline expired but verdict survived");
        // Positive control: a live monotonic deadline retains the verdict.
        let alive = std::time::Instant::now() + std::time::Duration::from_secs(60);
        cache.insert_with_deadline("deleg2", "pk", true, far_future, alive);
        assert_eq!(cache.get("deleg2", "pk"), Some(true));
    }

    #[test]
    fn cache_sweeps_expired_entries_past_cap() {
        let cap = 10;
        let cache = A4aCache::with_capacity_for_test(cap);
        let already_expired = unix_time().saturating_sub(1);

        for i in 0..(cap * 3) {
            cache.insert(&format!("deleg-{i}"), &format!("pk-{i}"), true, already_expired);
        }

        assert!(
            cache.len() <= cap,
            "cache should have swept expired entries back under the cap, got len={}",
            cache.len()
        );
    }

    /// Even when entries are all still valid (not expired), the cache must
    /// never exceed its hard cap -- the eviction backstop drains arbitrary
    /// entries once the expiry sweep alone can't bring it under the limit.
    #[test]
    fn cache_size_bounded_by_hard_cap_even_when_unexpired() {
        let cap = 10;
        let cache = A4aCache::with_capacity_for_test(cap);
        let far_future = unix_time() + 3600;

        for i in 0..(cap * 5) {
            cache.insert(&format!("deleg-{i}"), &format!("pk-{i}"), true, far_future);
        }

        assert!(
            cache.len() <= cap,
            "cache must never grow past its hard cap, got len={}",
            cache.len()
        );
    }

    /// A cache that never crosses the cap keeps every entry -- eviction
    /// must not be triggered spuriously below the threshold.
    #[test]
    fn cache_keeps_entries_under_cap() {
        let cap = 10;
        let cache = A4aCache::with_capacity_for_test(cap);
        let far_future = unix_time() + 3600;

        for i in 0..(cap - 1) {
            cache.insert(&format!("deleg-{i}"), &format!("pk-{i}"), true, far_future);
        }

        assert_eq!(cache.len(), cap - 1);
    }
}
