//! Event persistence and querying
//use crate::config::SETTINGS;
use crate::config::Settings;
use crate::db::QueryResult;
use crate::error::{Error::SqlError, Result};
use crate::event::Event;
use crate::nip05::{Nip05Name, VerificationRecord};
use crate::repo::sqlite_migration::{upgrade_db, STARTUP_SQL};
use crate::server::NostrMetrics;
use crate::subscription::{ReqFilter, Subscription, TagOperand};
use crate::utils::{is_hex, unix_time};
use async_trait::async_trait;
use hex;
use itertools::Itertools;
use r2d2;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;
use rusqlite::types::ToSql;
use rusqlite::OpenFlags;
use rusqlite::OptionalExtension;
use std::fmt::Write as _;
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::time::Instant;
use tokio::sync::{Mutex, MutexGuard, Semaphore};
use tokio::task;
use tracing::{debug, info, trace, warn};

use crate::repo::{now_jitter, NostrRepo};

pub type SqlitePool = r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>;
pub type PooledConnection = r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>;
pub const DB_FILE: &str = "nostr.db";

fn sqlite_trace(event: rusqlite::trace::TraceEvent<'_>) {
    if let rusqlite::trace::TraceEvent::Stmt(_, sql) = event {
        trace!("SQL trace: {:?}", sql);
    }
}

fn history_sql() -> String {
    // Include timestamps explicitly: they are protected by author, not kind.
    let kinds = PROTECTED_KINDS.iter().copied()
        .chain(std::iter::once(crate::a4a_delegation::A4A_KIND_TIMESTAMP))
        .map(|k| k.to_string()).collect::<Vec<_>>().join(",");
    let max_event = crate::repo::MAX_HISTORY_PAGE_BYTES - 320;
    // octet_length reads the stored byte count without loading overflow pages.
    // length(CAST(... AS BLOB)) would first allocate the entire TEXT value.
    format!(
        "SELECT first_seen, octet_length(content), \
         CASE WHEN octet_length(content) <= {max_event} THEN content ELSE NULL END \
         FROM event INDEXED BY event_first_seen_index \
         WHERE kind IN ({kinds}) AND hidden!=TRUE \
         AND (first_seen, event_hash) > (?, ?) AND first_seen < ? \
         ORDER BY first_seen, event_hash LIMIT ?"
    )
}

fn inbox_sql() -> String {
    let max_event = crate::repo::MAX_HISTORY_PAGE_BYTES - 320;
    // Start with the recipient's indexed event IDs, not global receipt history.
    // Sort only candidate metadata; the outer scalar lookup defers JSON loading
    // until after LIMIT. Work still depends on this recipient's own history.
    // NOT INDEXED still allows rowid lookups, but excludes global kind/receipt scans.
    format!(
        "SELECT page.first_seen, page.content_bytes, \
         CASE WHEN page.content_bytes <= {max_event} \
              THEN (SELECT content FROM event WHERE id=page.id) ELSE NULL END \
         FROM (SELECT id, first_seen, event_hash, octet_length(content) AS content_bytes \
               FROM event NOT INDEXED \
               WHERE id IN (SELECT event_id FROM tag INDEXED BY tag_name_value_index \
                            WHERE name='p' AND value=?5) \
               AND kind IN (1059,31033) AND hidden!=TRUE \
               AND (first_seen, event_hash) > (?1, ?2) AND first_seen < ?3 \
               AND (expires_at IS NULL OR expires_at > ?4) \
               ORDER BY first_seen, event_hash LIMIT ?6) AS page"
    )
}

const INBOX_VM_STEP_BUDGET: usize = 1_000_000;
const INBOX_PROGRESS_INTERVAL: i32 = 1000;

// IN and ORDER BY can do substantial work before yielding even the first row.
// A native progress hook bounds that work, including an empty end-cursor query.
// Remove it before returning the pooled connection to unrelated/WS readers.
struct InboxWorkBudget<'a>(&'a rusqlite::Connection);

impl<'a> InboxWorkBudget<'a> {
    fn install(conn: &'a rusqlite::Connection) -> Result<Self> {
        let mut remaining = INBOX_VM_STEP_BUDGET / INBOX_PROGRESS_INTERVAL as usize;
        conn.progress_handler(INBOX_PROGRESS_INTERVAL, Some(move || {
            remaining = remaining.saturating_sub(1);
            remaining == 0
        }))?;
        Ok(Self(conn))
    }
}

impl Drop for InboxWorkBudget<'_> {
    fn drop(&mut self) {
        // This guard never transfers connection ownership, so check_owned succeeds.
        let _ = self.0.progress_handler(0, None::<fn() -> bool>);
    }
}

#[derive(Clone)]
pub struct SqliteRepo {
    /// Metrics
    metrics: NostrMetrics,
    /// Pool for reading events and NIP-05 status
    read_pool: SqlitePool,
    /// Pool for writing events and NIP-05 verification
    write_pool: SqlitePool,
    /// Pool for performing checkpoints/optimization
    maint_pool: SqlitePool,
    /// Point lookups on the WRITER path (`get_event_by_id`, `get_a4a_addressable`):
    /// delegation checks on cache miss and cache invalidation on deletion or revocation.
    ///
    /// Separate from `read_pool`, which subscriptions can exhaust. Eight broad REQs held
    /// every reader connection, making the writer and all publications wait for the
    /// 30-second `connection_timeout`. Moving `get` into `spawn_blocking` stopped blocking
    /// the executor thread but not the wait (finding 66; independent measurement: a
    /// 3-second task timeout versus 30 seconds waiting for the pool). Subscriptions never
    /// use this pool, so they cannot occupy it. Cost: up to two `cache_size_mb` connections.
    lookup_pool: SqlitePool,
    /// Flag to indicate a checkpoint is underway
    checkpoint_in_progress: Arc<Mutex<u64>>,
    /// Flag to limit writer concurrency
    write_in_progress: Arc<Mutex<u64>>,
    /// Semaphore for readers to acquire blocking threads
    reader_threads_ready: Arc<Semaphore>,
    /// Global and per-kind retention periods (see `delete_aged`).
    persist_days: Option<usize>,
    kind_persist_days: std::collections::HashMap<u64, usize>,
    max_events_per_author: Option<usize>,
    /// Database-size ceiling (see `enforce_size_budget`).
    max_db_bytes: Option<u64>,
    /// Current and retired time-notary keys as raw bytes. Only their kind-1040 timestamps
    /// are protected from deletion; foreign timestamps stay disposable on every node.
    /// Otherwise declaring a notary would retroactively make old foreign junk undeletable
    /// (finding 124).
    notary_keys: Vec<Vec<u8>>,
    /// Threshold for one-time database rebuild when enabling incremental vacuum.
    vacuum_max_bytes: u64,
}

impl SqliteRepo {
    // build all the pools needed
    #[must_use]
    pub fn new(settings: &Settings, metrics: NostrMetrics) -> SqliteRepo {
        let write_pool = build_pool(
            "writer",
            settings,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            0,
            2,
            false,
        );
        let maint_pool = build_pool(
            "maintenance",
            settings,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            0,
            2,
            true,
        );
        let read_pool = build_pool(
            "reader",
            settings,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            settings.database.min_conn,
            settings.database.max_conn,
            true,
        );
        let lookup_pool = build_pool(
            "lookup",
            settings,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            0,
            2,
            true,
        );

        // this is used to block new reads during critical checkpoints
        let checkpoint_in_progress = Arc::new(Mutex::new(0));
        // SQLite can only effectively write single threaded, so don't
        // block multiple worker threads unnecessarily.
        let write_in_progress = Arc::new(Mutex::new(0));
        // configure the number of worker threads that can be spawned
        // to match the number of database reader connections.
        let max_conn = settings.database.max_conn as usize;
        let reader_threads_ready = Arc::new(Semaphore::new(max_conn));
        SqliteRepo {
            metrics,
            read_pool,
            write_pool,
            maint_pool,
            lookup_pool,
            checkpoint_in_progress,
            write_in_progress,
            reader_threads_ready,
            persist_days: settings.retention.persist_days,
            kind_persist_days: settings
                .retention
                .kind_persist_days
                .clone()
                .unwrap_or_default(),
            max_events_per_author: settings.retention.max_events_per_author,
            max_db_bytes: settings.retention.max_db_bytes,
            notary_keys: settings
                .a4a
                .notary_pubkey
                .iter()
                .cloned()
                .chain(settings.a4a.notary_retired.iter().map(|r| r.pubkey.clone()))
                .filter_map(|k| hex::decode(k).ok())
                .collect(),
            vacuum_max_bytes: settings.database.vacuum_max_bytes,
        }
    }

    /// Test-only escape hatch: expose the write pool so tests in other
    /// modules (e.g. `crate::db::tests`) can reach into the database
    /// directly to simulate conditions (like a delegation event becoming
    /// unavailable) that aren't reachable through the public `NostrRepo`
    /// API.
    #[cfg(test)]
    pub(crate) fn write_pool(&self) -> SqlitePool {
        self.write_pool.clone()
    }

    /// `Ok(true)` a row exists, `Ok(false)` the query ran and found nothing,
    /// `Err` the query did not run. The third must not look like the second.
    fn row_means_present(row: std::result::Result<i64, rusqlite::Error>) -> Result<bool> {
        match row {
            Ok(_) => Ok(true),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Persist an event to the database, returning rows added.
    pub fn persist_event(conn: &mut PooledConnection, e: &Event) -> Result<u64> {
        // This used to run `pragma auto_vacuum = FULL` on EVERY event write. It had no
        // effect: SQLite changes auto_vacuum only on an empty database or through VACUUM,
        // and the database is already populated here (production measurement on
        // 2026-08-29: auto_vacuum = 0). Configure the mode once at startup in
        // `ensure_incremental_vacuum`.

        // start transaction
        let tx = conn.transaction()?;
        // get relevant fields from event and convert to blobs.
        let id_blob = hex::decode(&e.id).ok();
        let pubkey_blob: Option<Vec<u8>> = hex::decode(&e.pubkey).ok();
        let delegator_blob: Option<Vec<u8>> =
            e.delegated_by.as_ref().and_then(|d| hex::decode(d).ok());
        let event_str = serde_json::to_string(&e).ok();
        // check for replaceable events that would hide this one; we won't even attempt to insert these.
        if e.is_replaceable() {
            let repl_count = tx.query_row(
                "SELECT e.id FROM event e INDEXED BY author_index WHERE e.author=? AND e.kind=? AND e.created_at >= ? LIMIT 1;",
                params![pubkey_blob, crate::utils::u64_to_sql(e.kind), crate::utils::u64_to_sql(e.created_at)], |row| row.get::<usize, i64>(0));
            // `QueryReturnedNoRows` means no newer copy. Any other error means
            // the question was not answered. `.ok().is_some()` treated that as
            // "no newer copy" and inserted the event.
            if Self::row_means_present(repl_count)? {
                return Ok(0);
            }
        }
        // check for parameterized replaceable events that would be hidden; don't insert these either.
        if let Some(d_tag) = e.distinct_param() {
            let repl_count = tx.query_row(
                "SELECT e.id FROM event e LEFT JOIN tag t ON e.id=t.event_id WHERE e.author=? AND e.kind=? AND t.name='d' AND t.value=? AND e.created_at >= ? LIMIT 1;",
                params![pubkey_blob, crate::utils::u64_to_sql(e.kind), d_tag, crate::utils::u64_to_sql(e.created_at)],|row| row.get::<usize, i64>(0));
            // if any rows were returned, then some newer event with
            // the same author/kind/tag value exist, and we can ignore
            // this event.
            if Self::row_means_present(repl_count)? {
                return Ok(0);
            }
        }
        // ignore if the event hash is a duplicate.
        let mut ins_count = tx.execute(
            "INSERT OR IGNORE INTO event (event_hash, created_at, expires_at, kind, author, delegated_by, content, first_seen, hidden) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, strftime('%s','now'), FALSE);",
            params![id_blob, crate::utils::u64_to_sql(e.created_at), e.expiration().map(crate::utils::u64_to_sql), crate::utils::u64_to_sql(e.kind), pubkey_blob, delegator_blob, event_str]
        )? as u64;
        if ins_count == 0 {
            // if the event was a duplicate, no need to insert event or
            // pubkey references.
            tx.rollback().ok();
            return Ok(ins_count);
        }
        // remember primary key of the event most recently inserted.
        let ev_id = tx.last_insert_rowid();
        // add all tags to the tag table, up to MAX_INDEXED_TAGS_PER_EVENT
        // -- but ONLY the cap applies to multi-char tag names. Single-char
        // tags (d/e/p/a/...) are ALWAYS indexed regardless of position or
        // cap, because NIP-01 thread/mention search and parameterized-
        // replaceable dedup (queries on t.name='d') depend on them; an
        // event with >100 tags whose d/e/p tags land after position 100
        // must not lose that indexing. The cap only bounds the F2
        // multi-char discovery tags, which are the actual DB-bloat vector
        // (see MAX_INDEXED_TAGS_PER_EVENT's doc comment). The full tag list
        // is still kept in the event's stored JSON regardless.
        let mut indexed_multi_char_tags = 0usize;
        for tag in &e.tags {
            // ensure we have 2 values.
            if tag.len() >= 2 {
                let tagname = &tag[0];
                let tagval = &tag[1];
                if tagname.is_empty() {
                    continue;
                }
                let is_single_char = crate::event::single_char_tagname(tagname).is_some();
                if !is_single_char {
                    if indexed_multi_char_tags >= crate::event::MAX_INDEXED_TAGS_PER_EVENT {
                        continue;
                    }
                    indexed_multi_char_tags += 1;
                }
                tx.execute(
                    "INSERT OR IGNORE INTO tag (event_id, name, value, kind, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![ev_id, &tagname, &tagval, crate::utils::u64_to_sql(e.kind), crate::utils::u64_to_sql(e.created_at)],
                )?;
            }
        }
        // if this event is replaceable update, remove other replaceable
        // event with the same kind from the same author that was issued
        // earlier than this.
        if e.is_replaceable() {
            let author = hex::decode(&e.pubkey).ok();
            // this is a backwards check - hide any events that were older.
            let update_count = tx.execute(
                "DELETE FROM event WHERE kind=? and author=? and id NOT IN (SELECT id FROM event INDEXED BY author_kind_index WHERE kind=? AND author=? ORDER BY created_at DESC LIMIT 1)",
                params![crate::utils::u64_to_sql(e.kind), author, crate::utils::u64_to_sql(e.kind), author],
            )?;
            if update_count > 0 {
                info!(
                    "removed {} older replaceable kind {} events for author: {:?}",
                    update_count,
                    e.kind,
                    e.get_author_prefix()
                );
            }
        }
        // if this event is parameterized replaceable, remove other events.
        if let Some(d_tag) = e.distinct_param() {
            // Archive a kind-31000 delegation before replacement. Old agent events refer
            // to it by id, and without a copy even a timestamp cannot prove whether the
            // agent was authorized then (finding 65 / F4). The archive is a separate table,
            // invisible to intake and coordinate lookup.
            if e.kind == crate::a4a_delegation::A4A_KIND_DELEGATION {
                tx.execute(
                    "INSERT OR IGNORE INTO delegation_archive(event_hash, content, replaced_at) \
                     SELECT DISTINCT e.event_hash, e.content, ? FROM event e LEFT JOIN tag t ON e.id=t.event_id \
                     WHERE e.kind=? AND e.author=? AND t.name='d' AND t.value=? \
                     ORDER BY t.created_at DESC LIMIT -1 OFFSET 1;",
                    params![crate::utils::u64_to_sql(crate::utils::unix_time()), crate::utils::u64_to_sql(e.kind), pubkey_blob, d_tag],
                )?;
            }
            let update_count = tx.execute(
                "DELETE FROM event WHERE kind=? AND author=? AND id IN (SELECT DISTINCT e.id FROM event e LEFT JOIN tag t ON e.id=t.event_id WHERE e.kind=? AND e.author=? AND t.name='d' AND t.value=? ORDER BY t.created_at DESC LIMIT -1 OFFSET 1);",
                params![crate::utils::u64_to_sql(e.kind), pubkey_blob, crate::utils::u64_to_sql(e.kind), pubkey_blob, d_tag])?;
            if update_count > 0 {
                info!(
                    "removed {} older parameterized replaceable kind {} events for author: {:?}",
                    update_count,
                    e.kind,
                    e.get_author_prefix()
                );
            }
        }
        // if this event is a deletion, hide the referenced events from the same author.
        if e.kind == 5 {
            let event_candidates = e.tag_values_by_name("e");
            // first parameter will be author
            let mut params: Vec<Box<dyn ToSql>> = vec![Box::new(hex::decode(&e.pubkey)?)];
            event_candidates
                .iter()
                .filter(|x| is_hex(x) && x.len() == 64)
                .filter_map(|x| hex::decode(x).ok())
                .for_each(|x| params.push(Box::new(x)));
            let query = format!(
                "UPDATE event SET hidden=TRUE WHERE kind!=5 AND author=? AND event_hash IN ({})",
                repeat_vars(params.len() - 1)
            );
            let mut stmt = tx.prepare(&query)?;
            let update_count = stmt.execute(rusqlite::params_from_iter(params))?;
            info!(
                "hid {} deleted events for author {:?}",
                update_count,
                e.get_author_prefix()
            );
        } else {
            // check if a deletion has already been recorded for this event.
            // Only relevant for non-deletion events
            let del_count = tx.query_row(
                "SELECT e.id FROM event e WHERE e.author=? AND e.id IN (SELECT t.event_id FROM tag t WHERE t.name='e' AND t.kind=5 AND t.value=?) LIMIT 1;",
                params![pubkey_blob, e.id], |row| row.get::<usize, i64>(0));
            // A SQL error is not "no deletion exists". Treating it as absence
            // saved the event and broadcast it after the author had deleted it,
            // or when the deletion table could not be read.
            if Self::row_means_present(del_count)? {
                // a deletion already existed, mark original event as hidden.
                info!(
                    "hid event: {:?} due to existing deletion by author: {:?}",
                    e.get_event_id_prefix(),
                    e.get_author_prefix()
                );
                let _update_count =
                    tx.execute("UPDATE event SET hidden=TRUE WHERE id=?", params![ev_id])?;
                // event was deleted, so let caller know nothing new
                // arrived, preventing this from being sent to active
                // subscriptions
                ins_count = 0;
            }
        }
        tx.commit()?;
        Ok(ins_count)
    }

    /// One inbox page AS OF a supplied clock sample.
    ///
    /// Extracted from `inbox_after_id` for testability. When the sample was read inside,
    /// one clock read and two were indistinguishable because both produced nearly the same
    /// current time. The parameter makes "expired at the sealed instant" observable.
    /// Production always passes a sample captured while holding the lock.
    async fn inbox_page_at(&self, recipient: &str, after: u64, after_id: &str,
                           limit: usize, before: u64) -> Result<Vec<(u64, Event)>> {
        let pool = self.read_pool.clone();
        let recipient = recipient.to_owned();
        let after_id = hex::decode(after_id)?;
        let limit = limit.clamp(1, 5000) as i64;
        let rows = tokio::task::spawn_blocking(move || -> Result<Vec<(u64, String)>> {
            let conn = pool.get()?;
            let _budget = InboxWorkBudget::install(&conn)?;
            let mut stmt = conn.prepare_cached(&inbox_sql())?;
            // ONE sample for the entire operation: both intake upper bound and expiration
            // filtering. A second clock read here produced the reviewer's counterexample.
            let mut rows = stmt.query(params![crate::utils::u64_to_sql(after), after_id,
                crate::utils::u64_to_sql(before), crate::utils::u64_to_sql(before),
                recipient, limit])?;
            let mut out = Vec::new();
            // Covers the recipient, page envelope, cursor and row wrappers.
            let mut bytes = 256usize;
            while let Some(row) = rows.next()? {
                let size = usize::try_from(row.get::<_, i64>(1)?).unwrap_or(usize::MAX);
                let cost = size.saturating_add(64);
                if bytes.saturating_add(cost) > crate::repo::MAX_HISTORY_PAGE_BYTES {
                    if out.is_empty() {
                        return Err(crate::error::Error::HistoryEventTooLarge);
                    }
                    break;
                }
                out.push((row.get::<_, i64>(0)?.max(0) as u64, row.get::<_, String>(2)?));
                bytes += cost;
            }
            Ok(out)
        }).await??;
        rows.into_iter().map(|(first_seen, content)| -> Result<(u64, Event)> {
            let mut event: Event = serde_json::from_str(&content)?;
            event.update_delegation();
            Ok((first_seen, event))
        }).collect()
    }
}

/// Tell the subscriber the query ended.
///
/// `None` is EOSE: the stored set was read. `Some` is NIP-01 CLOSED: the
/// read failed or was aborted, so an empty EOSE would be a lie. A failed
/// send means the client is already gone.
fn send_query_terminal(
    tx: &tokio::sync::mpsc::Sender<QueryResult>,
    sub_id: &str,
    failure: Option<&str>,
) {
    let event = match failure {
        None => "EOSE".to_owned(),
        Some(reason) => format!("CLOSED {reason}"),
    };
    if tx
        .blocking_send(QueryResult {
            sub_id: sub_id.to_owned(),
            event,
        })
        .is_err()
    {
        debug!("query terminal was not delivered; client is gone (sub: {sub_id})");
    }
}

#[async_trait]
impl NostrRepo for SqliteRepo {
    async fn start(&self) -> Result<()> {
        db_checkpoint_task(
            self.maint_pool.clone(),
            Duration::from_secs(60),
            self.write_in_progress.clone(),
            self.checkpoint_in_progress.clone(),
        )
        .await?;
        // Configure space reclamation ONCE at startup before cleanup begins; otherwise
        // the first cleanup deletes events without returning a byte.
        // A missing maintenance connection used to skip vacuum and still
        // return Ok, so `/v1/health` said ready. `start()`'s caller stores
        // the error in NOT_READY. The size-threshold skip inside
        // `ensure_incremental_vacuum` stays Ok: that path logs and asks the
        // operator to vacuum by hand.
        let mut conn = self.maint_pool.get().map_err(|e| {
            warn!(
                "maintenance connection unavailable; incremental vacuum was not configured: {:?}",
                e
            );
            crate::error::Error::DatabasePoolError(e)
        })?;
        if let Err(e) = ensure_incremental_vacuum(&mut conn, self.vacuum_max_bytes) {
            warn!("could not enable incremental vacuum: {:?}", e);
            return Err(e);
        }
        cleanup_expired(
            self.maint_pool.clone(),
            Duration::from_secs(600),
            self.write_in_progress.clone(),
            self.persist_days,
            self.kind_persist_days.clone(),
            self.max_events_per_author,
            self.max_db_bytes,
            self.notary_keys.clone(),
        )
        .await
    }

    async fn migrate_up(&self) -> Result<usize> {
        let _write_guard = self.write_in_progress.lock().await;
        let mut conn = self.write_pool.get()?;
        task::spawn_blocking(move || upgrade_db(&mut conn)).await?
    }
    /// Persist event to database
    async fn write_event(&self, e: &Event) -> Result<u64> {
        let start = Instant::now();
        let max_write_attempts = 10;
        let mut attempts = 0;
        let _write_guard = self.write_in_progress.lock().await;
        // spawn a blocking thread
        //let mut conn = self.write_pool.get()?;
        let pool = self.write_pool.clone();
        let e = e.clone();
        let event_count = task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            // this could fail because the database was busy; try
            // multiple times before giving up.
            loop {
                attempts += 1;
                let wr = SqliteRepo::persist_event(&mut conn, &e);
                match wr {
                    Err(SqlError(rusqlite::Error::SqliteFailure(e, _))) => {
                        // this basically means that NIP-05 or another
                        // writer was using the database between us
                        // reading and promoting the connection to a
                        // write lock.
                        info!(
                            "event write failed, DB locked (attempt: {}); sqlite err: {}",
                            attempts, e.extended_code
                        );
                    }
                    _ => {
                        return wr;
                    }
                }
                if attempts >= max_write_attempts {
                    return wr;
                }
            }
        })
        .await?;
        self.metrics
            .write_events
            .observe(start.elapsed().as_secs_f64());
        event_count
    }

    /// Perform a database query using a subscription.
    ///
    /// The [`Subscription`] is converted into a SQL query.  Each result
    /// is published on the `query_tx` channel as it is returned.  If a
    /// message becomes available on the `abandon_query_rx` channel, the
    /// query is immediately aborted.
    async fn query_subscription(
        &self,
        sub: Subscription,
        client_id: String,
        query_tx: tokio::sync::mpsc::Sender<QueryResult>,
        mut abandon_query_rx: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<()> {
        let pre_spawn_start = Instant::now();
        // if we let every request spawn a thread, we'll exhaust the
        // thread pool waiting for queries to finish under high load.
        // Instead, don't bother spawning threads when they will just
        // block on a database connection.
        let sem = self
            .reader_threads_ready
            .clone()
            .acquire_owned()
            .await
            .unwrap();
        let self = self.clone();
        let metrics = self.metrics.clone();
        task::spawn_blocking(move || {
            {
                // if we are waiting on a checkpoint, stop until it is complete
                let _x = self.checkpoint_in_progress.blocking_lock();
            }
            let db_queue_time = pre_spawn_start.elapsed();
            // if the queue time was very long (>5 seconds), spare the DB and abort.
            if db_queue_time > Duration::from_secs(5) {
                info!(
                    "shedding DB query load queued for {:?} (cid: {}, sub: {:?})",
                    db_queue_time, client_id, sub.id
                );
                metrics.query_aborts.with_label_values(&["loadshed"]).inc();
                send_query_terminal(
                    &query_tx,
                    &sub.id,
                    Some("error: query shed because the database was busy"),
                );
                return Ok(());
            }
            // otherwise, report queuing time if it is slow
            else if db_queue_time > Duration::from_secs(1) {
                debug!(
                    "(slow) DB query queued for {:?} (cid: {}, sub: {:?})",
                    db_queue_time, client_id, sub.id
                );
            }
            // check before getting a DB connection if the client still wants the results
            // The client already sent CLOSE or dropped the socket. EOSE or
            // CLOSED would be addressed to a subscription nobody is reading.
            // This is not the load-shed path: there the client is still waiting.
            if crate::utils::client_abandoned_query(&mut abandon_query_rx) {
                debug!(
                    "query cancelled by client (before execution) (cid: {}, sub: {:?})",
                    client_id, sub.id
                );
                return Ok(());
            }

            let start = Instant::now();
            let mut row_count: usize = 0;
            // cutoff for displaying slow queries
            let slow_cutoff = Duration::from_millis(250);
            let mut filter_count = 0;
            let mut query_failure: Option<&'static str> = None;
            // remove duplicates from the filter list.
            if let Ok(conn) = self.read_pool.get() {
                {
                    let pool_state = self.read_pool.state();
                    metrics
                        .db_connections
                        .set((pool_state.connections - pool_state.idle_connections).into());
                }
                'filters: for filter in sub.filters.iter() {
                    let filter_start = Instant::now();
                    filter_count += 1;
                    let sql_gen_elapsed = filter_start.elapsed();
                    let (q, p, idx) = query_from_filter(filter);
                    if sql_gen_elapsed > Duration::from_millis(10) {
                        debug!("SQL (slow) generated in {:?}", filter_start.elapsed());
                    }
                    // any client that doesn't cause us to generate new rows in 2
                    // seconds gets dropped.
                    let abort_cutoff = Duration::from_secs(2);
                    let mut slow_first_event;
                    let mut last_successful_send = Instant::now();
                    // execute the query.
                    // make the actual SQL query (with parameters inserted) available
                    conn.trace_v2(
                        rusqlite::trace::TraceEventCodes::SQLITE_TRACE_STMT,
                        Some(sqlite_trace),
                    );
                    // Query preparation or execution errors must NOT escape this
                    // closure through `?`. That bypassed the terminal message and
                    // left the subscription hanging (finding 71). Do not send EOSE
                    // for them: EOSE means the stored set is complete. Send CLOSED.
                    let mut stmt = match conn.prepare_cached(&q) {
                        Ok(stmt) => stmt,
                        Err(e) => {
                            warn!(
                                "query could not be prepared (cid: {}, sub: {:?}): {:?}",
                                client_id, sub.id, e
                            );
                            metrics.query_aborts.with_label_values(&["error"]).inc();
                            query_failure = Some("error: query could not be prepared");
                            break;
                        }
                    };
                    let mut event_rows = match stmt.query(rusqlite::params_from_iter(p)) {
                        Ok(rows) => rows,
                        Err(e) => {
                            warn!(
                                "query could not be started (cid: {}, sub: {:?}): {:?}",
                                client_id, sub.id, e
                            );
                            metrics.query_aborts.with_label_values(&["error"]).inc();
                            query_failure = Some("error: query could not be started");
                            break;
                        }
                    };

                    let mut first_result = true;
                    loop {
                        let row = match event_rows.next() {
                            Ok(Some(row)) => row,
                            Ok(None) => break,
                            Err(e) => {
                                warn!(
                                    "query failed while reading rows (cid: {}, sub: {:?}): {:?}",
                                    client_id, sub.id, e
                                );
                                metrics.query_aborts.with_label_values(&["error"]).inc();
                                query_failure = Some("error: query failed while reading rows");
                                break 'filters;
                            }
                        };
                        let first_event_elapsed = filter_start.elapsed();
                        slow_first_event = first_event_elapsed >= slow_cutoff;
                        if first_result {
                            debug!(
                                "first result in {:?} (cid: {}, sub: {:?}, filter: {}) [used index: {:?}]",
                                first_event_elapsed, client_id, sub.id, filter_count, idx
                            );
                            // logging for slow queries; show filter and SQL.
                            // to reduce logging; only show 1/16th of clients (leading 0)
                            if slow_first_event && client_id.starts_with('0') {
                                debug!(
                                    "filter first result in {:?} (slow): {} (cid: {}, sub: {:?})",
                                    first_event_elapsed,
                                    serde_json::to_string(&filter).unwrap_or_else(|_| "<unserializable filter>".to_owned()),
                                    client_id,
                                    sub.id
                                );
                            }
                            first_result = false;
                        }
                        // check if a checkpoint is trying to run, and abort
                        if row_count.is_multiple_of(100) {
                            {
                                if self.checkpoint_in_progress.try_lock().is_err() {
                                    // lock was held, abort this query
                                    debug!(
                                        "query aborted due to checkpoint (cid: {}, sub: {:?})",
                                        client_id, sub.id
                                    );
                                    metrics
                                        .query_aborts
                                        .with_label_values(&["checkpoint"])
                                        .inc();
                                    query_failure = Some("error: query aborted for a checkpoint");
                                    break 'filters;
                                }
                            }
                        }

                        // Client sent CLOSE or dropped. Do not send EOSE: they
                        // are not waiting. A checkpoint abort above is different
                        // because the subscription is still open.
                        if row_count.is_multiple_of(100)
                            && crate::utils::client_abandoned_query(&mut abandon_query_rx)
                        {
                            debug!(
                                "query cancelled by client (cid: {}, sub: {:?})",
                                client_id, sub.id
                            );
                            return Ok(());
                        }
                        row_count += 1;
                        let event_json: String = match row.get(0) {
                            Ok(value) => value,
                            Err(e) => {
                                warn!(
                                    "query failed while reading an event (cid: {}, sub: {:?}): {:?}",
                                    client_id, sub.id, e
                                );
                                metrics.query_aborts.with_label_values(&["error"]).inc();
                                query_failure = Some("error: query failed while reading an event");
                                break 'filters;
                            }
                        };
                        loop {
                            if query_tx.capacity() != 0 {
                                // we have capacity to add another item
                                break;
                            }
                            // the queue is full
                            trace!("db reader thread is stalled");
                            if last_successful_send + abort_cutoff < Instant::now() {
                                // the queue has been full for too long, abort
                                info!("aborting database query due to slow client (cid: {}, sub: {:?})",
                                      client_id, sub.id);
                                metrics
                                    .query_aborts
                                    .with_label_values(&["slowclient"])
                                    .inc();
                                query_failure = Some("error: query aborted because the client was too slow");
                                break 'filters;
                            }
                            // check if a checkpoint is trying to run, and abort
                            if self.checkpoint_in_progress.try_lock().is_err() {
                                // lock was held, abort this query
                                debug!(
                                    "query aborted due to checkpoint (cid: {}, sub: {:?})",
                                    client_id, sub.id
                                );
                                metrics
                                    .query_aborts
                                    .with_label_values(&["checkpoint"])
                                    .inc();
                                query_failure = Some("error: query aborted for a checkpoint");
                                break 'filters;
                            }
                            // give the queue a chance to clear before trying again
                            debug!(
                                "query thread sleeping due to full query_tx (cid: {}, sub: {:?})",
                                client_id, sub.id
                            );
                            thread::sleep(Duration::from_millis(500));
                        }
                        // Backpressure choice: blocking_send retains ownership of the
                        // query result and avoids the retry bookkeeping required by
                        // try_send.
                        query_tx
                            .blocking_send(QueryResult {
                                sub_id: sub.get_id(),
                                event: event_json,
                            })
                            .ok();
                        last_successful_send = Instant::now();
                    }
                    metrics
                        .query_db
                        .observe(filter_start.elapsed().as_secs_f64());
                    // if the filter took too much db_time, print out the JSON.
                    if filter_start.elapsed() > slow_cutoff && client_id.starts_with('0') {
                        debug!(
                            "query filter req (slow): {} (cid: {}, sub: {:?}, filter: {})",
                            serde_json::to_string(&filter).unwrap_or_else(|_| "<unserializable filter>".to_owned()),
                            client_id,
                            sub.id,
                            filter_count
                        );
                    }
                }
            } else {
                warn!("Could not get a database connection for querying");
                query_failure = Some("error: could not get a database connection");
            }
            drop(sem); // new query can begin
            debug!(
                "query completed in {:?} (cid: {}, sub: {:?}, db_time: {:?}, rows: {})",
                pre_spawn_start.elapsed(),
                client_id,
                sub.id,
                start.elapsed(),
                row_count
            );
            send_query_terminal(&query_tx, &sub.id, query_failure);
            metrics
                .query_sub
                .observe(pre_spawn_start.elapsed().as_secs_f64());
            let ok: Result<()> = Ok(());
            ok
        });
        Ok(())
    }

    /// Intake-time history (finding 86). Only protected and visible kinds; `first_seen`
    /// is the node intake second (`strftime('%s','now')` at write time).
    async fn history_after_id(&self, after: u64, after_id: &str, limit: usize) -> Result<Vec<(u64, Event)>> {
        // first_seen is assigned before COMMIT. Wait for any active event write
        // before sealing a second; later writes cannot enter the closed interval
        // while the relay clock is non-regressing. Do not hold the writer for I/O.
        let before = {
            let _guard = self.write_in_progress.lock().await;
            unix_time()
        };
        let pool = self.read_pool.clone();
        let after_id = hex::decode(after_id)?;
        let limit = limit.clamp(1, 5000) as i64;
        let rows: Vec<(u64, String)> = tokio::task::spawn_blocking(move || -> Result<Vec<(u64, String)>> {
            let conn = pool.get()?;
            let mut stmt = conn.prepare_cached(&history_sql())?;
            let mut rows = stmt.query(params![crate::utils::u64_to_sql(after), after_id,
                                              crate::utils::u64_to_sql(before), limit])?;
            let mut out = Vec::new();
            // Reserve the page envelope/cursor and each row's first_seen wrapper.
            // Check SQLite's byte length before copying any event into Rust memory.
            let mut bytes = 256usize;
            while let Some(row) = rows.next()? {
                let size = usize::try_from(row.get::<_, i64>(1)?).unwrap_or(usize::MAX);
                let cost = size.saturating_add(64);
                if bytes.saturating_add(cost) > crate::repo::MAX_HISTORY_PAGE_BYTES {
                    if out.is_empty() {
                        return Err(crate::error::Error::HistoryEventTooLarge);
                    }
                    break;
                }
                out.push((row.get::<_, i64>(0)?.max(0) as u64, row.get::<_, String>(2)?));
                bytes += cost;
            }
            Ok(out)
        })
        .await??;
        rows.into_iter()
            .map(|(first_seen, content)| -> Result<(u64, Event)> {
                let mut event: Event = serde_json::from_str(&content)?;
                event.update_delegation();
                Ok((first_seen, event))
            })
            .collect()
    }

    async fn inbox_after_id(&self, recipient: &str, after: u64, after_id: &str,
                            limit: usize) -> Result<Vec<(u64, Event)>> {
        // The same commit fence as history: never advance into a reception
        // second that an in-flight event write can still enter.
        let before = {
            let _guard = self.write_in_progress.lock().await;
            unix_time()
        };
        self.inbox_page_at(recipient, after, after_id, limit, before).await
    }

    /// NIP-33-replaced kind-31000 delegation from the archive, by id.
    async fn get_archived_delegation(&self, id: &str) -> Result<Option<Event>> {
        let id_blob = hex::decode(id).ok();
        let pool = self.lookup_pool.clone();
        let event_json: Option<String> = tokio::task::spawn_blocking(move || -> Result<Option<String>> {
            let conn = pool.get()?;
            let mut stmt = conn.prepare_cached(
                "SELECT content FROM delegation_archive WHERE event_hash=?",
            )?;
            Ok(stmt.query_row(params![id_blob], |row| row.get(0)).optional()?)
        })
        .await??;
        event_json
            .map(|c| -> Result<Event> {
                let mut event: Event = serde_json::from_str(&c)?;
                event.update_delegation();
                Ok(event)
            })
            .transpose()
    }

    /// Fetch a single event by its (hex-encoded) id.
    async fn get_event_by_id(&self, id: &str) -> Result<Option<Event>> {
        let id_blob = hex::decode(id).ok();
        // Acquire the connection INSIDE the blocking thread. Outside it, `Pool::get()`
        // blocked the Tokio thread until `connection_timeout` (r2d2 defaults to 30 seconds
        // and `build_pool` does not override it), along with every task on that thread.
        //
        // What this does NOT solve: this writer-side path checks delegation on cache miss,
        // and the writer still awaits the JoinHandle while all readers are occupied, for
        // up to the same 30 seconds. Review measured the old form blocking the executor
        // entirely (a 3-second timeout could not run; pool failure arrived at 30.000 s),
        // while the new form waits in a task and leaves others alive. Reader-induced
        // writer delay remains an open pool concern. Upstream acquires inside
        // `spawn_blocking` for `write_event` and `query_subscription`, but outside it for
        // seven service queries.
        let pool = self.lookup_pool.clone();
        let event_json: Option<String> = tokio::task::spawn_blocking(move || -> Result<Option<String>> {
            let conn = pool.get()?;
            let mut stmt = conn.prepare_cached(
                "SELECT e.content FROM event e INDEXED BY event_hash_index WHERE event_hash=? AND hidden!=TRUE",
            )?;
            Ok(stmt
                .query_row(params![id_blob], |row| row.get(0))
                .optional()?)
        })
        .await??;
        event_json
            .map(|c| -> Result<Event> {
                let mut event: Event = serde_json::from_str(&c)?;
                // tags are preserved, but `delegated_by` is a transient
                // field (`#[serde(skip)]`) that must be recomputed.
                event.update_delegation();
                Ok(event)
            })
            .transpose()
    }

    async fn get_a4a_addressable(
        &self,
        kind: u64,
        d_value: &str,
        author: &str,
    ) -> Result<Option<Event>> {
        let pubkey_blob: Option<Vec<u8>> = hex::decode(author).ok();
        let d_value = d_value.to_owned();
        // See `get_event_by_id`: acquire inside the blocking thread so the writer does not
        // wait for readers on an async executor thread.
        let pool = self.lookup_pool.clone();
        let event_json: Option<String> = tokio::task::spawn_blocking(move || -> Result<Option<String>> {
            let conn = pool.get()?;
            let mut stmt = conn.prepare_cached(
                "SELECT e.content FROM event e LEFT JOIN tag t ON e.id=t.event_id WHERE e.author=? AND e.kind=? AND t.name='d' AND t.value=? AND e.hidden!=TRUE LIMIT 1;",
            )?;
            Ok(stmt
                .query_row(
                    params![
                        pubkey_blob,
                        crate::utils::u64_to_sql(kind),
                        d_value
                    ],
                    |row| row.get(0),
                )
                .optional()?)
        })
        .await??;
        event_json
            .map(|c| -> Result<Event> {
                let mut event: Event = serde_json::from_str(&c)?;
                // tags are preserved, but `delegated_by` is a transient
                // field (`#[serde(skip)]`) that must be recomputed.
                event.update_delegation();
                Ok(event)
            })
            .transpose()
    }

    /// Perform normal maintenance
    async fn optimize_db(&self) -> Result<()> {
        let conn = self.write_pool.get()?;
        task::spawn_blocking(move || {
            let start = Instant::now();
            conn.execute_batch("PRAGMA optimize;").ok();
            info!("optimize ran in {:?}", start.elapsed());
        })
        .await?;
        Ok(())
    }

    /// Create a new verification record connected to a specific event
    async fn create_verification_record(&self, event_id: &str, name: &str) -> Result<()> {
        let e = hex::decode(event_id).ok();
        let n = name.to_owned();
        let mut conn = self.write_pool.get()?;
        let _write_guard = self.write_in_progress.lock().await;
        tokio::task::spawn_blocking(move || {
            let tx = conn.transaction()?;
            {
                // if we create a /new/ one, we should get rid of any old ones.  or group the new ones by name and only consider the latest.
                let query = "INSERT INTO user_verification (metadata_event, name, verified_at) VALUES ((SELECT id from event WHERE event_hash=?), ?, strftime('%s','now'));";
                let mut stmt = tx.prepare(query)?;
                stmt.execute(params![e, n])?;
                // get the row ID
                let v_id = tx.last_insert_rowid();
                // delete everything else by this name
                let del_query = "DELETE FROM user_verification WHERE name = ? AND id != ?;";
                let mut del_stmt = tx.prepare(del_query)?;
                let count = del_stmt.execute(params![n,v_id])?;
                if count > 0 {
                    info!("removed {} old verification records for ({:?})", count, n);
                }
            }
            tx.commit()?;
            info!("saved new verification record for ({:?})", n);
            let ok: Result<()> = Ok(());
            ok
        }).await?
    }

    /// Update verification timestamp
    async fn update_verification_timestamp(&self, id: u64) -> Result<()> {
        let mut conn = self.write_pool.get()?;
        let _write_guard = self.write_in_progress.lock().await;
        tokio::task::spawn_blocking(move || {
            // add some jitter to the verification to prevent everything from stacking up together.
            let verif_time = now_jitter(600);
            let tx = conn.transaction()?;
            {
                // update verification time and reset any failure count
                let query =
                    "UPDATE user_verification SET verified_at=?, failure_count=0 WHERE id=?";
                let mut stmt = tx.prepare(query)?;
                stmt.execute(params![crate::utils::u64_to_sql(verif_time), crate::utils::u64_to_sql(id)])?;
            }
            tx.commit()?;
            let ok: Result<()> = Ok(());
            ok
        })
        .await?
    }

    /// Update verification record as failed
    async fn fail_verification(&self, id: u64) -> Result<()> {
        let mut conn = self.write_pool.get()?;
        let _write_guard = self.write_in_progress.lock().await;
        tokio::task::spawn_blocking(move || {
            // add some jitter to the verification to prevent everything from stacking up together.
            let fail_time = now_jitter(600);
            let tx = conn.transaction()?;
            {
                let query = "UPDATE user_verification SET failed_at=?, failure_count=failure_count+1 WHERE id=?";
                let mut stmt = tx.prepare(query)?;
                stmt.execute(params![crate::utils::u64_to_sql(fail_time), crate::utils::u64_to_sql(id)])?;
            }
            tx.commit()?;
            let ok: Result<()> = Ok(());
            ok
        })
            .await?
    }

    /// Delete verification record
    async fn delete_verification(&self, id: u64) -> Result<()> {
        let mut conn = self.write_pool.get()?;
        let _write_guard = self.write_in_progress.lock().await;
        tokio::task::spawn_blocking(move || {
            let tx = conn.transaction()?;
            {
                let query = "DELETE FROM user_verification WHERE id=?;";
                let mut stmt = tx.prepare(query)?;
                stmt.execute(params![crate::utils::u64_to_sql(id)])?;
            }
            tx.commit()?;
            let ok: Result<()> = Ok(());
            ok
        })
        .await?
    }

    /// Get the latest verification record for a given pubkey.
    async fn get_latest_user_verification(&self, pub_key: &str) -> Result<VerificationRecord> {
        let mut conn = self.read_pool.get()?;
        let pub_key = pub_key.to_owned();
        tokio::task::spawn_blocking(move || {
            let tx = conn.transaction()?;
            let query = "SELECT v.id, v.name, e.event_hash, e.created_at, v.verified_at, v.failed_at, v.failure_count FROM user_verification v LEFT JOIN event e ON e.id=v.metadata_event WHERE e.author=? ORDER BY e.created_at DESC, v.verified_at DESC, v.failed_at DESC LIMIT 1;";
            let mut stmt = tx.prepare_cached(query)?;
            let fields = stmt.query_row(params![hex::decode(&pub_key).ok()], |r| {
                let rowid: u64 = crate::utils::sql_to_u64(r.get::<_, i64>(0)?);
                let rowname: String = r.get(1)?;
                let eventid: Vec<u8> = r.get(2)?;
                let created_at: u64 = crate::utils::sql_to_u64(r.get::<_, i64>(3)?);
                // create a tuple since we can't throw non-rusqlite errors in this closure
                Ok((
                    rowid,
                    rowname,
                    eventid,
                    created_at,
                    r.get::<_, i64>(4).ok().map(crate::utils::sql_to_u64),
                    r.get::<_, i64>(5).ok().map(crate::utils::sql_to_u64),
                    r.get::<_, i64>(6)? as u64,
                ))
            })?;
            Ok(VerificationRecord {
                rowid: fields.0,
                name: Nip05Name::try_from(&fields.1[..])?,
                address: pub_key,
                event: hex::encode(fields.2),
                event_created: fields.3,
                last_success: fields.4,
                last_failure: fields.5,
                failure_count: fields.6,
            })
        }).await?
    }

    /// Get oldest verification before timestamp
    async fn get_oldest_user_verification(&self, before: u64) -> Result<VerificationRecord> {
        let mut conn = self.read_pool.get()?;
        tokio::task::spawn_blocking(move || {
            let tx = conn.transaction()?;
            let query = "SELECT v.id, v.name, e.event_hash, e.author, e.created_at, v.verified_at, v.failed_at, v.failure_count FROM user_verification v INNER JOIN event e ON e.id=v.metadata_event WHERE (v.verified_at < ? OR v.verified_at IS NULL) AND (v.failed_at < ? OR v.failed_at IS NULL) ORDER BY v.verified_at ASC, v.failed_at ASC LIMIT 1;";
            let mut stmt = tx.prepare_cached(query)?;
            let fields = stmt.query_row(params![crate::utils::u64_to_sql(before), crate::utils::u64_to_sql(before)], |r| {
                let rowid: u64 = crate::utils::sql_to_u64(r.get::<_, i64>(0)?);
                let rowname: String = r.get(1)?;
                let eventid: Vec<u8> = r.get(2)?;
                let pubkey: Vec<u8> = r.get(3)?;
                let created_at: u64 = crate::utils::sql_to_u64(r.get::<_, i64>(4)?);
                // create a tuple since we can't throw non-rusqlite errors in this closure
                Ok((
                    rowid,
                    rowname,
                    eventid,
                    pubkey,
                    created_at,
                    r.get::<_, i64>(5).ok().map(crate::utils::sql_to_u64),
                    r.get::<_, i64>(6).ok().map(crate::utils::sql_to_u64),
                    r.get::<_, i64>(7)? as u64,
                ))
            })?;
            let vr = VerificationRecord {
                rowid: fields.0,
                name: Nip05Name::try_from(&fields.1[..])?,
                address: hex::encode(fields.3),
                event: hex::encode(fields.2),
                event_created: fields.4,
                last_success: fields.5,
                last_failure: fields.6,
                failure_count: fields.7,
            };
            Ok(vr)
        }).await?
    }

}

/// Decide if there is an index that should be used explicitly
fn override_index(f: &ReqFilter) -> Option<String> {
    if f.ids.is_some() {
        return Some("event_hash_index".into());
    }
    // queries for multiple kinds default to kind_index, which is
    // significantly slower than kind_created_at_index.
    if let Some(ks) = &f.kinds {
        if f.ids.is_none()
            && ks.len() > 1
            && f.since.is_none()
            && f.until.is_none()
            && f.tags.is_none()
            && f.authors.is_none()
        {
            return Some("kind_created_at_index".into());
        }
    }
    // if there is an author, it is much better to force the authors index.
    if f.authors.is_some() {
        if f.since.is_none() && f.until.is_none() && f.limit.is_none() {
            if f.kinds.is_none() {
                // with no use of kinds/created_at, just author
                return Some("author_index".into());
            }
            // prefer author_kind if there are kinds
            return Some("author_kind_index".into());
        }
        // finally, prefer author_created_at if time is provided
        return Some("author_created_at_index".into());
    }
    None
}

/// Create a dynamic SQL subquery and params from a subscription filter (and optional explicit index used)
fn query_from_filter(f: &ReqFilter) -> (String, Vec<Box<dyn ToSql>>, Option<String>) {
    // build a dynamic SQL query.  all user-input is either an integer
    // (sqli-safe), or a string that is filtered to only contain
    // hexadecimal characters.  Strings that require escaping (tag
    // names/values) use parameters.

    // if the filter is malformed, don't return anything.
    if f.force_no_match {
        let empty_query = "SELECT e.content FROM event e WHERE 1=0".to_owned();
        // query parameters for SQLite
        let empty_params: Vec<Box<dyn ToSql>> = vec![];
        return (empty_query, empty_params, None);
    }

    // check if the index needs to be overridden
    let idx_name = override_index(f);
    let idx_stmt = idx_name
        .as_ref()
        .map_or_else(|| "".to_owned(), |i| format!("INDEXED BY {i}"));
    let mut query = format!("SELECT e.content FROM event e {idx_stmt}");
    // query parameters for SQLite
    let mut params: Vec<Box<dyn ToSql>> = vec![];

    // individual filter components (single conditions such as an author or event ID)
    let mut filter_components: Vec<String> = Vec::new();
    // Query for "authors", allowing prefix matches
    if let Some(authvec) = &f.authors {
        // take each author and convert to a hexsearch
        let mut auth_searches: Vec<String> = vec![];
        for auth in authvec {
            auth_searches.push("author=?".to_owned());
            let auth_bin = hex::decode(auth).ok();
            params.push(Box::new(auth_bin));
        }
        if !authvec.is_empty() {
            let auth_clause = format!("({})", auth_searches.join(" OR "));
            filter_components.push(auth_clause);
        } else {
            filter_components.push("false".to_owned());
        }
    }
    // Query for Kind
    if let Some(ks) = &f.kinds {
        // kind is number, no escaping needed
        let str_kinds: Vec<String> = ks.iter().map(std::string::ToString::to_string).collect();
        let kind_clause = format!("kind IN ({})", str_kinds.join(", "));
        filter_components.push(kind_clause);
    }
    // Query for event, allowing prefix matches
    if let Some(idvec) = &f.ids {
        // take each author and convert to a hexsearch
        let mut id_searches: Vec<String> = vec![];
        for id in idvec {
            id_searches.push("event_hash=?".to_owned());
            let id_bin = hex::decode(id).ok();
            params.push(Box::new(id_bin));
        }
        if idvec.is_empty() {
            // if the ids list was empty, we should never return
            // any results.
            filter_components.push("false".to_owned());
        } else {
            let id_clause = format!("({})", id_searches.join(" OR "));
            filter_components.push(id_clause);
        }
    }
    // Query for tags
    if let Some(map) = &f.tags {
        for (key, val) in map.iter().sorted_by(|(k1, _), (k2, _)| k1.cmp(k2)) {
            if val.is_empty() {
                if matches!(val, TagOperand::Or(_)) {
                    filter_components.push("false".to_owned());
                }
                continue;
            }

            // Query for Kind/Since/Until additionally, to reduce the number of tags that come back.
            let kind_clause;
            if let Some(ks) = &f.kinds {
                // kind is number, no escaping needed
                let str_kinds: Vec<String> =
                    ks.iter().map(std::string::ToString::to_string).collect();
                kind_clause = format!("AND kind IN ({})", str_kinds.join(", "));
            } else {
                kind_clause = String::new();
            };
            let since_clause = if let Some(since) = f.since {
                format!("AND created_at >= {since}")
            } else {
                String::new()
            };
            // Query for timestamp
            let until_clause = if let Some(until) = f.until {
                format!("AND created_at <= {until}")
            } else {
                String::new()
            };

            match val {
                TagOperand::Or(v_or) => {
                    // Sort values for consistent query generation
                    let mut sorted_values: Vec<String> = v_or.iter().cloned().collect();
                    sorted_values.sort();

                    let mut str_vals: Vec<Box<dyn ToSql>> = vec![];
                    for v in &sorted_values {
                        str_vals.push(Box::new(v.clone()));
                    }
                    // create clauses with "?" params for each tag value being searched
                    let str_clause = format!("AND value IN ({})", repeat_vars(str_vals.len()));

                    // Build WHERE clause components
                    let mut tag_where_parts = vec![format!("name=? {str_clause}")];
                    if !kind_clause.is_empty() {
                        tag_where_parts.push(kind_clause.clone());
                    }
                    if !since_clause.is_empty() {
                        tag_where_parts.push(since_clause.clone());
                    }
                    if !until_clause.is_empty() {
                        tag_where_parts.push(until_clause.clone());
                    }

                    // find evidence of the target tag name/value existing for this event.
                    let tag_clause = format!(
                        "e.id IN (SELECT t.event_id FROM tag t WHERE ({}))",
                        tag_where_parts.join(" ")
                    );

                    // add the tag name as the first parameter
                    params.push(Box::new(key.to_string()));
                    // add all tag values that are blobs as params
                    params.append(&mut str_vals);
                    filter_components.push(tag_clause);
                }
                TagOperand::And(v_and) => {
                    // Sort values for consistent query generation
                    let mut sorted_values: Vec<String> = v_and.iter().cloned().collect();
                    sorted_values.sort();

                    for v in &sorted_values {
                        // Build WHERE clause components
                        let mut tag_where_parts = vec!["name=? AND value=?".to_string()];
                        if !kind_clause.is_empty() {
                            tag_where_parts.push(kind_clause.clone());
                        }
                        if !since_clause.is_empty() {
                            tag_where_parts.push(since_clause.clone());
                        }
                        if !until_clause.is_empty() {
                            tag_where_parts.push(until_clause.clone());
                        }

                        // For AND operations, each value must exist, so we create a separate subquery for each
                        let tag_clause = format!(
                            "e.id IN (SELECT t.event_id FROM tag t WHERE ({}))",
                            tag_where_parts.join(" ")
                        );

                        // add the tag name as the first parameter
                        params.push(Box::new(key.to_string()));
                        // add the tag value
                        params.push(Box::new(v.clone()));
                        filter_components.push(tag_clause);
                    }
                }
            }
        }
    }
    // Query for timestamp
    if let Some(since) = f.since {
        let created_clause = format!("created_at >= {since}");
        filter_components.push(created_clause);
    }
    // Query for timestamp
    if let Some(until) = f.until {
        let until_clause = format!("created_at <= {until}");
        filter_components.push(until_clause);
    }
    // never display hidden events
    query.push_str(" WHERE hidden!=TRUE");
    // never display hidden events
    filter_components.push("(expires_at IS NULL OR expires_at > ?)".to_string());
    params.push(Box::new(crate::utils::u64_to_sql(unix_time())));
    // build filter component conditions
    if !filter_components.is_empty() {
        query.push_str(" AND ");
        query.push_str(&filter_components.join(" AND "));
    }
    // Apply per-filter limit to this subquery.
    // The use of a LIMIT implies a DESC order, to capture only the most recent events.
    if let Some(lim) = f.limit {
        let _ = write!(query, " ORDER BY e.created_at DESC LIMIT {lim}");
    } else {
        query.push_str(" ORDER BY e.created_at ASC");
    }
    (query, params, idx_name)
}

/// Create a dynamic SQL query string and params from a subscription.
fn _query_from_sub(sub: &Subscription) -> (String, Vec<Box<dyn ToSql>>, Vec<String>) {
    // build a dynamic SQL query for an entire subscription, based on
    // SQL subqueries for filters.
    let mut subqueries: Vec<String> = Vec::new();
    let mut indexes = vec![];
    // subquery params
    let mut params: Vec<Box<dyn ToSql>> = vec![];
    // for every filter in the subscription, generate a subquery
    for f in &sub.filters {
        let (f_subquery, mut f_params, index) = query_from_filter(f);
        if let Some(i) = index {
            indexes.push(i);
        }
        subqueries.push(f_subquery);
        params.append(&mut f_params);
    }
    // encapsulate subqueries into select statements
    let subqueries_selects: Vec<String> = subqueries
        .iter()
        .map(|s| format!("SELECT distinct content, created_at FROM ({s})"))
        .collect();
    let query: String = subqueries_selects.join(" UNION ");
    (query, params, indexes)
}

/// Build a database connection pool.
/// # Panics
///
/// Will panic if the pool could not be created.
#[must_use]
pub fn build_pool(
    name: &str,
    settings: &Settings,
    flags: OpenFlags,
    min_size: u32,
    max_size: u32,
    wait_for_db: bool,
) -> SqlitePool {
    let db_dir = &settings.database.data_directory;
    let full_path = Path::new(db_dir).join(DB_FILE);

    // Startup coordination: if the database does not exist yet, the writer thread
    // has not finished creating it. Give that first-run path a chance to complete.
    if !settings.database.in_memory {
        while !full_path.exists() && wait_for_db {
            debug!("Database reader pool is waiting on the database to be created...");
            thread::sleep(Duration::from_millis(500));
        }
    }
    // Set cache size as a negative number so SQLite interprets it as KILOBYTES rather
    // than pages. Page units would silently depend on page_size, making one configuration
    // consume different memory across databases.
    let cache_kb = settings.database.cache_size_mb.saturating_mul(1024);
    let init_sql = format!("{STARTUP_SQL}\nPRAGMA main.cache_size = -{cache_kb};");
    let manager = if settings.database.in_memory {
        let sql = init_sql.clone();
        SqliteConnectionManager::file("file::memory:?cache=shared")
            .with_flags(flags)
            .with_init(move |c| c.execute_batch(&sql))
    } else {
        let sql = init_sql.clone();
        SqliteConnectionManager::file(&full_path)
            .with_flags(flags)
            .with_init(move |c| c.execute_batch(&sql))
    };
    let pool: SqlitePool = r2d2::Pool::builder()
        .thread_pool(connection_pool_threads())
        .test_on_check_out(true) // no noticeable performance hit
        .min_idle(Some(min_size))
        .max_size(max_size)
        .idle_timeout(Some(Duration::from_secs(10)))
        .max_lifetime(Some(Duration::from_secs(30)))
        .build(manager)
        .unwrap();
    // retrieve a connection to ensure the startup statements run immediately
    {
        let _ = pool.get();
    }

    info!(
        "Built a connection pool {:?} (min={}, max={})",
        name, min_size, max_size
    );
    pool
}

fn connection_pool_threads() -> Arc<scheduled_thread_pool::ScheduledThreadPool> {
    // Keep three dedicated workers per pool. r2d2 schedules a weak-reference
    // reaper every 30 seconds; after the final pool/connection owner drops,
    // those pending jobs cannot do useful work. The default scheduler would
    // retain all workers until the deadline, exhausting PIDs during rapid
    // repository turnover. Discard only pending jobs, never an active job.
    Arc::new(scheduled_thread_pool::ScheduledThreadPool::builder()
        .num_threads(3)
        .thread_name_pattern("r2d2-worker-{}")
        .on_drop_behavior(scheduled_thread_pool::OnPoolDropBehavior::DiscardPendingScheduled)
        .build())
}

/// Cleanup expired events on a regular basis
// These arguments are independent maintenance controls copied into one long-lived task.
// A wrapper struct would only move the same fields away from their single call site.
#[allow(clippy::too_many_arguments)]
async fn cleanup_expired(
    pool: SqlitePool,
    frequency: Duration,
    write_in_progress: Arc<Mutex<u64>>,
    persist_days: Option<usize>,
    kind_persist_days: std::collections::HashMap<u64, usize>,
    max_per_author: Option<usize>,
    max_db_bytes: Option<u64>,
    notary_keys: Vec<Vec<u8>>,
) -> Result<()> {
    tokio::task::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(frequency) => {
                    if let Ok(mut conn) = pool.get() {
                        let mut _guard:Option<MutexGuard<u64>> = None;
                        // take a write lock to prevent event writes
                        // from proceeding while we are deleting
                        // events.  This isn't necessary, but
                        // minimizes the chances of forcing event
                        // persistence to be retried.
                        _guard = Some(write_in_progress.lock().await);
                        let start = Instant::now();
                        let kinds = kind_persist_days.clone();
                        // Clone per iteration because the closure takes ownership and the
                        // maintenance loop repeats every few minutes.
                        let notary_keys = notary_keys.clone();
                        let exp_res = tokio::task::spawn_blocking(move || {
                            let expired = delete_expired(&mut conn, &notary_keys)?;
                            // Run age retention in the same maintenance cycle. Another
                            // thread for one DELETE is unnecessary and the shared write
                            // lock is already held.
                            let aged = delete_aged(
                                &mut conn,
                                persist_days,
                                &kinds,
                                &notary_keys,
                            )?;
                            let trimmed = match max_per_author {
                                Some(cap) => trim_prolific_authors(&mut conn, cap, &notary_keys)?,
                                None => 0,
                            };
                            // Deleting rows does NOT itself return space to the OS; freed
                            // pages enter the file's freelist. A 2026-08-29 measurement
                            // deleting 7,000 of 13,853 events returned zero bytes. Reclaim
                            // in batches to avoid long locks: 2,000 4-KiB pages, about
                            // 8 MiB per pass.
                            let over = match max_db_bytes {
                                Some(cap) => enforce_size_budget(&mut conn, cap, &notary_keys)?,
                                None => 0,
                            };
                            // Log separately because the aggregate line below sums four
                            // counters and cannot show whether per-author trimming ran.
                            // This prevented an external reviewer from capturing a positive
                            // history-protection control on 2026-09-04.
                            if aged > 0 {
                                info!("retention: removed {} aged events", aged);
                            }
                            if trimmed > 0 {
                                info!("retention: trimmed {} events over the per-author cap", trimmed);
                            }
                            if over > 0 {
                                info!("retention: removed {} events over the size budget", over);
                            }
                            match release_free_pages(&conn, 2000) {
                                Ok(n) if n > 0 => info!("reclaimed {} database pages", n),
                                Ok(_) => {}
                                Err(e) => info!("could not reclaim database pages: {:?}", e),
                            }
                            Ok::<usize, crate::error::Error>(expired + aged + trimmed + over)
                        }).await;
                        match exp_res {
                            Ok(Ok(count)) => {
                                if count > 0 {
                                    info!("removed {} expired events in: {:?}", count, start.elapsed());
                                }
                            },
                            _ => {
                                // either the task or underlying query failed
                                info!("there was an error cleaning up expired events: {:?}", exp_res);
                            }
                        }
                    }
                }
            };
        }
    });
    Ok(())
}

/// Return up to `pages` free pages to the operating system.
///
/// A costly subtlety: `execute_batch("PRAGMA incremental_vacuum(N)")` releases EXACTLY
/// ONE page. The pragma advances one page per step, while execute_batch performs one step
/// and stops. Measurement: 495 free pages became 494. Prepare the statement and drive it
/// to completion instead.
///
/// Returns the number of pages released.
fn release_free_pages(conn: &PooledConnection, pages: u32) -> Result<i64> {
    let before: i64 = conn.query_row("PRAGMA freelist_count;", [], |r| r.get(0))?;
    {
        let mut stmt = conn.prepare(&format!("PRAGMA incremental_vacuum({pages});"))?;
        let mut rows = stmt.query([])?;
        while rows.next()?.is_some() {}
    }
    let after: i64 = conn.query_row("PRAGMA freelist_count;", [], |r| r.get(0))?;
    Ok(before - after)
}

/// Switch the database to incremental vacuum if not already enabled.
///
/// Upstream ran `pragma auto_vacuum = FULL` on every event write, but it did nothing:
/// SQLite changes the mode only for an EMPTY database or through a full rebuild. A
/// production database measured on 2026-08-29 had `auto_vacuum = 0`; deletions returned
/// zero bytes, so after filling disk once the node could never recover on its own and the
/// file stayed at its peak size forever.
///
/// Use INCREMENTAL rather than FULL. FULL rewrites the database tail on every commit and
/// costs write throughput, while incremental releases pages in maintenance batches where
/// the lock is already held.
///
/// Rebuilding needs roughly the database size in free space and holds a lock. Above
/// `max_bytes` it therefore NEVER runs silently; the relay warns and lets the operator
/// choose a maintenance window. Returns `true` when the mode was switched.
pub fn ensure_incremental_vacuum(conn: &mut PooledConnection, max_bytes: u64) -> Result<bool> {
    let mode: i64 = conn.query_row("PRAGMA auto_vacuum;", [], |r| r.get(0))?;
    if mode != 0 {
        return Ok(false);
    }
    let page_size: i64 = conn.query_row("PRAGMA page_size;", [], |r| r.get(0))?;
    let page_count: i64 = conn.query_row("PRAGMA page_count;", [], |r| r.get(0))?;
    let size = (page_size.max(0) as u64).saturating_mul(page_count.max(0) as u64);
    if size > max_bytes {
        warn!(
            "database is {} MiB with auto_vacuum disabled: deleting events does not \
             return space to the operating system. Startup rebuild is skipped above the \
             {} MiB threshold; run `VACUUM` manually in a maintenance window",
            size / (1024 * 1024),
            max_bytes / (1024 * 1024)
        );
        return Ok(false);
    }
    let start = Instant::now();
    conn.execute_batch("PRAGMA auto_vacuum = INCREMENTAL; VACUUM;")?;
    info!(
        "enabled incremental vacuum in {:?} (database was {} MiB); deletions can now \
         return disk space",
        start.elapsed(),
        size / (1024 * 1024)
    );
    Ok(true)
}

/// Execute a query to delete all expired events.
///
/// Protocol history is EXCLUDED, not as an optimization. A delegation's `expiration` is
/// mandate lifetime but shares its name with NIP-40. Deleting it makes old authorization
/// unverifiable, while deleting a revocation restores the revoked delegation. Agreements,
/// reviews, trust, credentials, and declared-notary timestamps are the durable evidence
/// used to reconstruct past decisions, so this path uses the same `protected_sql`
/// predicate as every other maintenance limit.
pub fn delete_expired(conn: &mut PooledConnection, notary_keys: &[Vec<u8>]) -> Result<usize> {
    let tx = conn.transaction()?;
    let (protected_cond, protected_args) = protected_sql(notary_keys);
    let sql = format!(
        "DELETE FROM event WHERE expires_at <= ? AND NOT {protected_cond}"
    );
    let mut args: Vec<Box<dyn rusqlite::ToSql>> =
        vec![Box::new(crate::utils::u64_to_sql(unix_time()))];
    args.extend(protected_args);
    let update_count = tx.execute(&sql, rusqlite::params_from_iter(args.iter()))?;
    tx.commit()?;
    Ok(update_count)
}

/// Delete events older than the configured retention, globally and per kind.
///
/// The `[retention]` section came from upstream declared but never implemented, and
/// nothing else bounded storage: `messages_per_sec` limits the RATE, not the total.
/// Measured 29.08.2026: one public A4A event costs ~6.4 KB on disk — nine times its
/// size on the wire, because every tag becomes an indexed row — so at the relay's own
/// limit of 100 events/s a single author fills 6.8 GB of free space in about three
/// hours. One mandate, no special resources.
///
/// Age is taken from `created_at`, which the author controls — but only within
/// `options.reject_future_seconds`, so dating events far ahead to dodge deletion does
/// not work. Without that setting this function would be trivially evaded; the two
/// belong together.
///
/// Per-kind limits exist because kinds are not equivalent: a stale request is worthless
/// after its deadline, while agreements and revocations constitute reputation. Deleting
/// them by age erases the history the system relies on.
pub fn delete_aged(
    conn: &mut PooledConnection,
    persist_days: Option<usize>,
    kind_persist_days: &std::collections::HashMap<u64, usize>,
    notary_keys: &[Vec<u8>],
) -> Result<usize> {
    let now = unix_time();
    let tx = conn.transaction()?;
    let mut removed = 0usize;
    for (kind, days) in kind_persist_days {
        let cutoff = now.saturating_sub(*days as u64 * 86_400);
        let (protected_cond, protected_args) = protected_sql(notary_keys);
        let sql = format!(
            "DELETE FROM event WHERE kind=? AND created_at < ? AND NOT {protected_cond}"
        );
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = vec![
            Box::new(crate::utils::u64_to_sql(*kind)),
            Box::new(crate::utils::u64_to_sql(cutoff)),
        ];
        args.extend(protected_args);
        removed += tx.execute(&sql, rusqlite::params_from_iter(args.iter()))?;
    }
    if let Some(days) = persist_days {
        let cutoff = now.saturating_sub(days as u64 * 86_400);
        let (protected_cond, protected_args) = protected_sql(notary_keys);
        let sql = format!("DELETE FROM event WHERE created_at < ? AND NOT {protected_cond}");
        let mut args: Vec<Box<dyn rusqlite::ToSql>> =
            vec![Box::new(crate::utils::u64_to_sql(cutoff))];
        args.extend(protected_args);
        removed += tx.execute(&sql, rusqlite::params_from_iter(args.iter()))?;
    }
    tx.commit()?;
    Ok(removed)
}

/// Event kinds that storage pressure must never delete because history depends on them.
///
/// A delegation and its revocation prove whether an agent was authorized. Agreements,
/// revocations, trust, and credentials constitute reputation. Reputation disappearing
/// under storage pressure is worse than refusing a write: refusal is immediately visible,
/// while erased history is invisible and unrecoverable. Kind 1040 contains notary
/// timestamps (NIP-03, §2.9): one author emits about 50 per hour, and a per-author cap
/// would remove the OLDEST timestamps first, precisely the past they preserve. A live
/// 2026-09-04 check left only 5 of 56 timestamps on a local node.
const PROTECTED_KINDS: [u64; 6] = [31000, 31007, 31004, 31005, 31020, 31021];

/// SQL predicate meaning "this row is protected from deletion," plus its arguments.
///
/// History (`PROTECTED_KINDS`) is always protected. Kind-1040 timestamps are protected
/// **only for the declared notary and retired keys**, so the predicate examines AUTHOR,
/// not merely kind. A node without a notary accepts 1040 from anyone for local protocol
/// testing. If protection activated by kind alone when a notary was later declared, all
/// previously accumulated foreign junk would become retroactively undeletable, recreating
/// finding 122. Independent review found this as finding 124; the window affected every
/// operator following the documented rollout.
fn protected_sql(notary_keys: &[Vec<u8>]) -> (String, Vec<Box<dyn rusqlite::ToSql>>) {
    let kinds = PROTECTED_KINDS
        .iter()
        .map(|k| k.to_string())
        .collect::<Vec<_>>()
        .join(",");
    if notary_keys.is_empty() {
        return (format!("kind IN ({kinds})"), Vec::new());
    }
    let authors = notary_keys.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let args: Vec<Box<dyn rusqlite::ToSql>> = notary_keys
        .iter()
        .map(|k| Box::new(k.clone()) as Box<dyn rusqlite::ToSql>)
        .collect();
    (
        format!(
            "(kind IN ({kinds}) OR (kind = {stamp} AND author IN ({authors})))",
            stamp = crate::a4a_delegation::A4A_KIND_TIMESTAMP
        ),
        args,
    )
}

/// Current database size in bytes.
fn database_bytes(conn: &PooledConnection) -> Result<u64> {
    let page_size: i64 = conn.query_row("PRAGMA page_size;", [], |r| r.get(0))?;
    let page_count: i64 = conn.query_row("PRAGMA page_count;", [], |r| r.get(0))?;
    Ok((page_size.max(0) as u64).saturating_mul(page_count.max(0) as u64))
}

/// Delete disposable events until the database fits within `max_bytes`.
///
/// Why this is needed beyond a per-author limit: that limit counts ITEMS. Five thousand
/// events at the 128-KiB maximum consume 640 MiB for one key, and keys are free. Fifteen
/// keys can fill a node disk without any author exceeding 5,000. Bound the resource that
/// actually runs out: space.
///
/// Delete the oldest disposable events in batches and never touch history. Returns the
/// number of deleted events.
pub fn enforce_size_budget(
    conn: &mut PooledConnection,
    max_bytes: u64,
    notary_keys: &[Vec<u8>],
) -> Result<usize> {
    if database_bytes(conn)? <= max_bytes {
        return Ok(0);
    }
    let (protected_cond, _) = protected_sql(notary_keys);
    let sql = format!(
        "DELETE FROM event WHERE id IN (SELECT id FROM event WHERE NOT {protected_cond} \
         ORDER BY created_at ASC LIMIT 2000)"
    );
    let mut removed = 0usize;
    // Batch work because one long DELETE would hold the write lock throughout. Cap one
    // maintenance cycle at twenty passes of 2,000 and continue in ten minutes.
    for _ in 0..20 {
        // Rebuild arguments for every batch because `ToSql` is not Clone.
        let (_, args) = protected_sql(notary_keys);
        let n = conn.execute(&sql, rusqlite::params_from_iter(args.iter()))?;
        removed += n;
        if n == 0 {
            break;
        }
        release_free_pages(conn, 4000)?;
        if database_bytes(conn)? <= max_bytes {
            return Ok(removed);
        }
    }
    if database_bytes(conn)? > max_bytes {
        warn!(
            "database is {} MiB above the {} MiB ceiling with no disposable events left; \
             only history and delegations remain, and deleting them would erase reputation. \
             Increase disk capacity or max_db_bytes",
            database_bytes(conn)? / (1024 * 1024),
            max_bytes / (1024 * 1024)
        );
    }
    Ok(removed)
}

/// Trim authors holding more than `max_events_per_author` events, oldest first.
///
/// Age retention bounds data by TIME, not volume; one key can write arbitrarily much
/// during the allowed period. This ceiling limits volume per identity.
///
/// Important limitation: keys are free, so this cap does not make disk exhaustion
/// impossible. It makes exhaustion linear in key count instead of unbounded for one key.
/// In an open network with free writes, only payment, an allowlist, or trust-graph
/// admission can close the problem completely; payment was deliberately rejected.
/// (docs/design/2026-08-28-relay-network-strategy.md).
pub fn trim_prolific_authors(
    conn: &mut PooledConnection,
    max_events_per_author: usize,
    notary_keys: &[Vec<u8>],
) -> Result<usize> {
    // Exclude protected kinds EXACTLY as `enforce_size_budget` does above. Before
    // 2026-09-04 they were NOT excluded here, so two adjacent ceilings behaved in
    // opposite ways: one preserved history forever while the other deleted it first
    // because history is oldest.
    //
    // Real impact: the cap selects an author's OLDEST events, including early agreements
    // (31004), reviews (31005), and in a single-key model the owner's delegation (31000).
    // Worst of all, deleting a delegation revocation (31007) RESTORES the revoked
    // delegation. Maintenance could therefore revive a revoked agent when processing a
    // prolific owner.
    //
    // The cap now counts and deletes only DISPOSABLE events. The `config.prod.toml`
    // promise that history is never deleted must either be true or be removed, never
    // contradict the implementation.
    let (protected_cond, _) = protected_sql(notary_keys);
    let tx = conn.transaction()?;
    let over: Vec<Vec<u8>> = {
        let sql = format!(
            "SELECT author FROM event WHERE NOT {protected_cond} \
             GROUP BY author HAVING count(*) > ? LIMIT 1000"
        );
        let mut stmt = tx.prepare(&sql)?;
        let (_, mut args) = protected_sql(notary_keys);
        args.push(Box::new(max_events_per_author as i64));
        let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), |r| {
            r.get::<usize, Vec<u8>>(0)
        })?;
        rows.filter_map(std::result::Result::ok).collect()
    };
    let mut removed = 0usize;
    let del_sql = format!(
        "DELETE FROM event WHERE id IN (SELECT id FROM event WHERE author=? \
         AND NOT {protected_cond} ORDER BY created_at DESC LIMIT -1 OFFSET ?)"
    );
    for author in over {
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(author)];
        let (_, protected_args) = protected_sql(notary_keys);
        args.extend(protected_args);
        args.push(Box::new(max_events_per_author as i64));
        removed += tx.execute(&del_sql, rusqlite::params_from_iter(args.iter()))?;
    }
    tx.commit()?;
    Ok(removed)
}

/// Perform database WAL checkpoint on a regular basis
pub async fn db_checkpoint_task(
    pool: SqlitePool,
    frequency: Duration,
    write_in_progress: Arc<Mutex<u64>>,
    checkpoint_in_progress: Arc<Mutex<u64>>,
) -> Result<()> {
    // Known performance limitation: readers may interrupt a checkpoint because this
    // path does not acquire every reader permit at once.
    tokio::task::spawn(async move {
        // WAL size in pages.
        let mut current_wal_size = 0;
        // WAL threshold for more aggressive checkpointing (10,000 pages, or about 40MB)
        let wal_threshold = 1000 * 10;
        // default threshold for the busy timer
        let busy_wait_default = Duration::from_secs(1);
        // if the WAL file is getting too big, switch to this
        let busy_wait_default_long = Duration::from_secs(10);
        loop {
            tokio::select! {
                _ = tokio::time::sleep(frequency) => {
                    if let Ok(mut conn) = pool.get() {
                        // block all other writers
                        let _write_guard = write_in_progress.lock().await;
                        let mut _guard:Option<MutexGuard<u64>> = None;
                        // the busy timer will block writers, so don't set
                        // this any higher than you want max latency for event
                        // writes.
                        if current_wal_size <= wal_threshold {
                            conn.busy_timeout(busy_wait_default).ok();
                        } else {
                            // if the wal size has exceeded a threshold, increase the busy timeout.
                            conn.busy_timeout(busy_wait_default_long).ok();
                            // take a lock that will prevent new readers.
                            info!("blocking new readers to perform wal_checkpoint");
                            _guard = Some(checkpoint_in_progress.lock().await);
                        }
                        debug!("running wal_checkpoint(TRUNCATE)");
                        if let Ok(new_size) = checkpoint_db(&mut conn) {
                            current_wal_size = new_size;
                        }
                    }
                }
            };
        }
    });

    Ok(())
}

#[derive(Debug)]
#[allow(dead_code)]
enum SqliteStatus {
    Ok,
    Busy,
    Error,
    Other(u64),
}

/// Checkpoint/Truncate WAL.  Returns the number of WAL pages remaining.
pub fn checkpoint_db(conn: &mut PooledConnection) -> Result<usize> {
    let query = "PRAGMA wal_checkpoint(TRUNCATE);";
    let start = Instant::now();
    let (cp_result, wal_size, _frames_checkpointed) = conn.query_row(query, [], |row| {
        let checkpoint_result: u64 = crate::utils::sql_to_u64(row.get::<_, i64>(0)?);
        let wal_size: u64 = crate::utils::sql_to_u64(row.get::<_, i64>(1)?);
        let frames_checkpointed: u64 = crate::utils::sql_to_u64(row.get::<_, i64>(2)?);
        Ok((checkpoint_result, wal_size, frames_checkpointed))
    })?;
    let result = match cp_result {
        0 => SqliteStatus::Ok,
        1 => SqliteStatus::Busy,
        2 => SqliteStatus::Error,
        x => SqliteStatus::Other(x),
    };
    info!(
        "checkpoint ran in {:?} (result: {:?}, WAL size: {})",
        start.elapsed(),
        result,
        wal_size
    );
    Ok(wal_size as usize)
}

/// Produce a arbitrary list of '?' parameters.
fn repeat_vars(count: usize) -> String {
    if count == 0 {
        return "".to_owned();
    }
    let mut s = "?, ".repeat(count);
    // Remove trailing comma and space
    s.pop();
    s.pop();
    s
}

/// Display database pool stats every 1 minute
pub async fn monitor_pool(name: &str, pool: SqlitePool) {
    let sleep_dur = Duration::from_secs(60);
    loop {
        log_pool_stats(name, &pool);
        tokio::time::sleep(sleep_dur).await;
    }
}

/// Log pool stats
fn log_pool_stats(name: &str, pool: &SqlitePool) {
    let state: r2d2::State = pool.state();
    let in_use_cxns = state.connections - state.idle_connections;
    debug!(
        "DB pool {:?} usage (in_use: {}, available: {}, max: {})",
        name,
        in_use_cxns,
        state.connections,
        pool.max_size()
    );
}

/// Check if the pool is fully utilized
fn _pool_at_capacity(pool: &SqlitePool) -> bool {
    let state: r2d2::State = pool.state();
    state.idle_connections == 0
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::subscription::TagOperand;
    use prometheus::{Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, Opts};
    use std::collections::{HashMap, HashSet};

    #[test]
    fn closed_pool_discards_delayed_jobs_promptly() {
        struct OnDrop(std::sync::mpsc::Sender<()>);
        impl Drop for OnDrop {
            fn drop(&mut self) {
                let _ = self.0.send(());
            }
        }

        let (released, observed) = std::sync::mpsc::channel();
        let notice = OnDrop(released);
        let workers = connection_pool_threads();
        workers.execute_after(Duration::from_secs(60), move || drop(notice));
        drop(workers);
        observed.recv_timeout(Duration::from_secs(2))
            .expect("closed pools must not retain workers until a delayed reaper runs");
    }

    #[test]
    fn live_pool_still_runs_scheduled_jobs() {
        let (completed, observed) = std::sync::mpsc::channel();
        let workers = connection_pool_threads();
        workers.execute_after(Duration::from_millis(10), move || {
            let _ = completed.send(());
        });
        drop(workers.clone());
        observed.recv_timeout(Duration::from_secs(2)).unwrap();
    }

    #[test]
    fn closing_pool_does_not_interrupt_a_running_job() {
        let (started, observed_start) = std::sync::mpsc::channel();
        let (resume, wait_resume) = std::sync::mpsc::channel();
        let (finished, observed_finish) = std::sync::mpsc::channel();
        let workers = connection_pool_threads();
        workers.execute(move || {
            let _ = started.send(());
            wait_resume.recv_timeout(Duration::from_secs(2)).unwrap();
            let _ = finished.send(());
        });
        observed_start.recv_timeout(Duration::from_secs(2)).unwrap();
        drop(workers);
        resume.send(()).unwrap();
        observed_finish.recv_timeout(Duration::from_secs(2)).unwrap();
    }

    /// Build a `NostrMetrics` instance suitable for tests (not registered
    /// with any Prometheus registry).
    fn test_metrics() -> NostrMetrics {
        NostrMetrics {
            query_sub: Histogram::with_opts(HistogramOpts::new("test_query_seconds", "test"))
                .unwrap(),
            query_db: Histogram::with_opts(HistogramOpts::new("test_filter_seconds", "test"))
                .unwrap(),
            connections_active: IntGauge::with_opts(
                Opts::new("test_connections_active", "test")).unwrap(),
            db_connections: IntGauge::with_opts(Opts::new("test_db_connections", "test")).unwrap(),
            write_events: Histogram::with_opts(HistogramOpts::new(
                "test_events_write_seconds",
                "test",
            ))
            .unwrap(),
            sent_events: IntCounterVec::new(
                Opts::new("test_events_sent_total", "test"),
                &["source"],
            )
            .unwrap(),
            connections: IntCounter::with_opts(Opts::new("test_connections_total", "test"))
                .unwrap(),
            disconnects: IntCounterVec::new(
                Opts::new("test_disconnects_total", "test"),
                &["reason"],
            )
            .unwrap(),
            query_aborts: IntCounterVec::new(
                Opts::new("test_query_abort_total", "test"),
                &["reason"],
            )
            .unwrap(),
            cmd_req: IntCounter::with_opts(Opts::new("test_cmd_req_total", "test")).unwrap(),
            cmd_event: IntCounter::with_opts(Opts::new("test_cmd_event_total", "test")).unwrap(),
            cmd_close: IntCounter::with_opts(Opts::new("test_cmd_close_total", "test")).unwrap(),
            cmd_auth: IntCounter::with_opts(Opts::new("test_cmd_auth_total", "test")).unwrap(),
        }
    }

    /// Build a `SqliteRepo` backed by a fresh, uniquely-named temp directory
    /// (schema created via migrations) for tests. A dedicated on-disk temp
    /// dir (rather than `database.in_memory`'s shared-cache `:memory:` URI,
    /// which all repos in the process would otherwise share) keeps parallel
    /// `#[tokio::test]`s from tripping over each other's data/migrations.
    pub(crate) async fn test_repo() -> SqliteRepo {
        use std::sync::atomic::{AtomicU64, Ordering};
        static TEST_DB_COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = TEST_DB_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "nostr_rs_relay_test_{}_{}",
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

    pub(crate) fn hold_readers(repo: &SqliteRepo) -> Vec<PooledConnection> {
        (0..repo.read_pool.max_size()).map(|_| repo.read_pool.get().unwrap()).collect()
    }

    pub(crate) async fn history_fixture() -> SqliteRepo {
        let repo = test_repo().await;
        let mut event = aged_event(980, 31005, 0);
        event.content = "x".repeat(120_000);
        repo.write_event(&event).await.unwrap();
        repo.write_pool.get().unwrap().execute("UPDATE event SET first_seen=100", []).unwrap();
        repo
    }

    pub(crate) fn inbox_event(seed: u32, kind: u64, recipient: &str) -> Event {
        let mut event = aged_event(seed, kind, u64::from(seed % 2));
        event.tags = vec![vec!["p".into(), recipient.into()],
                          vec!["d".into(), seed.to_string()]];
        event.content = "synthetic ciphertext".into();
        event
    }

    pub(crate) async fn inbox_fixture() -> SqliteRepo {
        let repo = test_repo().await;
        let recipient = "a".repeat(64);
        for (seed, kind, address) in [
            (1002, 31033, recipient.clone()), (1001, 1059, recipient.clone()),
            (1003, 1059, "b".repeat(64)), (1004, 31034, recipient.clone()),
            (1005, 31005, recipient.clone()), (1006, 1059, recipient.clone()),
            (1007, 1059, recipient.clone()), (1008, 1059, "a".repeat(63)),
            (1009, 1059, "A".repeat(64)), (1010, 1059, recipient.clone()),
            (1011, 4, recipient.clone()), (1012, 1059, recipient.clone()),
        ] {
            let mut event = inbox_event(seed, kind, &address);
            if seed == 1006 {
                event.tags.push(vec!["expiration".into(), "1".into()]);
            }
            if seed == 1010 { event.tags.retain(|tag| tag[0] != "p"); }
            repo.write_event(&event).await.unwrap();
        }
        let conn = repo.write_pool.get().unwrap();
        conn.execute("UPDATE event SET first_seen=100", []).unwrap();
        conn.execute("UPDATE event SET hidden=TRUE WHERE event_hash=?",
                     [hex::decode(format!("{:064x}", 1007)).unwrap()]).unwrap();
        conn.execute("UPDATE event SET first_seen=? WHERE event_hash=?",
                     params![crate::utils::u64_to_sql(unix_time() + 60),
                             hex::decode(format!("{:064x}", 1012)).unwrap()]).unwrap();
        drop(conn);
        repo
    }

    pub(crate) async fn inbox_large_recipient_fixture() -> SqliteRepo {
        let repo = test_repo().await;
        let mut conn = repo.write_pool.get().unwrap();
        let tx = conn.transaction().unwrap();
        let event = inbox_event(3000, 1059, &"a".repeat(64));
        tx.execute(
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100000) \
             INSERT INTO event(event_hash, first_seen, created_at, author, kind, hidden, content) \
             SELECT randomblob(32), 100, 0, zeroblob(32), 1059, FALSE, ? FROM n",
            [serde_json::to_string(&event).unwrap()]).unwrap();
        tx.execute("INSERT INTO tag(event_id, name, value, kind, created_at) \
                    SELECT id, 'p', ?, kind, created_at FROM event", ["a".repeat(64)]).unwrap();
        tx.commit().unwrap();
        drop(conn);
        repo
    }

    /// A query must stop when the client is gone, including when "gone" means
    /// the abandon sender was DROPPED rather than sent on.
    ///
    /// `oneshot::Receiver::try_recv` returns `Err(Closed)` once the sender is
    /// dropped, and the cancellation checks tested `.is_ok()` -- so a dropped
    /// sender read exactly like "no cancellation yet" and the query ran to
    /// completion with nobody left to receive it. The WS path always calls
    /// `send(())` explicitly and so never exposed this, but `/v1/search` relies
    /// on the drop: its handler returns after a 10 s timeout and leaves the
    /// blocking thread grinding through the table at full speed. Sixteen such
    /// requests exhaust `max_blocking_threads` and stall every subscription on
    /// the relay.
    #[tokio::test]
    async fn dropped_abandon_sender_cancels_the_query() {
        let repo = test_repo().await;
        for i in 0..250u32 {
            let event = Event {
                id: format!("{i:064x}"),
                pubkey: "b".repeat(64),
                delegated_by: None,
                created_at: 1_000 + u64::from(i),
                kind: 1,
                tags: vec![],
                content: format!("row {i}"),
                sig: "c".repeat(128),
                tagidx: None,
            };
            repo.write_event(&event).await.unwrap();
        }

        let sub = Subscription {
            id: "abandoned".to_owned(),
            filters: vec![ReqFilter {
                ids: None,
                kinds: Some(vec![1]),
                since: None,
                until: None,
                authors: None,
                limit: None,
                tags: None,
                force_no_match: false,
            }],
        };
        let (query_tx, mut query_rx) = tokio::sync::mpsc::channel::<QueryResult>(1000);
        let (abandon_tx, abandon_rx) = tokio::sync::oneshot::channel::<()>();
        drop(abandon_tx); // Client disconnected without sending anything.

        repo.query_subscription(sub, "test".to_owned(), query_tx, abandon_rx)
            .await
            .unwrap();

        let mut received = 0;
        while let Some(qr) = query_rx.recv().await {
            if qr.event == "EOSE" {
                break;
            }
            received += 1;
        }
        assert_eq!(
            received, 0,
            "query processed {received} rows after its receiver disappeared"
        );
    }

    /// An SQL error inside a subscription query used to end in EOSE and zero rows.
    /// That is the same message as "nothing is stored". Reproduced on a production
    /// node (finding 71) as silence; the following fix sent EOSE so the client
    /// would not hang. EOSE still claimed the stored set was complete.
    ///
    /// The terminal message must be CLOSED with an error reason, and it must not
    /// be EOSE. `query_aborts{error}` proves the query actually failed; a green
    /// CLOSED assertion without that increment proves nothing.
    #[tokio::test]
    async fn sql_error_in_a_query_closes_instead_of_empty_eose() {
        let repo = test_repo().await;
        // Construct the filter as a STRUCT to bypass parse caps and target query failure.
        // Production fails at 999 parameters and the local build at 32,766, depending on
        // SQLite compilation; neither accepts 40,000 authors.
        let authors: Vec<String> = (0..40_000).map(|i| format!("{i:064x}")).collect();
        let sub = Subscription {
            id: "overflow".to_owned(),
            filters: vec![ReqFilter {
                ids: None,
                kinds: Some(vec![1]),
                since: None,
                until: None,
                authors: Some(authors),
                limit: None,
                tags: None,
                force_no_match: false,
            }],
        };

        let (query_tx, mut query_rx) = tokio::sync::mpsc::channel::<QueryResult>(1000);
        let (_abandon_tx, abandon_rx) = tokio::sync::oneshot::channel::<()>();
        let before = repo.metrics.query_aborts.with_label_values(&["error"]).get();

        repo.query_subscription(sub, "test".to_owned(), query_tx, abandon_rx)
            .await
            .unwrap();

        let got = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while let Some(qr) = query_rx.recv().await {
                if qr.event == "EOSE" {
                    return "EOSE".to_owned();
                }
                if let Some(reason) = qr.event.strip_prefix("CLOSED ") {
                    return reason.to_owned();
                }
            }
            "silence".to_owned()
        })
        .await;
        let after = repo.metrics.query_aborts.with_label_values(&["error"]).get();
        assert!(
            after > before,
            "invalid setup: query did not fail, so a green CLOSED assertion proves nothing"
        );
        let terminal = got.expect("query produced no terminal message");
        assert!(
            terminal.starts_with("error:"),
            "SQL error looked like an empty stored set: {terminal}"
        );
        assert_ne!(terminal, "EOSE");
    }

    fn plain_event(id_byte: char, kind: u64) -> Event {
        Event {
            id: id_byte.to_string().repeat(64),
            pubkey: "b".repeat(64),
            delegated_by: None,
            created_at: 1_000,
            kind,
            tags: vec![],
            content: "plain".into(),
            sig: "c".repeat(128),
            tagidx: None,
        }
    }

    /// Dropping the author index makes the "is there a newer replaceable event?"
    /// query fail. That used to look like "no newer event", and the write succeeded.
    #[tokio::test]
    async fn replaceable_lookup_failure_is_not_a_successful_insert() {
        let repo = test_repo().await;
        repo.write_pool()
            .get()
            .unwrap()
            .execute_batch("DROP INDEX author_index;")
            .unwrap();
        let result = repo.write_event(&plain_event('d', 0)).await;
        assert!(
            result.is_err(),
            "index failure was treated as 'no newer event': {result:?}"
        );
    }

    /// Dropping the tag table makes the "was this event already deleted?" query
    /// fail. That used to look like "not deleted", and the event was saved.
    #[tokio::test]
    async fn deletion_lookup_failure_does_not_save_the_event() {
        let repo = test_repo().await;
        repo.write_pool()
            .get()
            .unwrap()
            .execute_batch("DROP TABLE tag;")
            .unwrap();
        let result = repo.write_event(&plain_event('e', 1)).await;
        assert!(
            result.is_err(),
            "deletion lookup failure saved the event: {result:?}"
        );
    }

    /// Delegation cache-miss checks run on the WRITER path and used the reader pool.
    /// Eight broad subscriptions occupied every connection, making the writer and all
    /// WebSocket or REST publications wait for r2d2's 30-second `connection_timeout`.
    /// Moving `Pool::get` into `spawn_blocking` (finding 66) freed the executor thread but
    /// not the writer: independent review measured a 3-second task timeout versus a
    /// 30-second pool wait. Only a separate pool unavailable to subscriptions fixes this.
    #[tokio::test]
    async fn writer_path_lookup_does_not_wait_for_subscription_readers() {
        let repo = test_repo().await;
        // Occupy every reader connection as eight broad REQs would. Hold exactly
        // `max_size()` using `get()`. The first test held one and checked
        // `try_get().is_none()`, which is also true with FREE capacity but no idle
        // connections. That invalid setup passed in 0.02 seconds before the fix.
        let max = repo.read_pool.max_size();
        let held: Vec<_> = (0..max)
            .map(|_| repo.read_pool.get().expect("hold a reader connection"))
            .collect();
        let st = repo.read_pool.state();
        assert!(
            st.connections == max && st.idle_connections == 0,
            "invalid setup: reader pool is not exhausted ({}/{} in use, {} idle)",
            st.connections, max, st.idle_connections
        );
        let started = std::time::Instant::now();
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            repo.get_event_by_id(&"0".repeat(64)),
        )
        .await;
        drop(held);
        assert!(
            matches!(outcome, Ok(Ok(None))),
            "writer-path lookup waited for readers {:?}: {:?}",
            started.elapsed(),
            outcome.map(|r| r.map(|e| e.is_some()))
        );
    }

    /// Reissuing a delegation with the same `d` replaces it under NIP-33 and used to
    /// delete the old copy physically. The archive now preserves that copy: live lookup
    /// still hides it, retaining NIP-33 semantics, while REST `/v1/delegation-history`
    /// exposes it (finding 65 / F4).
    #[tokio::test]
    async fn replaced_delegation_goes_to_the_archive_not_to_nowhere() {
        let repo = test_repo().await;
        let owner = "a".repeat(64);
        let mut v1 = aged_event(700, 31000, 2);
        v1.pubkey = owner.clone();
        v1.tags = vec![vec!["d".to_owned(), "b".repeat(64)]];
        v1.build_index();
        let mut v2 = aged_event(701, 31000, 1);
        v2.pubkey = owner.clone();
        v2.tags = vec![vec!["d".to_owned(), "b".repeat(64)]];
        v2.build_index();
        repo.write_event(&v1).await.unwrap();
        repo.write_event(&v2).await.unwrap();

        assert!(repo.get_event_by_id(&v1.id).await.unwrap().is_none(), "old copy remained live, breaking NIP-33");
        assert!(repo.get_event_by_id(&v2.id).await.unwrap().is_some());
        let archived = repo.get_archived_delegation(&v1.id).await.unwrap();
        assert_eq!(archived.map(|e| e.id), Some(v1.id.clone()), "replaced delegation was not archived");
        assert!(repo.get_archived_delegation(&v2.id).await.unwrap().is_none(), "live delegation must not be archived");
        // Other addressable kinds are not archived.
        let mut i1 = aged_event(702, 31002, 2);
        i1.pubkey = owner.clone();
        i1.tags = vec![vec!["d".to_owned(), "x".to_owned()]];
        i1.build_index();
        let mut i2 = aged_event(703, 31002, 1);
        i2.pubkey = owner;
        i2.tags = vec![vec!["d".to_owned(), "x".to_owned()]];
        i2.build_index();
        repo.write_event(&i1).await.unwrap();
        repo.write_event(&i2).await.unwrap();
        assert!(repo.get_archived_delegation(&i1.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn duplicate_d_tags_do_not_delete_the_accepted_revocation() {
        let repo = test_repo().await;
        let mut revoked = aged_event(710, 31007, 1);
        revoked.tags = vec![vec!["d".into(), "a".repeat(64)]; 2];
        revoked.build_index();

        assert_eq!(repo.write_event(&revoked).await.unwrap(), 1);
        assert_eq!(repo.get_event_by_id(&revoked.id).await.unwrap().map(|e| e.id),
                   Some(revoked.id.clone()), "an accepted revocation must remain stored");

        let mut newer = revoked.clone();
        newer.id = format!("{:064x}", 711);
        newer.created_at += 1;
        assert_eq!(repo.write_event(&newer).await.unwrap(), 1);
        assert!(repo.get_event_by_id(&revoked.id).await.unwrap().is_none());
        assert_eq!(repo.get_event_by_id(&newer.id).await.unwrap().map(|e| e.id),
                   Some(newer.id), "replacement must keep the newest event, not a tag row");
    }

    #[tokio::test]
    async fn duplicate_d_tags_archive_only_the_replaced_delegation() {
        let repo = test_repo().await;
        let mut old = aged_event(712, 31000, 2);
        old.tags = vec![vec!["d".into(), "a".repeat(64)]];
        old.build_index();
        repo.write_event(&old).await.unwrap();
        let mut new = old.clone();
        new.id = format!("{:064x}", 713);
        new.created_at += 1;
        new.tags.push(new.tags[0].clone());
        new.build_index();

        assert_eq!(repo.write_event(&new).await.unwrap(), 1);
        assert!(repo.get_event_by_id(&new.id).await.unwrap().is_some());
        assert!(repo.get_event_by_id(&old.id).await.unwrap().is_none());
        assert!(repo.get_archived_delegation(&old.id).await.unwrap().is_some());
        assert!(repo.get_archived_delegation(&new.id).await.unwrap().is_none(),
                "duplicate tags must not archive the live delegation");
    }

    /// Finding 86: the notary selected history by `created_at`, so an event accepted today
    /// but dated two days earlier was never timestamped. The proof must reflect INTAKE,
    /// meaning "no later than T." History uses `first_seen`: backdated events are included,
    /// non-persistent kinds are not, and the cursor is inclusive for reader deduplication.
    #[tokio::test]
    async fn history_after_is_ordered_by_reception_and_includes_backdated_events() {
        let repo = test_repo().await;
        let backdated = aged_event(800, 31004, 2);
        let fresh = aged_event(801, 31005, 0);
        let noise = aged_event(802, 1, 0);
        repo.write_event(&backdated).await.unwrap();
        repo.write_event(&fresh).await.unwrap();
        repo.write_event(&noise).await.unwrap();
        repo.write_pool.get().unwrap().execute(
            "UPDATE event SET first_seen = first_seen - 1", []).unwrap();
        let rows = repo.history_after(0, 10).await.unwrap();
        let ids: Vec<String> = rows.iter().map(|(_, e)| e.id.clone()).collect();
        assert!(ids.contains(&backdated.id), "backdated event disappeared from history");
        assert!(ids.contains(&fresh.id));
        assert!(!ids.contains(&noise.id), "kind 1 is not historical data");
        let now = crate::utils::unix_time();
        assert!(
            rows.iter().all(|(fs, _)| *fs + 5 >= now && *fs <= now + 1),
            "first_seen must be intake time, not created_at: {:?}",
            rows.iter().map(|(fs, _)| *fs).collect::<Vec<_>>()
        );
        // Within one second, order by event id. A live check found rowid ordering despite
        // the specification promising id as the secondary key.
        let mut sorted = rows.clone();
        sorted.sort_by(|a, b| (a.0, &a.1.id).cmp(&(b.0, &b.1.id)));
        assert_eq!(
            rows.iter().map(|(_, e)| &e.id).collect::<Vec<_>>(),
            sorted.iter().map(|(_, e)| &e.id).collect::<Vec<_>>(),
            "events within one second are not ordered by id"
        );
        let last = rows.last().unwrap().0;
        assert!(repo.history_after(last + 1, 10).await.unwrap().is_empty());
        assert_eq!(repo.history_after(last, 10).await.unwrap().len(), 2, "cursor must be inclusive");
        assert_eq!(repo.history_after(0, 1).await.unwrap().len(), 1, "limit");
    }

    #[tokio::test]
    async fn history_page_is_bounded_in_bytes_not_only_event_count() {
        let repo = test_repo().await;
        for i in 0..24 {
            let mut event = aged_event(900 + i, 31021, 0);
            event.content = "x".repeat(120_000);
            event.tags = vec![vec!["d".into(), i.to_string()]];
            repo.write_event(&event).await.unwrap();
        }
        repo.write_pool.get().unwrap().execute(
            "UPDATE event SET first_seen = first_seen - 1", []).unwrap();
        let rows = repo.history_after(0, 5000).await.unwrap();
        assert!(!rows.is_empty(), "a size limit must not disable history");
        let bytes = serde_json::to_vec(&rows).unwrap().len();
        assert!(bytes <= 2 * 1024 * 1024, "page allocated {bytes} bytes");

        let mut seen = rows.iter().map(|(_, e)| e.id.clone()).collect::<Vec<_>>();
        let (mut fs, mut id) = rows.last().map(|(fs, e)| (*fs, e.id.clone())).unwrap();
        loop {
            let page = repo.history_after_id(fs, &id, 5000).await.unwrap();
            if page.is_empty() { break; }
            (fs, id) = page.last().map(|(fs, e)| (*fs, e.id.clone())).unwrap();
            seen.extend(page.into_iter().map(|(_, e)| e.id));
        }
        assert_eq!(seen.len(), 24, "byte-limited continuation must not skip rows");
        assert_eq!(seen.iter().collect::<HashSet<_>>().len(), 24);
    }

    #[tokio::test]
    async fn history_continues_inside_a_second_without_repeating_the_boundary() {
        let repo = test_repo().await;
        for i in (0..7).rev() {
            repo.write_event(&aged_event(950 + i, 31005, 0)).await.unwrap();
        }
        repo.write_pool.get().unwrap().execute("UPDATE event SET first_seen = 100", []).unwrap();
        let mut cursor = (0, String::new());
        let mut seen = Vec::new();
        for _ in 0..5 {
            let rows = repo.history_after_id(cursor.0, &cursor.1, 2).await.unwrap();
            if let Some((fs, e)) = rows.last() { cursor = (*fs, e.id.clone()); }
            seen.extend(rows.into_iter().map(|(_, e)| e.id));
        }
        assert_eq!(seen, (0..7).map(|i| format!("{:064x}", 950 + i)).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn history_ordering_uses_an_index_not_an_in_memory_payload_sort() {
        let repo = test_repo().await;
        let conn = repo.read_pool.get().unwrap();
        let mut stmt = conn.prepare(
            "EXPLAIN QUERY PLAN SELECT content FROM event INDEXED BY event_first_seen_index \
             WHERE kind IN (31004,31005) \
             AND (first_seen,event_hash) > (100,x'') ORDER BY first_seen,event_hash LIMIT 5000").unwrap();
        let plan = stmt.query_map([], |r| r.get::<_, String>(3)).unwrap()
            .collect::<std::result::Result<Vec<_>, _>>().unwrap().join(" ");
        assert!(!plan.contains("TEMP B-TREE"), "unbounded payload sort: {plan}");
    }

    #[tokio::test]
    async fn history_index_migration_preserves_v20_events_and_archive() {
        let repo = test_repo().await;
        let mut old = aged_event(960, 31000, 2);
        old.tags = vec![vec!["d".into(), "a".repeat(64)]];
        repo.write_event(&old).await.unwrap();
        let mut new = old.clone();
        new.id = format!("{:064x}", 961);
        new.created_at += 1;
        repo.write_event(&new).await.unwrap();
        repo.write_pool.get().unwrap().execute_batch(
            "DROP INDEX event_first_seen_index; PRAGMA user_version=20;").unwrap();
        assert_eq!(repo.migrate_up().await.unwrap(), 21);
        assert!(repo.get_event_by_id(&new.id).await.unwrap().is_some());
        assert!(repo.get_archived_delegation(&old.id).await.unwrap().is_some());
        let indexes: i64 = repo.read_pool.get().unwrap().query_row(
            "SELECT count(*) FROM sqlite_master WHERE name='event_first_seen_index'",
            [], |r| r.get(0)).unwrap();
        assert_eq!(indexes, 1);
    }

    #[tokio::test]
    async fn history_does_not_advance_into_an_open_reception_second() {
        let repo = test_repo().await;
        repo.write_event(&aged_event(969, 31005, 0)).await.unwrap();
        let conn = repo.write_pool.get().unwrap();
        conn.execute("UPDATE event SET first_seen=?", [crate::utils::u64_to_sql(unix_time() + 60)]).unwrap();
        assert!(repo.history_after(0, 10).await.unwrap().is_empty());
        conn.execute("UPDATE event SET first_seen=first_seen-120", []).unwrap();
        assert_eq!(repo.history_after(0, 10).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn history_fence_waits_for_the_inflight_event_commit() {
        let repo = test_repo().await;
        repo.write_event(&aged_event(968, 31005, 0)).await.unwrap();
        let guard = repo.write_in_progress.lock().await;
        let mut conn = repo.write_pool.get().unwrap();
        let tx = conn.transaction().unwrap();
        tx.execute("UPDATE event SET first_seen=100", []).unwrap();
        let reader = repo.clone();
        let mut task = tokio::spawn(async move { reader.history_after(0, 10).await });
        assert!(tokio::time::timeout(Duration::from_millis(50), &mut task).await.is_err(),
                "history advanced before the in-flight event was committed");
        tx.commit().unwrap();
        drop(guard);
        assert_eq!(task.await.unwrap().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn history_does_not_allocate_or_skip_an_oversized_stored_event() {
        let repo = test_repo().await;
        let mut event = aged_event(970, 31021, 0);
        event.content = "x".repeat(crate::repo::MAX_HISTORY_PAGE_BYTES);
        repo.write_event(&event).await.unwrap();
        repo.write_pool.get().unwrap().execute("UPDATE event SET first_seen = 100", []).unwrap();
        assert!(matches!(repo.history_after(0, 10).await,
                         Err(crate::error::Error::HistoryEventTooLarge)));
        let conn = repo.read_pool.get().unwrap();
        let mut stmt = conn.prepare(&history_sql()).unwrap();
        let (size, payload): (i64, Option<String>) = stmt.query_row(
            params![0, Vec::<u8>::new(), 200, 10], |r| Ok((r.get(1)?, r.get(2)?))).unwrap();
        assert!(size > crate::repo::MAX_HISTORY_PAGE_BYTES as i64);
        assert!(payload.is_none(), "SQLite itself must not materialize an oversized payload");
    }

    #[tokio::test]
    async fn inbox_filters_recipient_expiry_and_uses_receipt_order() {
        let repo = inbox_fixture().await;
        let recipient = "a".repeat(64);
        let rows = repo.inbox_after_id(&recipient, 0, "", 5000).await.unwrap();
        assert_eq!(rows.iter().map(|(_, e)| e.id.clone()).collect::<Vec<_>>(),
                   [1001, 1002].map(|id| format!("{id:064x}")));
        let foreign = repo.inbox_after_id(&"b".repeat(64), 0, "", 5000).await.unwrap();
        assert_eq!(foreign.len(), 1);
        assert_eq!(foreign[0].1.id, format!("{:064x}", 1003));
        let conn = repo.write_pool.get().unwrap();
        // Corrupt JSON outside the selected recipient/kinds must not be parsed.
        conn.execute("UPDATE event SET content='not JSON' WHERE event_hash IN (?,?)",
            params![hex::decode(format!("{:064x}", 1003)).unwrap(),
                    hex::decode(format!("{:064x}", 1004)).unwrap()]).unwrap();
        conn.execute("UPDATE event SET first_seen=101 WHERE event_hash=?",
            [hex::decode(format!("{:064x}", 1001)).unwrap()]).unwrap();
        let page = repo.inbox_after_id(&recipient, 100, "", 1).await.unwrap();
        assert_eq!((page[0].0, page[0].1.id.clone()), (100, format!("{:064x}", 1002)));
        let page = repo.inbox_after_id(&recipient, 100, &page[0].1.id, 1).await.unwrap();
        assert_eq!((page[0].0, page[0].1.id.clone()), (101, format!("{:064x}", 1001)));
        assert!(repo.inbox_after_id(&recipient, 101, &page[0].1.id, 1).await.unwrap().is_empty());
        conn.execute("UPDATE event SET expires_at=? WHERE event_hash=?",
            params![crate::utils::u64_to_sql(unix_time()), hex::decode(&page[0].1.id).unwrap()]).unwrap();
        assert!(repo.inbox_after_id(&recipient, 101, "", 1).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn inbox_work_budget_interrupts_large_recipient_even_at_end_cursor() {
        let repo = inbox_large_recipient_fixture().await;
        for after in [0, 101] {
            let result = repo.inbox_after_id(&"a".repeat(64), after, "", 1).await;
            assert!(matches!(result, Err(SqlError(rusqlite::Error::SqliteFailure(ref error, _)))
                if error.code == rusqlite::ErrorCode::OperationInterrupted),
                "recipient work must fail explicitly, including an empty end cursor: {result:?}");
        }
        {
            let conn = repo.read_pool.get().unwrap();
            let _budget = InboxWorkBudget::install(&conn).unwrap();
            let mut stmt = conn.prepare(&inbox_sql()).unwrap();
            let mut rows = stmt.query(params![101, Vec::<u8>::new(),
                crate::utils::u64_to_sql(unix_time()), crate::utils::u64_to_sql(unix_time()),
                "a".repeat(64), 1]).unwrap();
            assert!(matches!(rows.next(), Err(rusqlite::Error::SqliteFailure(ref error, _))
                if error.code == rusqlite::ErrorCode::OperationInterrupted));
            drop(rows);
            let steps = stmt.get_status(rusqlite::StatementStatus::VmStep) as usize;
            println!("100k recipient end-cursor VM steps: {steps}, budget: {INBOX_VM_STEP_BUDGET}");
            assert!(steps >= INBOX_VM_STEP_BUDGET - INBOX_PROGRESS_INTERVAL as usize);
            assert!(steps <= INBOX_VM_STEP_BUDGET + INBOX_PROGRESS_INTERVAL as usize);
        }
        assert!(repo.inbox_after_id(&"b".repeat(64), 0, "", 1).await.unwrap().is_empty());
        // Every pooled connection must be usable without the inbox work budget.
        for conn in hold_readers(&repo) {
            let sum: i64 = conn.query_row(
                "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<200000) \
                 SELECT sum(x) FROM n", [], |row| row.get(0)).unwrap();
            assert_eq!(sum, 20_000_100_000);
        }
    }

    #[tokio::test]
    async fn inbox_query_plan_starts_with_recipient_index_and_rowid_lookups() {
        let repo = test_repo().await;
        let conn = repo.read_pool.get().unwrap();
        let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {}", inbox_sql())).unwrap();
        let plan = stmt.query_map(params![0, Vec::<u8>::new(), 200, 200, "a".repeat(64), 250],
            |r| r.get::<_, String>(3)).unwrap()
            .collect::<std::result::Result<Vec<_>, _>>().unwrap().join(" ");
        println!("inbox query plan: {plan}");
        assert_eq!(plan.matches("SEARCH event USING INTEGER PRIMARY KEY (rowid=?)").count(), 2,
                   "both metadata and payload must use rowid lookups: {plan}");
        assert!(plan.contains("USING COVERING INDEX tag_name_value_index (name=? AND value=?)"), "{plan}");
        assert!(!plan.contains("event_first_seen_index"), "global receipt scan: {plan}");
        assert!(!plan.contains("SCAN event") && !plan.contains("SCAN tag"), "{plan}");
        assert!(plan.contains("CO-ROUTINE page") && plan.contains("CORRELATED SCALAR SUBQUERY"),
                "JSON lookup must remain outside the metadata sort: {plan}");
    }

    #[tokio::test]
    async fn inbox_unrelated_recipients_do_not_increase_work_or_duplicate_p_events() {
        fn query_steps(repo: &SqliteRepo, recipient: &str, expected: &[String]) -> i32 {
            let conn = repo.read_pool.get().unwrap();
            let mut stmt = conn.prepare(&inbox_sql()).unwrap();
            let ids = stmt.query_map(params![0, Vec::<u8>::new(), 200, 200, recipient, 250],
                |row| row.get::<_, String>(2)).unwrap()
                .map(|payload| serde_json::from_str::<Event>(&payload.unwrap()).unwrap().id)
                .collect::<Vec<_>>();
            assert_eq!(ids, expected);
            stmt.get_status(rusqlite::StatementStatus::VmStep)
        }

        let repo = test_repo().await;
        let recipient = "a".repeat(64);
        for seed in [1402, 1401] {
            let mut event = inbox_event(seed, 1059, &recipient);
            event.tags.push(vec!["p".into(), recipient.clone()]);
            repo.write_event(&event).await.unwrap();
        }
        repo.write_pool.get().unwrap().execute("UPDATE event SET first_seen=100", []).unwrap();
        let duplicate_tags: i64 = repo.read_pool.get().unwrap().query_row(
            "SELECT count(*) FROM tag WHERE name='p' AND value=?", [&recipient], |r| r.get(0)).unwrap();
        assert_eq!(duplicate_tags, 4, "fixture must contain actual duplicate p rows");
        let expected = [1401, 1402].map(|id| format!("{id:064x}"));
        let idle = "f".repeat(64);
        let before = query_steps(&repo, &recipient, &expected);
        let idle_before = query_steps(&repo, &idle, &[]);

        for seed in 3000..5048 {
            repo.write_event(&inbox_event(seed, if seed % 2 == 0 { 1059 } else { 31033 },
                &format!("{seed:064x}"))).await.unwrap();
        }
        let conn = repo.write_pool.get().unwrap();
        conn.execute("UPDATE event SET first_seen=100", []).unwrap();
        conn.execute("UPDATE event SET content='not JSON' WHERE id IN \
                      (SELECT event_id FROM tag WHERE name='p' AND value!=?)", [&recipient]).unwrap();
        drop(conn);
        let after = query_steps(&repo, &recipient, &expected);
        let idle_after = query_steps(&repo, &idle, &[]);
        println!("inbox VM steps before/after 2048 other recipients: {before}/{after}; idle: {idle_before}/{idle_after}");
        assert!(after <= before + 32, "other recipients increased VM steps: {before} -> {after}");
        assert!(idle_after <= idle_before + 32, "idle recipient scanned other history: {idle_before} -> {idle_after}");
    }

    #[tokio::test]
    async fn inbox_byte_limited_continuation_never_skips_rows() {
        let repo = test_repo().await;
        let recipient = "a".repeat(64);
        for seed in 1100..1124 {
            let mut event = inbox_event(seed, 1059, &recipient);
            event.content = "x".repeat(120_000);
            repo.write_event(&event).await.unwrap();
        }
        repo.write_pool.get().unwrap().execute("UPDATE event SET first_seen=100", []).unwrap();
        let mut cursor = (0, String::new());
        let mut seen = Vec::new();
        let mut pages = 0;
        loop {
            let page = repo.inbox_after_id(&recipient, cursor.0, &cursor.1, 250).await.unwrap();
            if page.is_empty() { break; }
            assert!(serde_json::to_vec(&page).unwrap().len() < crate::repo::MAX_HISTORY_PAGE_BYTES);
            cursor = page.last().map(|(fs, e)| (*fs, e.id.clone())).unwrap();
            seen.extend(page.into_iter().map(|(_, e)| e.id));
            pages += 1;
            assert!(pages <= 24, "cursor failed to advance");
        }
        assert_eq!(pages, 2);
        assert_eq!(seen, (1100..1124).map(|id| format!("{id:064x}")).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn inbox_oversized_payload_is_not_materialized_or_silently_skipped() {
        let repo = test_repo().await;
        let recipient = "a".repeat(64);
        let mut event = inbox_event(1200, 1059, &recipient);
        event.content = "x".repeat(crate::repo::MAX_HISTORY_PAGE_BYTES);
        repo.write_event(&event).await.unwrap();
        repo.write_pool.get().unwrap().execute("UPDATE event SET first_seen=100", []).unwrap();
        assert!(matches!(repo.inbox_after_id(&recipient, 0, "", 250).await,
            Err(crate::error::Error::HistoryEventTooLarge)));
        let conn = repo.read_pool.get().unwrap();
        let (size, payload): (i64, Option<String>) = conn.prepare(&inbox_sql()).unwrap().query_row(
            params![0, Vec::<u8>::new(), 200, 200, recipient, 250],
            |r| Ok((r.get(1)?, r.get(2)?))).unwrap();
        assert!(size > crate::repo::MAX_HISTORY_PAGE_BYTES as i64);
        assert!(payload.is_none());
    }

    #[tokio::test]
    async fn inbox_fence_waits_for_inflight_commit_and_seals_reception_seconds() {
        let repo = test_repo().await;
        let recipient = "a".repeat(64);
        repo.write_event(&inbox_event(1300, 1059, &recipient)).await.unwrap();
        let guard = repo.write_in_progress.lock().await;
        let mut conn = repo.write_pool.get().unwrap();
        let tx = conn.transaction().unwrap();
        tx.execute("UPDATE event SET first_seen=100", []).unwrap();
        let (reader, address) = (repo.clone(), recipient.clone());
        let mut task = tokio::spawn(async move { reader.inbox_after_id(&address, 0, "", 250).await });
        assert!(tokio::time::timeout(Duration::from_millis(50), &mut task).await.is_err());
        tx.commit().unwrap();
        drop(guard);
        assert_eq!(task.await.unwrap().unwrap().len(), 1);
        conn.execute("UPDATE event SET first_seen=?", [crate::utils::u64_to_sql(unix_time() + 60)]).unwrap();
        assert!(repo.inbox_after_id(&recipient, 0, "", 250).await.unwrap().is_empty());
    }

    /// Expiration must use the SAME clock sample as the intake upper bound.
    ///
    /// The query previously read the clock a SECOND time, enabling the reviewer's second
    /// counterexample: a row expired at the verified instant became eligible again after
    /// clock rollback, without any database write or publication-guard signal.
    ///
    /// Test BOTH sides. The second is an observable behavior change without rollback: a
    /// row expiring between sampling and query execution used to be filtered and is now
    /// returned. The contract says "expired at the sealed instant," not "expired when the
    /// response was sent," so record this explicitly to prevent it looking like a future
    /// regression. A schema newer than this build understands is an ERROR, not a panic.
    ///
    /// This used to `panic!` in a worker thread without stopping the node. A 2026-09-14
    /// run against a newer database panicked during migration yet ACCEPTED an event that
    /// could be read back. The node served a schema it refused to understand while
    /// `/v1/health` returned "ok."
    ///
    /// This test fails if the error becomes a panic again, or if it is collapsed into a
    /// generic SQL error. Operators must distinguish "schema too new" from "query failed"
    /// because the remedies differ.
    #[tokio::test]
    async fn schema_newer_than_this_build_is_refused_by_value_not_by_panic() {
        let repo = test_repo().await;
        {
            let conn = repo.write_pool.get().unwrap();
            conn.execute_batch(&format!(
                "PRAGMA user_version = {};",
                crate::repo::sqlite_migration::DB_VERSION + 1))
                .unwrap();
        }
        let outcome = repo.migrate_up().await;
        match outcome {
            Err(crate::error::Error::DatabaseSchemaTooNew { found, supported }) => {
                assert_eq!(supported, crate::repo::sqlite_migration::DB_VERSION);
                assert_eq!(found, crate::repo::sqlite_migration::DB_VERSION + 1);
            }
            other => panic!("expected a dedicated schema error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn inbox_expiry_is_judged_by_the_checked_sample_not_a_second_clock_read() {
        let repo = test_repo().await;
        let recipient = "a".repeat(64);
        repo.write_event(&inbox_event(1300, 1059, &recipient)).await.unwrap();
        let conn = repo.write_pool.get().unwrap();
        conn.execute("UPDATE event SET first_seen=100", []).unwrap();

        // Alive AT SEALED INSTANT 200, although wall time says it expired long ago. A
        // second clock read would filter it, losing data without any database write.
        conn.execute("UPDATE event SET expires_at=1000", []).unwrap();
        let page = repo.inbox_page_at(&recipient, 0, "", 250, 200).await.unwrap();
        assert_eq!(page.len(), 1,
            "row alive at the verified instant was filtered by a second clock read: {page:?}");

        // Opposite side: expired BY THE SEALED instant. A later clock reading that moved
        // backward would consider it live, reproducing the resurrection counterexample.
        let sealed = unix_time() + 7200;
        conn.execute("UPDATE event SET expires_at=?",
            [crate::utils::u64_to_sql(unix_time() + 3600)]).unwrap();
        assert!(repo.inbox_page_at(&recipient, 0, "", 250, sealed).await.unwrap().is_empty(),
            "row expired at the verified instant was revived by a second clock read");
    }

    fn aged_event(id_seed: u32, kind: u64, age_days: u64) -> Event {
        Event {
            id: format!("{id_seed:064x}"),
            pubkey: "b".repeat(64),
            delegated_by: None,
            created_at: crate::utils::unix_time().saturating_sub(age_days * 86_400),
            kind,
            tags: vec![],
            content: format!("event {id_seed}"),
            sig: "c".repeat(128),
            tagidx: None,
        }
    }

    /// Nothing bounded database growth: `messages_per_sec` limits RATE, not volume, and
    /// upstream declared `[retention]` without implementing it. A 2026-08-29 measurement
    /// put one public A4A event at about 6.4 KiB on disk, nine times its wire size because
    /// every tag becomes an indexed row. At the relay's own rate limit, one author can
    /// consume 6.8 GiB in roughly three hours.
    #[tokio::test]
    async fn aged_events_are_deleted_by_kind() {
        let repo = test_repo().await;
        for (i, (kind, age)) in [(31002u64, 40u64), (31002, 5), (31004, 400)]
            .iter()
            .enumerate()
        {
            repo.write_event(&aged_event(i as u32 + 1, *kind, *age))
                .await
                .unwrap();
        }
        let mut conn = repo.write_pool().get().unwrap();
        let kinds = std::collections::HashMap::from([(31002u64, 30usize)]);
        let removed = delete_aged(&mut conn, None, &kinds, &[]).unwrap();
        drop(conn);

        assert_eq!(removed, 1, "wrong number of events deleted");
        assert!(
            repo.get_event_by_id(&format!("{:064x}", 1)).await.unwrap().is_none(),
            "stale request was not deleted"
        );
        assert!(
            repo.get_event_by_id(&format!("{:064x}", 2)).await.unwrap().is_some(),
            "fresh request was deleted by age"
        );
        assert!(
            repo.get_event_by_id(&format!("{:064x}", 3)).await.unwrap().is_some(),
            "agreement was deleted by a REQUEST limit, erasing reputation history"
        );
    }

    /// Like `test_repo`, but also returns the database directory because FILE-SIZE tests
    /// need a path, not only a repository.
    async fn test_repo_with_dir() -> (SqliteRepo, std::path::PathBuf) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = DIR_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "nostr_rs_relay_vac_{}_{}",
            std::process::id(),
            n
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut settings = Settings::default();
        settings.database.data_directory = dir.to_string_lossy().to_string();
        settings.database.min_conn = 1;
        settings.database.max_conn = 2;
        let repo = SqliteRepo::new(&settings, test_metrics());
        repo.migrate_up().await.unwrap();
        (repo, dir)
    }

    /// Deleting events must RETURN SPACE rather than only remove rows.
    ///
    /// Production measurement on 2026-08-29: `pragma auto_vacuum` = 0, and deleting
    /// 7,000 of 13,853 events returned zero bytes to the OS. This is not an optimization:
    /// a node whose disk fills once cannot recover, because the file stays at peak size
    /// and a full disk has no room to run VACUUM.
    #[tokio::test]
    async fn deleting_events_returns_space_to_the_os() {
        let (repo, dir) = test_repo_with_dir().await;
        let path = dir.join(DB_FILE);

        for i in 0..400u32 {
            let mut ev = aged_event(i, 31002, 1);
            ev.content = "x".repeat(4000);
            ev.tags = vec![vec!["expiration".to_owned(), "1".to_owned()]];
            ev.build_index();
            repo.write_event(&ev).await.unwrap();
        }
        let mut conn = repo.write_pool().get().unwrap();
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
        let before = std::fs::metadata(&path).unwrap().len();
        assert!(before > 512 * 1024, "database did not grow; test setup is invalid: {before}");

        // Match relay startup: configure the mode before cleanup. Without incremental
        // vacuum this would be a no-op and the file would retain the space.
        assert!(ensure_incremental_vacuum(&mut conn, 1024 * 1024 * 1024).unwrap());
        assert!(delete_expired(&mut conn, &[]).unwrap() > 0);
        let freed = release_free_pages(&conn, 100_000).unwrap();
        assert!(freed > 100, "only {freed} pages reclaimed; pragma did not run to completion");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
        let after = std::fs::metadata(&path).unwrap().len();

        assert!(
            after < before / 2,
            "file remained {after} bytes after deletion versus {before}; space was not returned"
        );
    }

    /// The size ceiling deletes disposable events and returns space.
    ///
    /// A per-author limit counts ITEMS: 5,000 events at 128 KiB each consume 640 MiB per
    /// key, and keys are free. Fifteen keys fill the node disk without exceeding any
    /// author's 5,000-event limit. Bound the resource that runs out.
    #[tokio::test]
    async fn size_budget_removes_expendable_events() {
        let (repo, _dir) = test_repo_with_dir().await;
        for i in 0..300u32 {
            let mut ev = aged_event(i, 31002, 1);
            ev.content = "x".repeat(4000);
            ev.build_index();
            repo.write_event(&ev).await.unwrap();
        }
        let mut conn = repo.write_pool().get().unwrap();
        ensure_incremental_vacuum(&mut conn, 1024 * 1024 * 1024).unwrap();
        let before = database_bytes(&conn).unwrap();
        assert!(before > 512 * 1024, "database did not grow; test setup is invalid: {before}");

        let removed = enforce_size_budget(&mut conn, before / 2, &[]).unwrap();
        let after = database_bytes(&conn).unwrap();
        assert!(removed > 0, "no events were deleted");
        assert!(after <= before / 2, "database is {after} bytes against ceiling {}", before / 2);
    }

    /// History is NEVER deleted for space, even when the ceiling is exceeded.
    ///
    /// Agreements, revocations, trust, credentials, and delegations constitute
    /// reputation. Reputation disappearing under disk pressure is worse than refusing a
    /// write: refusal is visible immediately, while erased history is invisible and lost.
    #[tokio::test]
    async fn size_budget_never_touches_reputation_history() {
        let (repo, _dir) = test_repo_with_dir().await;
        for (i, kind) in (0..200u32).map(|i| (i, [31004u64, 31005, 31020, 31021, 31000][(i % 5) as usize])) {
            let mut ev = aged_event(i, kind, 1);
            ev.content = "x".repeat(4000);
            ev.build_index();
            repo.write_event(&ev).await.unwrap();
        }
        let mut conn = repo.write_pool().get().unwrap();
        ensure_incremental_vacuum(&mut conn, 1024 * 1024 * 1024).unwrap();
        let before: i64 = conn
            .query_row("SELECT count(*) FROM event", [], |r| r.get(0))
            .unwrap();

        let removed = enforce_size_budget(&mut conn, 1, &[]).unwrap();
        let after: i64 = conn
            .query_row("SELECT count(*) FROM event", [], |r| r.get(0))
            .unwrap();
        assert_eq!(removed, 0, "history was deleted for space");
        assert_eq!(before, after, "event count changed: {before} -> {after}");
    }

    /// Cleanup changes nothing while the database remains within its ceiling.
    #[tokio::test]
    async fn size_budget_is_a_noop_below_the_cap() {
        let (repo, _dir) = test_repo_with_dir().await;
        for i in 0..20u32 {
            let ev = aged_event(i, 31002, 1);
            repo.write_event(&ev).await.unwrap();
        }
        let mut conn = repo.write_pool().get().unwrap();
        assert_eq!(enforce_size_budget(&mut conn, 1024 * 1024 * 1024, &[]).unwrap(), 0);
        let left: i64 = conn
            .query_row("SELECT count(*) FROM event", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 20, "events were deleted unnecessarily");
    }

    /// A database created by an older version with auto_vacuum = 0 migrates at startup.
    #[tokio::test]
    async fn legacy_database_is_switched_to_incremental_vacuum() {
        let (repo, _dir) = test_repo_with_dir().await;
        let mut conn = repo.write_pool().get().unwrap();
        // Reproduce the production database state with no vacuum mode.
        conn.execute_batch("PRAGMA auto_vacuum = NONE; VACUUM;").unwrap();
        let before: i64 = conn.query_row("PRAGMA auto_vacuum;", [], |r| r.get(0)).unwrap();
        assert_eq!(before, 0, "could not reproduce the production database state");

        assert!(ensure_incremental_vacuum(&mut conn, 1024 * 1024 * 1024).unwrap());
        let after: i64 = conn.query_row("PRAGMA auto_vacuum;", [], |r| r.get(0)).unwrap();
        assert_eq!(after, 2, "mode did not switch to incremental");
    }

    /// A large database is NEVER rebuilt silently at startup.
    ///
    /// Rebuilding needs free space roughly equal to database size and holds a lock. Doing
    /// this without operator choice on a multi-gigabyte database can take the node down
    /// for housekeeping.
    #[tokio::test]
    async fn oversized_database_is_not_rebuilt_silently() {
        let (repo, _dir) = test_repo_with_dir().await;
        let mut conn = repo.write_pool().get().unwrap();
        conn.execute_batch("PRAGMA auto_vacuum = NONE; VACUUM;").unwrap();

        assert!(!ensure_incremental_vacuum(&mut conn, 1).unwrap(),
                "database was rebuilt despite the threshold");
        let mode: i64 = conn.query_row("PRAGMA auto_vacuum;", [], |r| r.get(0)).unwrap();
        assert_eq!(mode, 0, "mode switched despite the threshold");
    }

    /// Page-cache size comes from configuration rather than a hard-coded value.
    ///
    /// Upstream used 80 MiB PER CONNECTION. With up to eight readers this consumed as
    /// much as 800 MiB for cache alone, exceeding typical node memory and explaining the
    /// observed RSS growth under load.
    #[tokio::test]
    async fn page_cache_size_comes_from_settings() {
        let dir = std::env::temp_dir().join(format!("nostr_rs_relay_cache_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut settings = Settings::default();
        settings.database.data_directory = dir.to_string_lossy().to_string();
        settings.database.min_conn = 1;
        settings.database.max_conn = 1;
        settings.database.cache_size_mb = 3;
        let repo = SqliteRepo::new(&settings, test_metrics());
        repo.migrate_up().await.unwrap();

        let conn = repo.write_pool().get().unwrap();
        let cache: i64 = conn.query_row("PRAGMA main.cache_size;", [], |r| r.get(0)).unwrap();
        // A negative value means KiB; otherwise size would depend on page_size.
        assert_eq!(cache, -3 * 1024, "cache did not come from configuration: {cache}");
    }

    /// Deleting an event must delete its tags too.
    ///
    /// The schema declares `ON DELETE CASCADE` for `tag`, but SQLite defaults
    /// `PRAGMA foreign_keys` to OFF. If never enabled, cascade does not run and tag rows
    /// become orphans. This is material: a 2026-08-29 measurement put an event at 6,437
    /// bytes on disk versus about 700 on the wire because tags become indexed rows. If
    /// cleanup leaves them behind, almost no disk is freed and retention is illusory.
    #[tokio::test]
    async fn deleting_an_event_removes_its_tags() {
        let repo = test_repo().await;
        let mut ev = aged_event(70, 31002, 1);
        ev.tags = vec![
            vec!["expiration".to_owned(), "1".to_owned()],
            vec!["category".to_owned(), "design".to_owned()],
            vec!["t".to_owned(), "a4a:cat:design".to_owned()],
        ];
        ev.build_index();
        repo.write_event(&ev).await.unwrap();

        let conn = repo.write_pool().get().unwrap();
        let before: i64 = conn
            .query_row("SELECT count(*) FROM tag", [], |r| r.get(0))
            .unwrap();
        assert!(before > 0, "tags were not stored; test setup is invalid");
        drop(conn);

        let mut conn = repo.write_pool().get().unwrap();
        delete_expired(&mut conn, &[]).unwrap();
        let after: i64 = conn
            .query_row("SELECT count(*) FROM tag", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            after, 0,
            "{after} tag rows remained after event deletion, so disk cannot be reclaimed"
        );
    }

    /// An expired mandate must not be erased. For delegations, `expiration` means mandate
    /// lifetime but shares the NIP-40 tag name. Deleting it makes old agent events
    /// unverifiable, while deleting a revocation would restore the revoked delegation.
    #[tokio::test]
    async fn expired_delegations_and_revocations_survive_cleanup() {
        let repo = test_repo().await;
        let past = crate::utils::unix_time().saturating_sub(3600);
        for (i, kind) in [(1u32, 31000u64), (2, 31007), (3, 31002)] {
            let mut ev = aged_event(i, kind, 1);
            ev.tags = vec![vec!["expiration".to_owned(), past.to_string()]];
            repo.write_event(&ev).await.unwrap();
        }
        let mut conn = repo.write_pool().get().unwrap();
        let removed = delete_expired(&mut conn, &[]).unwrap();
        drop(conn);

        assert_eq!(removed, 1, "wrong number of expired events deleted");
        assert!(
            repo.get_event_by_id(&format!("{:064x}", 1)).await.unwrap().is_some(),
            "expired delegation was deleted, making past agent events unverifiable"
        );
        assert!(
            repo.get_event_by_id(&format!("{:064x}", 2)).await.unwrap().is_some(),
            "revocation was deleted, which would restore the revoked delegation"
        );
        assert!(
            repo.get_event_by_id(&format!("{:064x}", 3)).await.unwrap().is_none(),
            "ordinary expired event was not deleted"
        );
    }

    /// Per-key ceiling: age limits data by time, not volume. One key can write
    /// arbitrarily much during the allowed period.
    #[tokio::test]
    async fn prolific_author_is_trimmed_oldest_first() {
        let repo = test_repo().await;
        for i in 0..10u32 {
            // Same author, different ages; oldest must go first.
            repo.write_event(&aged_event(100 + i, 31002, u64::from(10 - i)))
                .await
                .unwrap();
        }
        // Another author with one event must remain untouched.
        let mut other = aged_event(200, 31002, 1);
        other.pubkey = "d".repeat(64);
        repo.write_event(&other).await.unwrap();

        let mut conn = repo.write_pool().get().unwrap();
        let removed = trim_prolific_authors(&mut conn, 4, &[]).unwrap();
        drop(conn);

        assert_eq!(removed, 6, "wrong number of events trimmed");
        assert!(
            repo.get_event_by_id(&format!("{:064x}", 100)).await.unwrap().is_none(),
            "noisy author's oldest event remained"
        );
        assert!(
            repo.get_event_by_id(&format!("{:064x}", 109)).await.unwrap().is_some(),
            "noisy author's fresh event was deleted; trimming started at the wrong end"
        );
        assert!(
            repo.get_event_by_id(&format!("{:064x}", 200)).await.unwrap().is_some(),
            "unrelated author was affected"
        );
    }

    /// The per-author ceiling must preserve history just like the size ceiling.
    ///
    /// Before 2026-09-04 it did not: it deleted the oldest events of ANY kind. For an
    /// active agent those are early agreements and reviews, exactly the reputation the
    /// protocol exists to preserve. Worse, deleting a delegation revocation (31007)
    /// restores the revoked delegation, so maintenance could revive an agent.
    /// `config.prod.toml` promises history is never deleted, and adjacent
    /// `enforce_size_budget` keeps that promise. The same rule has another live branch:
    /// without a declared notary, this author's timestamp is disposable and is removed
    /// alongside requests.
    #[tokio::test]
    async fn timestamps_of_an_unknown_author_are_trimmed_like_any_other_event() {
        let repo = test_repo().await;
        for (i, kind) in [(0u32, 31004u64), (1, 31005), (2, 31007), (3, 1040)] {
            repo.write_event(&aged_event(400 + i, kind, 20 + u64::from(i))).await.unwrap();
        }
        for i in 0..10u32 {
            repo.write_event(&aged_event(410 + i, 31002, u64::from(10 - i))).await.unwrap();
        }
        let mut conn = repo.write_pool().get().unwrap();
        // No notary keys: kind 1040 is disposable, so there are 11 disposable events, not 10.
        let removed = trim_prolific_authors(&mut conn, 4, &[]).unwrap();
        drop(conn);
        assert_eq!(removed, 7, "unknown author's timestamp must be trimmed like an ordinary event");
        assert!(
            repo.get_event_by_id(&format!("{:064x}", 403)).await.unwrap().is_none(),
            "foreign timestamp became undeletable, reopening finding 122"
        );
        for i in 0..3u32 {
            assert!(
                repo.get_event_by_id(&format!("{:064x}", 400 + i)).await.unwrap().is_some(),
                "history was deleted: {i}"
            );
        }
    }

    /// Finding 124: timestamp protection examines AUTHOR, not event kind. Otherwise an
    /// operator who starts without a notary as instructed and declares it later makes all
    /// accumulated foreign junk retroactively undeletable.
    #[test]
    fn timestamp_protection_looks_at_the_author_not_just_the_kind() {
        let notary = vec![0xab_u8; 32];
        let (with_keys, args) = protected_sql(std::slice::from_ref(&notary));
        assert!(with_keys.contains("author IN"), "author predicate missing: {with_keys}");
        assert!(with_keys.contains("1040"), "{with_keys}");
        assert_eq!(args.len(), 1, "notary key did not enter query arguments");

        let (without, args) = protected_sql(&[]);
        assert!(!without.contains("1040"), "timestamps must not be protected without a notary: {without}");
        assert!(args.is_empty());

        for k in [31000_u64, 31007, 31004, 31005, 31020, 31021] {
            let kind = k.to_string();
            assert!(with_keys.contains(&kind), "history must be protected: {kind}");
            assert!(without.contains(&kind), "history must always be protected: {kind}");
        }
    }

    #[tokio::test]
    async fn trimming_a_prolific_author_never_touches_protected_history() {
        let repo = test_repo().await;
        // Protected events are OLDEST (20+ days), so they used to be deleted first.
        // Kind 1040 is a timestamp emitted about 50 times per hour by one author;
        // trimming would consume history.
        for (i, kind) in [(0u32, 31004u64), (1, 31005), (2, 31007), (3, 1040)] {
            repo.write_event(&aged_event(300 + i, kind, 20 + u64::from(i)))
                .await
                .unwrap();
        }
        // Disposable requests are newer, from 10 days old (id 310) to 1 day (id 319).
        for i in 0..10u32 {
            repo.write_event(&aged_event(310 + i, 31002, u64::from(10 - i)))
                .await
                .unwrap();
        }

        let mut conn = repo.write_pool().get().unwrap();
        // Declare the test author as this node's notary so its kind-1040 timestamps are
        // protected like history (finding 124: protection examines author).
        let notary = vec![hex::decode("b".repeat(64)).unwrap()];
        let removed = trim_prolific_authors(&mut conn, 4, &notary).unwrap();
        drop(conn);

        // Ten disposable events with a cap of four means six removed. Protected events
        // do not count at all.
        assert_eq!(removed, 6, "wrong number of disposable events trimmed");
        for i in 0..4u32 {
            assert!(
                repo.get_event_by_id(&format!("{:064x}", 300 + i))
                    .await
                    .unwrap()
                    .is_some(),
                "trimming erased protected history (event {}) despite the configuration \
                 promising permanent retention",
                300 + i
            );
        }
        assert!(
            repo.get_event_by_id(&format!("{:064x}", 310)).await.unwrap().is_none(),
            "oldest disposable request remained, so trimming did not run"
        );
        assert!(
            repo.get_event_by_id(&format!("{:064x}", 319)).await.unwrap().is_some(),
            "fresh request was deleted; trimming started at the wrong end"
        );
    }

    /// The global ceiling applies to disposable kinds without a dedicated one.
    #[tokio::test]
    async fn global_retention_applies_to_kinds_without_their_own() {
        let repo = test_repo().await;
        repo.write_event(&aged_event(10, 31006, 500)).await.unwrap();
        repo.write_event(&aged_event(11, 31006, 10)).await.unwrap();
        let mut conn = repo.write_pool().get().unwrap();
        let removed = delete_aged(&mut conn, Some(365), &Default::default(), &[]).unwrap();
        drop(conn);
        assert_eq!(removed, 1);
        assert!(repo.get_event_by_id(&format!("{:064x}", 11)).await.unwrap().is_some());
    }

    /// Age retention must obey the same permanent-history boundary as the per-author
    /// and database-size ceilings. Previously only those two paths used
    /// `protected_sql`; a global age limit deleted agreements, reviews, trust,
    /// credentials, delegations, and revocations despite the operator documentation.
    #[tokio::test]
    async fn age_retention_never_deletes_protocol_history_or_declared_notary_timestamps() {
        let repo = test_repo().await;
        for (offset, kind) in PROTECTED_KINDS.iter().enumerate() {
            repo.write_event(&aged_event(100 + offset as u32, *kind, 500))
                .await
                .unwrap();
        }
        let declared_stamp = aged_event(200, crate::a4a_delegation::A4A_KIND_TIMESTAMP, 500);
        repo.write_event(&declared_stamp).await.unwrap();
        let mut foreign_stamp = aged_event(201, crate::a4a_delegation::A4A_KIND_TIMESTAMP, 500);
        foreign_stamp.pubkey = "c".repeat(64);
        repo.write_event(&foreign_stamp).await.unwrap();
        repo.write_event(&aged_event(202, 31006, 500)).await.unwrap();

        let notary_keys = vec![hex::decode("b".repeat(64)).unwrap()];
        let kinds = std::collections::HashMap::from([
            (31004u64, 1usize),
            (crate::a4a_delegation::A4A_KIND_TIMESTAMP, 1usize),
        ]);
        let mut conn = repo.write_pool().get().unwrap();
        let removed = delete_aged(&mut conn, Some(365), &kinds, &notary_keys).unwrap();
        drop(conn);

        assert_eq!(removed, 2, "only disposable data and the foreign timestamp should expire");
        for offset in 0..PROTECTED_KINDS.len() {
            assert!(repo.get_event_by_id(&format!("{:064x}", 100 + offset)).await.unwrap().is_some());
        }
        assert!(repo.get_event_by_id(&format!("{:064x}", 200)).await.unwrap().is_some());
        assert!(repo.get_event_by_id(&format!("{:064x}", 201)).await.unwrap().is_none());
        assert!(repo.get_event_by_id(&format!("{:064x}", 202)).await.unwrap().is_none());
    }

    /// NIP-40 cleanup is another retention path and must preserve the same history.
    /// An `expiration` tag on an agreement or review must not erase evidence, and an
    /// expired declared-notary timestamp remains necessary to verify the past.
    #[tokio::test]
    async fn nip40_cleanup_never_deletes_protocol_history_or_declared_notary_timestamps() {
        let repo = test_repo().await;
        let past = crate::utils::unix_time().saturating_sub(3600).to_string();
        for (offset, kind) in PROTECTED_KINDS.iter().enumerate() {
            let mut event = aged_event(300 + offset as u32, *kind, 1);
            event.tags = vec![vec!["expiration".to_owned(), past.clone()]];
            event.build_index();
            repo.write_event(&event).await.unwrap();
        }
        let mut declared_stamp =
            aged_event(400, crate::a4a_delegation::A4A_KIND_TIMESTAMP, 1);
        declared_stamp.tags = vec![vec!["expiration".to_owned(), past.clone()]];
        declared_stamp.build_index();
        repo.write_event(&declared_stamp).await.unwrap();
        for (seed, pubkey, kind) in [(401, "c".repeat(64), 1040u64), (402, "b".repeat(64), 31006)] {
            let mut event = aged_event(seed, kind, 1);
            event.pubkey = pubkey;
            event.tags = vec![vec!["expiration".to_owned(), past.clone()]];
            event.build_index();
            repo.write_event(&event).await.unwrap();
        }

        let notary_keys = vec![hex::decode("b".repeat(64)).unwrap()];
        let mut conn = repo.write_pool().get().unwrap();
        let removed = delete_expired(&mut conn, &notary_keys).unwrap();
        drop(conn);

        assert_eq!(removed, 2, "only disposable data and the foreign timestamp should expire");
        for offset in 0..PROTECTED_KINDS.len() {
            assert!(repo.get_event_by_id(&format!("{:064x}", 300 + offset)).await.unwrap().is_some());
        }
        assert!(repo.get_event_by_id(&format!("{:064x}", 400)).await.unwrap().is_some());
        assert!(repo.get_event_by_id(&format!("{:064x}", 401)).await.unwrap().is_none());
        assert!(repo.get_event_by_id(&format!("{:064x}", 402)).await.unwrap().is_none());
    }

    /// Without configuration, delete nothing; operator data must never vanish silently.
    #[tokio::test]
    async fn retention_is_off_unless_configured() {
        let repo = test_repo().await;
        repo.write_event(&aged_event(20, 31002, 10_000)).await.unwrap();
        let mut conn = repo.write_pool().get().unwrap();
        let removed = delete_aged(&mut conn, None, &Default::default(), &[]).unwrap();
        drop(conn);
        assert_eq!(removed, 0, "retention ran despite being unconfigured");
    }

    #[tokio::test]
    async fn get_event_by_id_returns_matching_event() {
        let repo = test_repo().await;
        let event = Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            delegated_by: None,
            created_at: 1_000,
            kind: 1,
            tags: vec![],
            content: "hello get_event_by_id".to_owned(),
            sig: "c".repeat(128),
            tagidx: None,
        };
        let count = repo.write_event(&event).await.unwrap();
        assert_eq!(count, 1);

        let found = repo
            .get_event_by_id(&event.id)
            .await
            .unwrap()
            .expect("event should be found");
        assert_eq!(found.id, event.id);
        assert_eq!(found.content, event.content);
    }

    /// Regression test for the `delegated_by` transient field: `Event`
    /// marks `delegated_by` as `#[serde(skip)]`, so it is never present in
    /// the JSON `content` stored on disk. `get_event_by_id` must recompute
    /// it (via `Event::update_delegation`) from the preserved `delegation`
    /// tag rather than returning `None` unconditionally.
    #[tokio::test]
    async fn get_event_by_id_restores_delegated_by() {
        use bitcoin_hashes::{sha256, Hash};
        use secp256k1::{Keypair, Secp256k1};

        let repo = test_repo().await;

        // Build a genuinely valid NIP-26 delegation tag, so
        // `update_delegation()` actually resolves `delegated_by` to
        // `Some(..)` instead of trivially staying `None` on both sides.
        let secp = Secp256k1::new();
        let mut rng = secp256k1::rand::thread_rng();
        let delegator_keypair = Keypair::new(&secp, &mut rng);
        // In secp256k1 0.30, `public_key()` returns a FULL 66-hex-character key while
        // Nostr uses 64-character x-only keys. The mismatch is silent until pubkey parsing
        // fails during event validation.
        let delegator_pubkey_hex = delegator_keypair.x_only_public_key().0.to_string();

        let delegatee_pubkey = "d".repeat(64);
        let cond_query = "kind=1";
        let tok = format!("nostr:delegation:{delegatee_pubkey}:{cond_query}");
        let digest = sha256::Hash::hash(tok.as_bytes());
        let sig = secp.sign_schnorr_no_aux_rand(digest.as_ref(), &delegator_keypair);
        let sig_hex = sig.to_string();

        let mut event = Event {
            id: "e".repeat(64),
            pubkey: delegatee_pubkey,
            delegated_by: None,
            created_at: 1_000,
            kind: 1,
            tags: vec![vec![
                "delegation".to_owned(),
                delegator_pubkey_hex.clone(),
                cond_query.to_owned(),
                sig_hex,
            ]],
            content: "delegated event".to_owned(),
            sig: "f".repeat(128),
            tagidx: None,
        };
        // sanity check: the delegation tag we built is actually valid, so
        // `update_delegation()` resolves to `Some(delegator)`.
        event.update_delegation();
        assert_eq!(event.delegated_by, Some(delegator_pubkey_hex.clone()));

        let count = repo.write_event(&event).await.unwrap();
        assert_eq!(count, 1);

        let found = repo
            .get_event_by_id(&event.id)
            .await
            .unwrap()
            .expect("event should be found");
        assert_eq!(found.delegated_by, Some(delegator_pubkey_hex));
    }

    #[tokio::test]
    async fn get_event_by_id_returns_none_for_missing_event() {
        let repo = test_repo().await;
        let absent_id = "0".repeat(64);
        let found = repo.get_event_by_id(&absent_id).await.unwrap();
        assert!(found.is_none());
    }

    /// Run a subscription with a single filter against a repo, and collect
    /// the serialized event JSON of every matching row (stopping at the
    /// "EOSE" sentinel `query_subscription` always sends at the end).
    async fn collect_query_results(repo: &SqliteRepo, filter: ReqFilter) -> Vec<String> {
        let sub = Subscription {
            id: "test-sub".to_owned(),
            filters: vec![filter],
        };
        let (query_tx, mut query_rx) = tokio::sync::mpsc::channel(100);
        let (_abandon_tx, abandon_rx) = tokio::sync::oneshot::channel();
        repo.query_subscription(sub, "test-client".to_owned(), query_tx, abandon_rx)
            .await
            .unwrap();
        let mut results = vec![];
        while let Some(r) = query_rx.recv().await {
            if r.event == "EOSE" {
                break;
            }
            results.push(r.event);
        }
        results
    }

    /// Regression/round-trip test for A4A discovery (task F2): persisting
    /// an event with a multi-char tag (`category`) must make it findable
    /// via a `#category` filter, and NOT findable under an unrelated tag
    /// value. Before this fix, `persist_event`'s `single_char_tagname` gate
    /// silently dropped the tag from the `tag` table, so this scenario
    /// always returned zero results.
    #[tokio::test]
    async fn multi_char_tag_query_round_trip() {
        let repo = test_repo().await;
        let event = Event {
            id: "1".repeat(64),
            pubkey: "2".repeat(64),
            delegated_by: None,
            created_at: 1_000,
            kind: 1,
            tags: vec![vec!["category".to_owned(), "development".to_owned()]],
            content: "a4a discovery event".to_owned(),
            sig: "3".repeat(128),
            tagidx: None,
        };
        let count = repo.write_event(&event).await.unwrap();
        assert_eq!(count, 1);

        let matching_filter = ReqFilter {
            ids: None,
            kinds: None,
            since: None,
            until: None,
            authors: None,
            limit: None,
            tags: Some(HashMap::from([(
                "category".to_string(),
                TagOperand::Or(HashSet::from(["development".to_owned()])),
            )])),
            force_no_match: false,
        };
        let matches = collect_query_results(&repo, matching_filter).await;
        assert_eq!(
            matches.len(),
            1,
            "event with tag [\"category\",\"development\"] should be found via #category=development"
        );
        assert!(matches[0].contains("a4a discovery event"));

        let non_matching_filter = ReqFilter {
            ids: None,
            kinds: None,
            since: None,
            until: None,
            authors: None,
            limit: None,
            tags: Some(HashMap::from([(
                "category".to_string(),
                TagOperand::Or(HashSet::from(["design".to_owned()])),
            )])),
            force_no_match: false,
        };
        let non_matches = collect_query_results(&repo, non_matching_filter).await;
        assert_eq!(
            non_matches.len(),
            0,
            "event should NOT be found under an unrelated #category value"
        );
    }

    /// Backward-compat companion to `multi_char_tag_query_round_trip`:
    /// standard single-char NIP-01/NIP-12 tags (`#e`) must still be stored
    /// and queryable exactly as before this change.
    #[tokio::test]
    async fn single_char_tag_query_round_trip_backward_compat() {
        let repo = test_repo().await;
        let referenced_id = "a".repeat(64);
        let event = Event {
            id: "4".repeat(64),
            pubkey: "5".repeat(64),
            delegated_by: None,
            created_at: 1_000,
            kind: 1,
            tags: vec![vec!["e".to_owned(), referenced_id.clone()]],
            content: "regular nostr reply".to_owned(),
            sig: "6".repeat(128),
            tagidx: None,
        };
        let count = repo.write_event(&event).await.unwrap();
        assert_eq!(count, 1);

        let filter = ReqFilter {
            ids: None,
            kinds: None,
            since: None,
            until: None,
            authors: None,
            limit: None,
            tags: Some(HashMap::from([(
                "e".to_string(),
                TagOperand::Or(HashSet::from([referenced_id])),
            )])),
            force_no_match: false,
        };
        let matches = collect_query_results(&repo, filter).await;
        assert_eq!(matches.len(), 1, "event should still be found via #e (NIP-01/12)");
    }

    /// Hardening item 3: an event packing far more MULTI-char tags than
    /// `MAX_INDEXED_TAGS_PER_EVENT` must only get that many multi-char rows
    /// written into the `tag` table -- the rest are simply not indexed
    /// (though the event itself, and its full tag list in the stored JSON,
    /// are still persisted unchanged). Without this cap, an attacker could
    /// pack thousands of throwaway multi-char tags into a single ~128KB
    /// event and bloat the `tag` table per event.
    ///
    /// Crucially, this test also places single-char `d`/`e`/`p` tags AFTER
    /// the multi-char tags (i.e. past array position `cap`). Before this
    /// fix, the cap counted ALL tags in raw array order, so any single-char
    /// tag landing after position 100 was silently dropped from the `tag`
    /// table -- breaking NIP-01 `#e`/`#p` search and parameterized-
    /// replaceable dedup (`t.name='d'`) for any event with >100 preceding
    /// tags. This test fails against that old (order-based) cap, because
    /// the d/e/p tags below sit at positions cap..cap+3, well past 100.
    #[tokio::test]
    async fn tag_indexing_is_capped_per_event() {
        let repo = test_repo().await;
        let cap = crate::event::MAX_INDEXED_TAGS_PER_EVENT;
        let extra = 50;
        let referenced_id = "a".repeat(64);
        let referenced_pubkey = "b".repeat(64);
        let d_value = "my-unique-d-tag".to_owned();
        let mut tags: Vec<Vec<String>> = (0..(cap + extra))
            .map(|i| vec![format!("t{i}"), format!("v{i}")])
            .collect();
        // single-char tags placed AFTER the multi-char run, past position `cap`.
        tags.push(vec!["d".to_owned(), d_value.clone()]);
        tags.push(vec!["e".to_owned(), referenced_id.clone()]);
        tags.push(vec!["p".to_owned(), referenced_pubkey.clone()]);
        let total_tags = tags.len();
        let event = Event {
            id: "7".repeat(64),
            pubkey: "8".repeat(64),
            delegated_by: None,
            created_at: 1_000,
            kind: 30001, // parameterized-replaceable range, so the `d` tag matters
            tags,
            content: "event with excessive tags".to_owned(),
            sig: "9".repeat(128),
            tagidx: None,
        };
        let count = repo.write_event(&event).await.unwrap();
        assert_eq!(count, 1);

        let id_blob = hex::decode(&event.id).unwrap();
        let conn = repo.read_pool.get().unwrap();
        let ev_pk: i64 = conn
            .query_row(
                "SELECT id FROM event WHERE event_hash=?",
                rusqlite::params![id_blob],
                |row| row.get(0),
            )
            .unwrap();
        let tag_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM tag WHERE event_id=?",
                rusqlite::params![ev_pk],
                |row| row.get(0),
            )
            .unwrap();
        // cap multi-char tags + the 3 single-char tags (d/e/p), which are
        // never subject to the cap.
        assert_eq!(
            tag_rows as usize,
            cap + 3,
            "multi-char tags should be capped at MAX_INDEXED_TAGS_PER_EVENT, \
             but single-char d/e/p tags must always be indexed on top of that"
        );

        // The single-char tags, despite sitting past position `cap` in the
        // raw tag array, must still be present in the tag table.
        let d_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM tag WHERE event_id=? AND name='d' AND value=?",
                rusqlite::params![ev_pk, d_value],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(d_rows, 1, "the 'd' tag must be indexed even though it is past position {cap}");

        let e_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM tag WHERE event_id=? AND name='e' AND value=?",
                rusqlite::params![ev_pk, referenced_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(e_rows, 1, "the 'e' tag must be indexed even though it is past position {cap}");

        let p_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM tag WHERE event_id=? AND name='p' AND value=?",
                rusqlite::params![ev_pk, referenced_pubkey],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(p_rows, 1, "the 'p' tag must be indexed even though it is past position {cap}");

        // The event itself (and its full, un-truncated tag list) must
        // still be persisted -- the cap only affects what gets INDEXED.
        let found = repo
            .get_event_by_id(&event.id)
            .await
            .unwrap()
            .expect("event should still be persisted despite excess tags");
        assert_eq!(found.tags.len(), total_tags);

        // Dedup reliance: a `d`-tag query (as used by parameterized-
        // replaceable dedup logic) must be able to find this event.
        let d_dedup_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM event e LEFT JOIN tag t ON e.id=t.event_id \
                 WHERE e.author=? AND e.kind=? AND t.name='d' AND t.value=?",
                rusqlite::params![
                    hex::decode(&event.pubkey).unwrap(),
                    crate::utils::u64_to_sql(event.kind),
                    d_value
                ],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            d_dedup_count, 1,
            "parameterized-replaceable dedup query on t.name='d' must find this event"
        );
    }

    #[test]
    fn test_query_gen_tag_value_or() {
        let filter = ReqFilter {
            ids: None,
            kinds: Some(vec![1000]),
            since: None,
            until: None,
            authors: Some(vec![
                "84de35e2584d2b144aae823c9ed0b0f3deda09648530b93d1a2a146d1dea9864".to_owned(),
            ]),
            limit: None,
            tags: Some(HashMap::from([(
                "d".to_string(),
                TagOperand::Or(HashSet::from(["test".to_owned()])),
            )])),
            force_no_match: false,
        };

        let (query, _params, _idx) = query_from_filter(&filter);
        assert_eq!(
            query,
            "SELECT e.content FROM event e INDEXED BY author_kind_index WHERE hidden!=TRUE AND (author=?) AND kind IN (1000) AND e.id IN (SELECT t.event_id FROM tag t WHERE (name=? AND value IN (?) AND kind IN (1000))) AND (expires_at IS NULL OR expires_at > ?) ORDER BY e.created_at ASC"
        );
    }

    #[test]
    fn test_query_gen_tag_value_or_multiple() {
        let filter = ReqFilter {
            ids: None,
            kinds: Some(vec![30_001]),
            since: None,
            until: None,
            authors: None,
            limit: None,
            tags: Some(HashMap::from([(
                "d".to_string(),
                TagOperand::Or(HashSet::from(["test".to_owned(), "test2".to_owned()])),
            )])),
            force_no_match: false,
        };

        let (query, _params, _idx) = query_from_filter(&filter);
        // Values are sorted, so test comes before test2
        assert_eq!(
            query,
            "SELECT e.content FROM event e  WHERE hidden!=TRUE AND kind IN (30001) AND e.id IN (SELECT t.event_id FROM tag t WHERE (name=? AND value IN (?, ?) AND kind IN (30001))) AND (expires_at IS NULL OR expires_at > ?) ORDER BY e.created_at ASC"
        );
    }

    #[test]
    fn test_query_gen_tag_value_and() {
        let filter = ReqFilter {
            ids: None,
            kinds: Some(vec![1000]),
            since: None,
            until: None,
            authors: Some(vec![
                "84de35e2584d2b144aae823c9ed0b0f3deda09648530b93d1a2a146d1dea9864".to_owned(),
            ]),
            limit: None,
            tags: Some(HashMap::from([(
                "d".to_string(),
                TagOperand::And(HashSet::from(["test".to_owned(), "test2".to_owned()])),
            )])),
            force_no_match: false,
        };

        let (query, _params, _idx) = query_from_filter(&filter);
        // For AND queries, we should have multiple subqueries
        assert!(query.contains("SELECT e.content FROM event e"));
        assert!(query.contains("WHERE hidden!=TRUE"));
        assert!(query.contains("(author=?)"));
        assert!(query.contains("kind IN (1000)"));
        // Should contain two separate subqueries for AND operation
        let subquery_count = query
            .matches("e.id IN (SELECT t.event_id FROM tag t WHERE (name=? AND value=?")
            .count();
        assert_eq!(
            subquery_count, 2,
            "Should have 2 subqueries for AND operation"
        );
        assert!(query.contains("ORDER BY e.created_at ASC"));
    }

    #[test]
    fn test_query_gen_tag_value_and_hex() {
        let filter = ReqFilter {
            ids: None,
            kinds: Some(vec![1000]),
            since: None,
            until: None,
            authors: Some(vec![
                "84de35e2584d2b144aae823c9ed0b0f3deda09648530b93d1a2a146d1dea9864".to_owned(),
            ]),
            limit: None,
            tags: Some(HashMap::from([(
                "p".to_string(),
                TagOperand::And(HashSet::from([
                    "63fe6318dc58583cfe16810f86dd09e18bfd76aabc24a0081ce2856f330504ed".to_owned(),
                    "84de35e2584d2b144aae823c9ed0b0f3deda09648530b93d1a2a146d1dea9864".to_owned(),
                ])),
            )])),
            force_no_match: false,
        };

        let (query, _params, _idx) = query_from_filter(&filter);
        // For AND queries with hex values
        assert!(query.contains("SELECT e.content FROM event e"));
        assert!(query.contains("WHERE hidden!=TRUE"));
        assert!(query.contains("(author=?)"));
        assert!(query.contains("kind IN (1000)"));
        // Should contain two separate subqueries for AND operation
        let subquery_count = query
            .matches("e.id IN (SELECT t.event_id FROM tag t WHERE (name=? AND value=?")
            .count();
        assert_eq!(
            subquery_count, 2,
            "Should have 2 subqueries for AND operation with hex values"
        );
    }

    #[test]
    fn test_query_empty_tags() {
        let filter = ReqFilter {
            ids: None,
            kinds: Some(vec![1, 6, 16, 30023, 1063, 6969]),
            since: Some(1700697846),
            until: None,
            authors: None,
            limit: None,
            tags: Some(HashMap::from([("a".to_string(), TagOperand::And(HashSet::new()))])),
            force_no_match: false,
        };

        let (query, _params, _idx) = query_from_filter(&filter);
        // Empty tags should still generate a valid query, just without tag filters
        assert!(query.contains("SELECT e.content FROM event e"));
        assert!(query.contains("WHERE hidden!=TRUE"));
        assert!(query.contains("kind IN (1, 6, 16, 30023, 1063, 6969)"));
        // Should not contain tag subqueries since the tag set is empty
        assert!(!query.contains("e.id IN (SELECT t.event_id FROM tag t"));
    }

    #[test]
    fn empty_or_tag_filter_matches_no_stored_events() {
        let filter: ReqFilter = serde_json::from_str(r##"{"#p":[]}"##).unwrap();
        let (query, params, _idx) = query_from_filter(&filter);
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE event (content TEXT, hidden INTEGER, expires_at INTEGER, created_at INTEGER);
             INSERT INTO event VALUES ('unrelated', 0, NULL, 1);"
        ).unwrap();
        let rows = conn.prepare(&query).unwrap()
            .query_map(rusqlite::params_from_iter(params.iter()), |row| row.get::<_, String>(0))
            .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert!(rows.is_empty(), "empty OR must not drop the tag restriction");
    }

    #[test]
    fn test_query_tag_with_since_until() {
        let filter = ReqFilter {
            ids: None,
            kinds: Some(vec![1000]),
            since: Some(1234567890),
            until: Some(9876543210),
            authors: None,
            limit: None,
            tags: Some(HashMap::from([(
                "d".to_string(),
                TagOperand::Or(HashSet::from(["test".to_owned()])),
            )])),
            force_no_match: false,
        };

        let (query, _params, _idx) = query_from_filter(&filter);
        // Should include since and until in both the main query and the tag subquery
        assert!(query.contains("created_at >= 1234567890"));
        assert!(query.contains("created_at <= 9876543210"));
        // Tag subquery should also include the time constraints
        assert!(query.contains("AND created_at >= 1234567890"));
        assert!(query.contains("AND created_at <= 9876543210"));
    }

    #[test]
    fn test_query_multiple_tag_keys_or() {
        let filter = ReqFilter {
            ids: None,
            kinds: Some(vec![1000]),
            since: None,
            until: None,
            authors: None,
            limit: None,
            tags: Some(HashMap::from([
                ("d".to_string(), TagOperand::Or(HashSet::from(["test".to_owned()]))),
                ("e".to_string(), TagOperand::Or(HashSet::from(["event1".to_owned()]))),
            ])),
            force_no_match: false,
        };

        let (query, _params, _idx) = query_from_filter(&filter);
        // Should have two separate tag subqueries, one for each key
        let subquery_count = query
            .matches("e.id IN (SELECT t.event_id FROM tag t WHERE (name=?")
            .count();
        assert_eq!(
            subquery_count, 2,
            "Should have 2 subqueries for 2 different tag keys"
        );
    }

    /// F3: the migration to v19 must create `tag_name_value_index`, so
    /// fresh databases (built via `mig_init`/`INIT_SQL`) as well as
    /// upgraded ones end up with the index in place.
    #[tokio::test]
    async fn migration_creates_tag_name_value_index() {
        let repo = test_repo().await;
        let conn = repo.read_pool.get().unwrap();

        let user_version: usize = conn
            .query_row("PRAGMA user_version;", [], |row| row.get::<_, i64>(0))
            .unwrap() as usize;
        assert_eq!(
            user_version,
            crate::repo::sqlite_migration::DB_VERSION,
            "fresh test db should be migrated to the latest schema version"
        );

        let index_name: String = conn
            .query_row(
                "SELECT name FROM sqlite_master WHERE type='index' AND name='tag_name_value_index';",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(index_name, "tag_name_value_index");
    }

    /// F3: an A4A-style `#category` lookup (name+value, no `kind`
    /// constraint) must use `tag_name_value_index` rather than falling
    /// back to a full scan of the `tag` table.
    ///
    /// `name` alone is a leading column of three different indexes
    /// (`tag_name_eid_index`, `tag_covering_index`, `tag_name_value_index`),
    /// so on a freshly-migrated, *empty* `tag` table SQLite's cost-based
    /// planner has no real statistics to distinguish them by and its
    /// built-in guesses can, in principle, tie-break to a different one of
    /// those three (this is what made this test flake under a full parallel
    /// run, even though it passed reliably in isolation). To make the
    /// planner's choice reflect genuine selectivity rather than a guess, we
    /// populate `tag` with a realistic, skewed distribution -- lots of rows
    /// sharing `name='category'` with assorted values, only a handful of
    /// which also have `value='development'` -- and then run `ANALYZE` so
    /// the planner has real `sqlite_stat1` data to cost each candidate index
    /// against. With that data, `tag_name_value_index` (which can seek on
    /// both `name` AND `value`) is unambiguously cheaper than the other two
    /// (which can only seek on `name`), making the assertion deterministic.
    #[tokio::test]
    async fn a4a_category_query_uses_tag_name_value_index() {
        let repo = test_repo().await;
        let conn = repo.write_pool.get().unwrap();
        // These synthetic tag rows exist purely to give the planner a
        // realistic distribution to run ANALYZE against; they don't need
        // (and, for simplicity, don't have) matching rows in `event`.
        conn.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();

        {
            let tx = conn.unchecked_transaction().unwrap();
            {
                let mut insert = tx
                    .prepare(
                        "INSERT INTO tag (event_id, name, value, created_at, kind) VALUES (?, ?, ?, ?, ?)",
                    )
                    .unwrap();
                // Lots of noise: other tag names entirely, so a plain
                // `name='category'` seek still has real work to filter out.
                let other_names = ["e", "p", "t", "d", "expiration", "delegation"];
                for i in 0..1500u64 {
                    let name = other_names[(i as usize) % other_names.len()];
                    insert
                        .execute(rusqlite::params![
                            i as i64,
                            name,
                            format!("value-{i}"),
                            1_000_i64,
                            1_i64
                        ])
                        .unwrap();
                }
                // Many `category` rows, but only a few with `value='development'`,
                // so `(name,value)` is meaningfully more selective than `name` alone.
                for i in 0..300u64 {
                    let value = if i < 4 {
                        "development".to_owned()
                    } else {
                        format!("category-value-{i}")
                    };
                    insert
                        .execute(rusqlite::params![
                            2_000_i64 + i as i64,
                            "category",
                            value,
                            1_000_i64,
                            1_i64
                        ])
                        .unwrap();
                }
            }
            tx.commit().unwrap();
        }
        conn.execute_batch("ANALYZE;").unwrap();

        let mut stmt = conn
            .prepare(
                "EXPLAIN QUERY PLAN SELECT event_id FROM tag WHERE name = 'category' AND value = 'development';",
            )
            .unwrap();
        let plan: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let plan_text = plan.join(" | ");

        assert!(
            plan_text.contains("tag_name_value_index"),
            "expected query plan to use tag_name_value_index, got: {plan_text}"
        );
        assert!(
            !plan_text.contains("SCAN tag"),
            "expected no full scan of the tag table, got: {plan_text}"
        );
    }
}
