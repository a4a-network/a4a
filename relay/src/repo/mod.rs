use crate::db::QueryResult;
use crate::error::Result;
use crate::event::Event;
use crate::nip05::VerificationRecord;
use crate::subscription::Subscription;
use crate::utils::unix_time;
use async_trait::async_trait;
use rand::Rng;

pub mod postgres;
pub mod postgres_migration;
pub mod sqlite;
pub mod sqlite_migration;

/// Includes JSON row wrappers and the pagination envelope.
pub const MAX_HISTORY_PAGE_BYTES: usize = 2 * 1024 * 1024;

#[async_trait]
pub trait NostrRepo: Send + Sync {
    /// Start the repository (any initialization or maintenance tasks can be kicked off here)
    async fn start(&self) -> Result<()>;

    /// Run migrations and return current version
    async fn migrate_up(&self) -> Result<usize>;

    /// Persist event to database
    async fn write_event(&self, e: &Event) -> Result<u64>;

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
    ) -> Result<()>;

    /// Fetch a single event by its (hex-encoded) id.
    ///
    /// Returns `Ok(None)` if no event with that id exists, or if it exists
    /// but is hidden (e.g. superseded by a replaceable event, or deleted).
    /// This is a point-lookup, distinct from [`NostrRepo::query_subscription`],
    /// which is intended for streaming subscription results.
    async fn get_event_by_id(&self, id: &str) -> Result<Option<Event>>;

    /// Archived NIP-33-replaced delegation (31000) by id. The default has no archive:
    /// the Postgres engine does not maintain one (internal finding 47: the secondary
    /// engine lags), so REST honestly returns 404 instead of inventing a copy.
    async fn get_archived_delegation(&self, _id: &str) -> Result<Option<Event>> {
        Ok(None)
    }

    /// Protected-kind history by RECEIPT time as `(first_seen, event)`, with
    /// `first_seen >= after`, ascending and bounded by `limit`. The notary stamps
    /// receipt, not `created_at` (finding 86: a two-day backdated event was never
    /// stamped). The default means unsupported, so REST returns 501, not an empty list.
    async fn history_after(&self, after: u64, limit: usize) -> Result<Vec<(u64, Event)>> {
        self.history_after_id(after, "", limit).await
    }

    /// Exclusive continuation within a reception second. An empty id includes
    /// the entire `after` second. Only completed reception seconds are returned.
    async fn history_after_id(&self, _after: u64, _after_id: &str, _limit: usize) -> Result<Vec<(u64, Event)>> {
        Err(crate::error::Error::CustomError(
            "history_after: this storage engine does not expose receipt-time history".into(),
        ))
    }

    /// Recipient-filtered transport inbox, separate from notarised history.
    /// Only visible, unexpired 1059/31033 events in sealed reception seconds.
    /// The (first_seen, id) cursor is exclusive; an empty id includes that second.
    /// Unsupported backends must fail, not claim an empty inbox.
    async fn inbox_after_id(&self, _recipient: &str, _after: u64, _after_id: &str,
                            _limit: usize) -> Result<Vec<(u64, Event)>> {
        Err(crate::error::Error::CustomError(
            "recipient inbox is not supported by this storage backend".into(),
        ))
    }

    /// Fetch the A4A revocation event (kind 31007) that `owner_pubkey` issued
    /// for the AGENT `delegate_pubkey`, if present.
    ///
    /// Addressable by (author, kind, d=delegate), so at most one -- and that is
    /// the point: a revocation revokes an agent, not one signed copy of a
    /// delegation. Keyed by the delegation's event id it missed every earlier
    /// copy, which re-issuing leaves behind and anyone could republish (audit F6).
    async fn get_a4a_revocation(
        &self,
        delegate_pubkey: &str,
        owner_pubkey: &str,
    ) -> Result<Option<Event>> {
        self.get_a4a_addressable(
            crate::a4a_delegation::A4A_KIND_REVOCATION,
            delegate_pubkey,
            owner_pubkey,
        )
        .await
    }

    /// Fetch the addressable event of `kind` that `author` published under
    /// `d_value`, if any. Both the delegation (31000) and its revocation (31007)
    /// are keyed by the delegate pubkey, so one query serves both -- and asking
    /// for them the same way is what keeps the two from drifting apart.
    async fn get_a4a_addressable(
        &self,
        kind: u64,
        d_value: &str,
        author: &str,
    ) -> Result<Option<Event>>;

    /// Perform normal maintenance
    async fn optimize_db(&self) -> Result<()>;

    /// Create a new verification record connected to a specific event
    async fn create_verification_record(&self, event_id: &str, name: &str) -> Result<()>;

    /// Update verification timestamp
    async fn update_verification_timestamp(&self, id: u64) -> Result<()>;

    /// Update verification record as failed
    async fn fail_verification(&self, id: u64) -> Result<()>;

    /// Delete verification record
    async fn delete_verification(&self, id: u64) -> Result<()>;

    /// Get the latest verification record for a given pubkey.
    async fn get_latest_user_verification(&self, pub_key: &str) -> Result<VerificationRecord>;

    /// Get oldest verification before timestamp
    async fn get_oldest_user_verification(&self, before: u64) -> Result<VerificationRecord>;

}

// Current time, with a slight forward jitter in seconds
pub(crate) fn now_jitter(sec: u64) -> u64 {
    // random time between now, and 10min in future.
    let mut rng = rand::thread_rng();
    let jitter_amount = rng.gen_range(0..sec);
    let now = unix_time();
    now.saturating_add(jitter_amount)
}
