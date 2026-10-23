use crate::db::QueryResult;
use crate::error;
use crate::error::Result;
use crate::event::Event;
use crate::nip05::{Nip05Name, VerificationRecord};
use crate::repo::postgres_migration::run_migrations;
use crate::repo::{now_jitter, NostrRepo};
use crate::server::NostrMetrics;
use crate::subscription::{ReqFilter, Subscription, TagOperand};
use crate::utils::{self, is_hex, is_hex_tag_value};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use itertools::Itertools;
use sqlx::postgres::PgRow;
use sqlx::Error::RowNotFound;
use sqlx::{Error, FromRow, Postgres, QueryBuilder, Row};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::Sender;
use tokio::sync::oneshot::Receiver;
use tracing::{debug, error, info, trace, warn};

pub type PostgresPool = sqlx::pool::Pool<Postgres>;

pub struct PostgresRepo {
    conn: PostgresPool,
    conn_write: PostgresPool,
    metrics: NostrMetrics,
}

impl PostgresRepo {
    pub fn new(c: PostgresPool, cw: PostgresPool, m: NostrMetrics) -> PostgresRepo {
        PostgresRepo {
            conn: c,
            conn_write: cw,
            metrics: m,
        }
    }
}

/// Cleanup expired events on a regular basis
async fn cleanup_expired(conn: PostgresPool, frequency: Duration) -> Result<()> {
    tokio::task::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(frequency) => {
                    let start = Instant::now();
                    let exp_res = delete_expired(conn.clone()).await;
                    match exp_res {
                        Ok(exp_count) => {
                            if exp_count > 0 {
                                info!("removed {} expired events in: {:?}", exp_count, start.elapsed());
                            }
                        },
                        Err(e) => {
                            warn!("could not remove expired events due to error: {:?}", e);
                        }
                    }
                }
            };
        }
    });
    Ok(())
}

/// One-time deletion of all expired events
///
/// Exclude delegations (31000) and revocations (31007), as in the SQLite backend.
/// A delegation's `expiration` tag is mandate lifetime but shares its name with
/// NIP-40. Deleting it prevents verifying whether the agent was authorized when
/// older events were published; deleting a revocation would restore a revoked
/// delegation. The original fix covered only SQLite (finding 47, 2026-08-30).
async fn delete_expired(conn: PostgresPool) -> Result<u64> {
    let mut tx = conn.begin().await?;
    let update_count = sqlx::query(
        "DELETE FROM \"event\" WHERE expires_at <= $1 AND kind NOT IN ($2, $3);",
    )
        .bind(utils::u64_to_timestamp(utils::unix_time()))
        .bind(crate::a4a_delegation::A4A_KIND_DELEGATION as i64)
        .bind(crate::a4a_delegation::A4A_KIND_REVOCATION as i64)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    Ok(update_count)
}

#[async_trait]
impl NostrRepo for PostgresRepo {
    async fn start(&self) -> Result<()> {
        // begin a cleanup task for expired events.
        cleanup_expired(self.conn_write.clone(), Duration::from_secs(600)).await?;
        Ok(())
    }

    async fn migrate_up(&self) -> Result<usize> {
        Ok(run_migrations(&self.conn_write).await?)
    }

    async fn write_event(&self, e: &Event) -> Result<u64> {
        // start transaction
        let mut tx = self.conn_write.begin().await?;
        let start = Instant::now();

        // get relevant fields from event and convert to blobs.
        let id_blob = hex::decode(&e.id).ok();
        let pubkey_blob: Option<Vec<u8>> = hex::decode(&e.pubkey).ok();
        let delegator_blob: Option<Vec<u8>> =
            e.delegated_by.as_ref().and_then(|d| hex::decode(d).ok());
        let event_str = serde_json::to_string(&e).unwrap();

        // determine if this event would be shadowed by an existing
        // replaceable event or parameterized replaceable event.
        if e.is_replaceable() {
            let repl_count = sqlx::query(
                "SELECT e.id FROM event e WHERE e.pub_key=$1 AND e.kind=$2 AND e.created_at >= $3 LIMIT 1;")
                .bind(&pubkey_blob)
                .bind(e.kind as i64)
                .bind(utils::u64_to_timestamp(e.created_at))
                .fetch_optional(&mut *tx)
                .await?;
            if repl_count.is_some() {
                return Ok(0);
            }
        }
        if let Some(d_tag) = e.distinct_param() {
            let repl_count: i64 = if is_hex_tag_value(&d_tag) {
                sqlx::query_scalar(
                    "SELECT count(*) AS count FROM event e LEFT JOIN tag t ON e.id=t.event_id WHERE e.pub_key=$1 AND e.kind=$2 AND t.name='d' AND t.value_hex=$3 AND e.created_at >= $4 LIMIT 1;")
                    .bind(hex::decode(&e.pubkey).ok())
                    .bind(e.kind as i64)
                    .bind(hex::decode(d_tag).ok())
                    .bind(utils::u64_to_timestamp(e.created_at))
                    .fetch_one(&mut *tx)
                    .await?
            } else {
                sqlx::query_scalar(
                    "SELECT count(*) AS count FROM event e LEFT JOIN tag t ON e.id=t.event_id WHERE e.pub_key=$1 AND e.kind=$2 AND t.name='d' AND t.value=$3 AND e.created_at >= $4 LIMIT 1;")
                    .bind(hex::decode(&e.pubkey).ok())
                    .bind(e.kind as i64)
                    .bind(d_tag.as_bytes())
                    .bind(utils::u64_to_timestamp(e.created_at))
                    .fetch_one(&mut *tx)
                    .await?
            };
            // if any rows were returned, then some newer event with
            // the same author/kind/tag value exist, and we can ignore
            // this event.
            if repl_count > 0 {
                return Ok(0);
            }
        }
        // ignore if the event hash is a duplicate.
        let mut ins_count = sqlx::query(
            r#"INSERT INTO "event"
(id, pub_key, created_at, expires_at, kind, "content", delegated_by)
VALUES($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (id) DO NOTHING"#,
        )
        .bind(&id_blob)
        .bind(&pubkey_blob)
        .bind(utils::u64_to_timestamp(e.created_at))
        .bind(
            e.expiration()
                .map(utils::u64_to_timestamp),
        )
        .bind(e.kind as i64)
        .bind(event_str.into_bytes())
        .bind(delegator_blob)
        .execute(&mut *tx)
        .await?
        .rows_affected();

        if ins_count == 0 {
            // if the event was a duplicate, no need to insert event or
            // pubkey references.  This will abort the txn.
            return Ok(0);
        }

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
        for tag in e.tags.iter() {
            // ensure we have 2 values.
            if tag.len() >= 2 {
                let tag_name = &tag[0];
                let tag_val = &tag[1];
                if tag_name.is_empty() {
                    continue;
                }
                let is_single_char = crate::event::single_char_tagname(tag_name).is_some();
                if !is_single_char {
                    if indexed_multi_char_tags >= crate::event::MAX_INDEXED_TAGS_PER_EVENT {
                        continue;
                    }
                    indexed_multi_char_tags += 1;
                }
                // if tag value is lowercase hex;
                if is_hex_tag_value(tag_val) {
                    sqlx::query("INSERT INTO tag (event_id, \"name\", value, value_hex) VALUES($1, $2, NULL, $3) \
                                 ON CONFLICT (event_id, \"name\", value, value_hex) DO NOTHING")
                            .bind(&id_blob)
                        .bind(tag_name)
                        .bind(hex::decode(tag_val).ok())
                        .execute(&mut *tx)
                        .await?;
                } else {
                    sqlx::query("INSERT INTO tag (event_id, \"name\", value, value_hex) VALUES($1, $2, $3, NULL) \
                                 ON CONFLICT (event_id, \"name\", value, value_hex) DO NOTHING")
                            .bind(&id_blob)
                        .bind(tag_name)
                        .bind(tag_val.as_bytes())
                        .execute(&mut *tx)
                        .await?;
                }
            }
        }
        if e.is_replaceable() {
            let update_count = sqlx::query("DELETE FROM \"event\" WHERE kind=$1 and pub_key = $2 and id not in (select id from \"event\" where kind=$1 and pub_key=$2 order by created_at desc limit 1);")
                .bind(e.kind as i64)
                .bind(hex::decode(&e.pubkey).ok())
                .execute(&mut *tx)
                .await?.rows_affected();
            if update_count > 0 {
                info!(
                    "hid {} older replaceable kind {} events for author: {:?}",
                    update_count,
                    e.kind,
                    e.get_author_prefix()
                );
            }
        }
        // parameterized replaceable events
        // check for parameterized replaceable events that would be hidden; don't insert these either.
        if let Some(d_tag) = e.distinct_param() {
            let update_count = if is_hex_tag_value(&d_tag) {
                sqlx::query("DELETE FROM event WHERE kind=$1 AND pub_key=$2 AND id IN (SELECT e.id FROM event e LEFT JOIN tag t ON e.id=t.event_id WHERE e.kind=$1 AND e.pub_key=$2 AND t.name='d' AND t.value_hex=$3 ORDER BY created_at DESC OFFSET 1);")
                    .bind(e.kind as i64)
                    .bind(hex::decode(&e.pubkey).ok())
                    .bind(hex::decode(d_tag).ok())
                    .execute(&mut *tx)
                    .await?.rows_affected()
            } else {
                sqlx::query("DELETE FROM event WHERE kind=$1 AND pub_key=$2 AND id IN (SELECT e.id FROM event e LEFT JOIN tag t ON e.id=t.event_id WHERE e.kind=$1 AND e.pub_key=$2 AND t.name='d' AND t.value=$3 ORDER BY created_at DESC OFFSET 1);")
                    .bind(e.kind as i64)
                    .bind(hex::decode(&e.pubkey).ok())
                    .bind(d_tag.as_bytes())
                    .execute(&mut *tx)
                    .await?.rows_affected()
            };
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
            let pub_keys: Vec<Vec<u8>> = event_candidates
                .iter()
                .filter(|x| is_hex(x) && x.len() == 64)
                .filter_map(|x| hex::decode(x).ok())
                .collect();

            let mut builder = QueryBuilder::new(
                "UPDATE \"event\" SET hidden = 1::bit(1) WHERE kind != 5 AND pub_key = ",
            );
            builder.push_bind(hex::decode(&e.pubkey).ok());
            builder.push(" AND id IN (");

            let mut sep = builder.separated(", ");
            for pk in pub_keys {
                sep.push_bind(pk);
            }
            sep.push_unseparated(")");

            let update_count = builder.build().execute(&mut *tx).await?.rows_affected();
            info!(
                "hid {} deleted events for author {:?}",
                update_count,
                e.get_author_prefix()
            );
        } else {
            // check if a deletion has already been recorded for this event.
            // Only relevant for non-deletion events
            let del_count = sqlx::query(
                "SELECT e.id FROM \"event\" e \
            LEFT JOIN tag t ON e.id = t.event_id \
            WHERE e.pub_key = $1 AND t.\"name\" = 'e' AND e.kind = 5 AND t.value = $2 LIMIT 1",
            )
            .bind(&pubkey_blob)
            .bind(&id_blob)
            .fetch_optional(&mut *tx)
            .await?;

            // check if a the query returned a result, meaning we should
            // hid the current event
            if del_count.is_some() {
                // a deletion already existed, mark original event as hidden.
                info!(
                    "hid event: {:?} due to existing deletion by author: {:?}",
                    e.get_event_id_prefix(),
                    e.get_author_prefix()
                );
                sqlx::query("UPDATE \"event\" SET hidden = 1::bit(1) WHERE id = $1")
                    .bind(&id_blob)
                    .execute(&mut *tx)
                    .await?;
                // event was deleted, so let caller know nothing new
                // arrived, preventing this from being sent to active
                // subscriptions
                ins_count = 0;
            }
        }
        tx.commit().await?;
        self.metrics
            .write_events
            .observe(start.elapsed().as_secs_f64());
        Ok(ins_count)
    }

    async fn query_subscription(
        &self,
        sub: Subscription,
        client_id: String,
        query_tx: Sender<QueryResult>,
        mut abandon_query_rx: Receiver<()>,
    ) -> Result<()> {
        let start = Instant::now();
        let mut row_count: usize = 0;
        let metrics = &self.metrics;

        for filter in sub.filters.iter() {
            let start = Instant::now();
            // generate SQL query
            let q_filter = query_from_filter(filter);
            if q_filter.is_none() {
                debug!("Failed to generate query!");
                continue;
            }

            debug!("SQL generated in {:?}", start.elapsed());

            // cutoff for displaying slow queries
            let slow_cutoff = Duration::from_millis(2000);

            // any client that doesn't cause us to generate new rows in 5
            // seconds gets dropped.
            let abort_cutoff = Duration::from_secs(5);

            let start = Instant::now();
            let mut slow_first_event;
            let mut last_successful_send = Instant::now();

            // execute the query. Don't cache, since queries vary so much.
            let mut q_filter = q_filter.unwrap();
            // sqlx 0.9: Execute::sql() CONSUMES the query, so capture log text from
            // the builder before constructing the query.
            let sql = q_filter.sql().to_owned();
            let q_build = q_filter.build();
            let mut results = q_build.fetch(&self.conn);

            let mut first_result = true;
            let mut query_failure: Option<&'static str> = None;
            'rows: while let Some(row) = results.next().await {
                let row = match row {
                    Ok(row) => row,
                    Err(e) => {
                        error!("Query failed: {} {:?} {:?}", e, sql, filter);
                        // EOSE after this would claim the stored set is complete.
                        query_failure = Some("error: query failed while reading rows");
                        break;
                    }
                };
                let first_event_elapsed = start.elapsed();
                slow_first_event = first_event_elapsed >= slow_cutoff;
                if first_result {
                    debug!(
                        "first result in {:?} (cid: {}, sub: {:?})",
                        first_event_elapsed, client_id, sub.id
                    );
                    first_result = false;
                }

                // logging for slow queries; show sub and SQL.
                // to reduce logging; only show 1/16th of clients (leading 0)
                if slow_first_event && client_id.starts_with("00") {
                    debug!(
                        "query req (slow): {:?} (cid: {}, sub: {:?})",
                        &sub, client_id, sub.id
                    );
                } else {
                    trace!(
                        "query req: {:?} (cid: {}, sub: {:?})",
                        &sub,
                        client_id,
                        sub.id
                    );
                }

                // check if this is still active; every 100 rows
                if row_count.is_multiple_of(100)
                    && crate::utils::client_abandoned_query(&mut abandon_query_rx)
                {
                    debug!(
                        "query cancelled by client (cid: {}, sub: {:?})",
                        client_id, sub.id
                    );
                    // The client already left. Sending EOSE or CLOSED would
                    // address a subscription nobody is reading.
                    return Ok(());
                }

                row_count += 1;
                let event_json: Vec<u8> = row.get(0);
                loop {
                    if query_tx.capacity() != 0 {
                        // we have capacity to add another item
                        break;
                    } else {
                        // the queue is full
                        trace!("db reader thread is stalled");
                        if last_successful_send + abort_cutoff < Instant::now() {
                            // the queue has been full for too long, abort
                            info!("aborting database query due to slow client");
                            metrics
                                .query_aborts
                                .with_label_values(&["slowclient"])
                                .inc();
                            query_failure = Some(
                                "error: query aborted because the client was too slow",
                            );
                            break 'rows;
                        }
                        // give the queue a chance to clear before trying again
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }

                // Backpressure choice: awaiting send retains ownership of the query
                // result and avoids retry bookkeeping around try_send failures.
                query_tx
                    .send(QueryResult {
                        sub_id: sub.get_id(),
                        event: String::from_utf8(event_json).unwrap(),
                    })
                    .await
                    .ok();
                last_successful_send = Instant::now();
            }
            if let Some(reason) = query_failure {
                let _ = query_tx
                    .send(QueryResult {
                        sub_id: sub.get_id(),
                        event: format!("CLOSED {reason}"),
                    })
                    .await;
                return Ok(());
            }
        }
        let sent = query_tx
            .send(QueryResult {
                sub_id: sub.get_id(),
                event: "EOSE".to_string(),
            })
            .await;
        if sent.is_err() {
            debug!("EOSE was not delivered; client is gone (sub: {:?})", sub.id);
        }
        self.metrics
            .query_sub
            .observe(start.elapsed().as_secs_f64());
        debug!(
            "query completed in {:?} (cid: {}, sub: {:?}, db_time: {:?}, rows: {})",
            start.elapsed(),
            client_id,
            sub.id,
            start.elapsed(),
            row_count
        );
        Ok(())
    }

    /// Fetch a single event by its (hex-encoded) id.
    async fn get_event_by_id(&self, id: &str) -> Result<Option<Event>> {
        let id_blob = hex::decode(id).ok();
        let row = sqlx::query("SELECT content FROM \"event\" WHERE id = $1 AND hidden != 1::bit(1)")
            .bind(id_blob)
            .fetch_optional(&self.conn)
            .await?;
        row.map(|r| -> Result<Event> {
            let content: Vec<u8> = r.get(0);
            let json = String::from_utf8(content).unwrap();
            let mut event: Event = serde_json::from_str(&json)?;
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
        // Postgres stores hex tag values in t.value_hex with t.value = NULL, as in
        // the dedup queries above. A 64-hex SHA-256 d_value belongs in value_hex.
        // The old t.value comparison NEVER found Postgres revocations, leaving a
        // revoked delegation valid. Branch exactly as dedup does.
        let kind = kind as i64;
        let row = if is_hex_tag_value(d_value) {
            sqlx::query(
                "SELECT e.content FROM \"event\" e LEFT JOIN tag t ON e.id=t.event_id WHERE e.pub_key=$1 AND e.kind=$2 AND t.name='d' AND t.value_hex=$3 AND e.hidden != 1::bit(1) LIMIT 1")
                .bind(hex::decode(author).ok())
                .bind(kind)
                .bind(hex::decode(d_value).ok())
                .fetch_optional(&self.conn)
                .await?
        } else {
            sqlx::query(
                "SELECT e.content FROM \"event\" e LEFT JOIN tag t ON e.id=t.event_id WHERE e.pub_key=$1 AND e.kind=$2 AND t.name='d' AND t.value=$3 AND e.hidden != 1::bit(1) LIMIT 1")
                .bind(hex::decode(author).ok())
                .bind(kind)
                .bind(d_value.as_bytes())
                .fetch_optional(&self.conn)
                .await?
        };
        row.map(|r| -> Result<Event> {
            let content: Vec<u8> = r.get(0);
            let json = String::from_utf8(content).unwrap();
            let mut event: Event = serde_json::from_str(&json)?;
            // tags are preserved, but `delegated_by` is a transient
            // field (`#[serde(skip)]`) that must be recomputed.
            event.update_delegation();
            Ok(event)
        })
        .transpose()
    }

    async fn optimize_db(&self) -> Result<()> {
        // PostgreSQL maintenance is external to the relay; this repository backend
        // therefore has no explicit optimize operation.
        Ok(())
    }

    async fn create_verification_record(&self, event_id: &str, name: &str) -> Result<()> {
        let mut tx = self.conn_write.begin().await?;

        sqlx::query("DELETE FROM user_verification WHERE \"name\" = $1")
            .bind(name)
            .execute(&mut *tx)
            .await?;

        sqlx::query("INSERT INTO user_verification (event_id, \"name\", verified_at) VALUES ($1, $2, now())")
            .bind(hex::decode(event_id).ok())
            .bind(name)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        info!("saved new verification record for ({:?})", name);
        Ok(())
    }

    async fn update_verification_timestamp(&self, id: u64) -> Result<()> {
        // add some jitter to the verification to prevent everything from stacking up together.
        let verify_time = now_jitter(600);

        // update verification time and reset any failure count
        sqlx::query("UPDATE user_verification SET verified_at = $1, fail_count = 0 WHERE id = $2")
            .bind(utils::u64_to_timestamp(verify_time))
            .bind(id as i64)
            .execute(&self.conn_write)
            .await?;

        info!("verification updated for {}", id);
        Ok(())
    }

    async fn fail_verification(&self, id: u64) -> Result<()> {
        sqlx::query("UPDATE user_verification SET failed_at = now(), fail_count = fail_count + 1 WHERE id = $1")
            .bind(id as i64)
            .execute(&self.conn_write)
            .await?;
        Ok(())
    }

    async fn delete_verification(&self, id: u64) -> Result<()> {
        sqlx::query("DELETE FROM user_verification WHERE id = $1")
            .bind(id as i64)
            .execute(&self.conn_write)
            .await?;
        Ok(())
    }

    async fn get_latest_user_verification(&self, pub_key: &str) -> Result<VerificationRecord> {
        let query = r#"SELECT
            v.id,
            v."name",
            e.id as event_id,
            e.pub_key,
            e.created_at,
            v.verified_at,
            v.failed_at,
            v.fail_count
            FROM user_verification v
            LEFT JOIN "event" e ON e.id = v.event_id
            WHERE e.pub_key = $1
            ORDER BY e.created_at DESC, v.verified_at DESC, v.failed_at DESC
            LIMIT 1"#;
        sqlx::query_as::<_, VerificationRecord>(query)
            .bind(hex::decode(pub_key).ok())
            .fetch_optional(&self.conn)
            .await?
            .ok_or(error::Error::SqlxError(RowNotFound))
    }

    async fn get_oldest_user_verification(&self, before: u64) -> Result<VerificationRecord> {
        let query = r#"SELECT
            v.id,
            v."name",
            e.id as event_id,
            e.pub_key,
            e.created_at,
            v.verified_at,
            v.failed_at,
            v.fail_count
            FROM user_verification v
            LEFT JOIN "event" e ON e.id = v.event_id
                WHERE (v.verified_at < $1 OR v.verified_at IS NULL)
                AND (v.failed_at < $1 OR v.failed_at IS NULL)
            ORDER BY v.verified_at ASC, v.failed_at ASC
            LIMIT 1"#;
        sqlx::query_as::<_, VerificationRecord>(query)
            .bind(utils::u64_to_timestamp(before))
            .fetch_optional(&self.conn)
            .await?
            .ok_or(error::Error::SqlxError(RowNotFound))
    }

}

/// Create a dynamic SQL query and params from a subscription filter.
fn query_from_filter(f: &'_ ReqFilter) -> Option<QueryBuilder<Postgres>> {
    // if the filter is malformed, don't return anything.
    if f.force_no_match {
        return None;
    }

    let mut query = QueryBuilder::new("SELECT e.\"content\", e.created_at FROM \"event\" e");

    // This tracks whether we need to push a prefix AND before adding another clause
    let mut push_and = false;

    // Query for tags
    if let Some(map) = &f.tags {
        if !map.is_empty() {
            let mut tag_ctr = 1;
            for (key, val) in map.iter().sorted_by(|(k1, _), (k2, _)| k1.cmp(k2)) {
                if val.is_empty() {
                    if matches!(val, TagOperand::Or(_)) {
                        return None;
                    }
                    continue;
                }
                let has_plain_values = val.iter().any(|v| !is_hex_tag_value(v));
                let has_hex_values = val.iter().any(|v| is_hex_tag_value(v));

                if let TagOperand::Or(v_or) = val {
                    query
                        .push(format!(
                            " JOIN tag t{0} on e.id = t{0}.event_id AND t{0}.\"name\" = ",
                            tag_ctr
                        ))
                        .push_bind(key.to_string())
                        .push(" AND (");

                    if has_plain_values {
                        query.push(format!("t{0}.\"value\" in (", tag_ctr));
                        let mut tag_query = query.separated(", ");
                        for v in v_or.iter().filter(|v| !is_hex_tag_value(v)) {
                            tag_query.push_bind(v.as_bytes());
                        }
                    }
                    if has_plain_values && has_hex_values {
                        query.push(") OR ");
                    }
                    if has_hex_values {
                        query.push(format!("t{0}.\"value_hex\" in (", tag_ctr));
                        let mut tag_query = query.separated(", ");
                        for v in v_or.iter().filter(|v| is_hex_tag_value(v)) {
                            tag_query.push_bind(hex::decode(v).ok());
                        }
                    }

                    tag_ctr += 1;
                    query.push("))");
                } else if let TagOperand::And(v_and) = val {
                    let mut sorted_values: Vec<_> = v_and.iter().collect();
                    sorted_values.sort();
                    for vx in sorted_values {
                        query
                            .push(format!(
                                " JOIN \"tag\" t{0} on e.id = t{0}.event_id AND t{0}.\"name\" = ",
                                tag_ctr
                            ))
                            .push_bind(key.to_string())
                            .push(" AND ");

                        if !is_hex_tag_value(vx) {
                            query
                                .push(format!("t{0}.\"value\" = ", tag_ctr))
                                .push_bind(vx.as_bytes());
                        } else {
                            query
                                .push(format!("t{0}.\"value_hex\" = ", tag_ctr))
                                .push_bind(hex::decode(vx).ok());
                        }

                        tag_ctr += 1;
                    }
                }
            }
        }
    }

    query.push(" WHERE ");
    // Query for "authors", allowing prefix matches
    if let Some(auth_vec) = &f.authors {
        // filter out non-hex values
        let auth_vec: Vec<&String> = auth_vec.iter().filter(|a| is_hex(a)).collect();

        if auth_vec.is_empty() {
            return None;
        }
        query.push("(e.pub_key in (");

        let mut pk_sep = query.separated(", ");
        for pk in auth_vec.iter() {
            pk_sep.push_bind(hex::decode(pk).ok());
        }
        query.push(") OR e.delegated_by in (");
        let mut pk_delegated_sep = query.separated(", ");
        for pk in auth_vec.iter() {
            pk_delegated_sep.push_bind(hex::decode(pk).ok());
        }
        push_and = true;
        query.push("))");
    }

    // Query for Kind
    if let Some(ks) = &f.kinds {
        if ks.is_empty() {
            return None;
        }
        if push_and {
            query.push(" AND ");
        }
        push_and = true;

        query.push("e.kind in (");
        let mut list_query = query.separated(", ");
        for k in ks.iter() {
            list_query.push_bind(*k as i64);
        }
        query.push(")");
    }

    // Query for event,
    if let Some(id_vec) = &f.ids {
        // filter out non-hex values
        let id_vec: Vec<&String> = id_vec.iter().filter(|a| is_hex(a)).collect();
        if id_vec.is_empty() {
            return None;
        }
        if push_and {
            query.push(" AND (");
        } else {
            query.push("(");
        }
        push_and = true;

        query.push("id in (");
        let mut sep = query.separated(", ");
        for id in id_vec.iter() {
            sep.push_bind(hex::decode(id).ok());
        }
        query.push("))");
    }

    // Query for timestamp
    if let Some(since) = f.since {
        if push_and {
            query.push(" AND ");
        }
        push_and = true;
        query
            .push("e.created_at >= ")
            .push_bind(utils::u64_to_timestamp(since));
    }

    // Query for timestamp
    if let Some(until) = f.until {
        if push_and {
            query.push(" AND ");
        }
        push_and = true;
        query
            .push("e.created_at <= ")
            .push_bind(utils::u64_to_timestamp(until));
    }

    // never display hidden events
    if push_and {
        query.push(" AND e.hidden != 1::bit(1)");
    } else {
        query.push("e.hidden != 1::bit(1)");
    }
    // never display expired events
    query.push(" AND (e.expires_at IS NULL OR e.expires_at > now())");

    // Apply per-filter limit to this query.
    // The use of a LIMIT implies a DESC order, to capture only the most recent events.
    if let Some(lim) = f.limit {
        query.push(" ORDER BY e.created_at DESC LIMIT ");
        query.push(lim.min(1000));
    } else {
        query.push(" ORDER BY e.created_at ASC LIMIT ");
        query.push(1000);
    }
    Some(query)
}

impl FromRow<'_, PgRow> for VerificationRecord {
    fn from_row(row: &'_ PgRow) -> std::result::Result<Self, Error> {
        let name = Nip05Name::try_from(row.get::<'_, &str, &str>("name")).or(Err(RowNotFound))?;
        Ok(VerificationRecord {
            rowid: row.get::<'_, i64, &str>("id") as u64,
            name,
            address: hex::encode(row.get::<'_, Vec<u8>, &str>("pub_key")),
            event: hex::encode(row.get::<'_, Vec<u8>, &str>("event_id")),
            event_created: row.get::<'_, DateTime<Utc>, &str>("created_at").timestamp() as u64,
            last_success: match row.try_get::<'_, DateTime<Utc>, &str>("verified_at") {
                Ok(x) => Some(x.timestamp() as u64),
                _ => None,
            },
            last_failure: match row.try_get::<'_, DateTime<Utc>, &str>("failed_at") {
                Ok(x) => Some(x.timestamp() as u64),
                _ => None,
            },
            failure_count: row.get::<'_, i32, &str>("fail_count") as u64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subscription::TagOperand;
    use std::collections::{HashMap, HashSet};

    /// A tag value made of an ODD number of hex characters is stored in the
    /// plain `value` column (the write path requires `len % 2 == 0` to use
    /// `value_hex`), but the query builder classified it by `is_lower_hex`
    /// alone. So it counted as "has hex values", opened `value_hex in (`, then
    /// filtered it out again when filling the list -- emitting `value_hex in ()`,
    /// which Postgres rejects outright, killing the whole query. And even with
    /// valid SQL the value would have been dropped from both branches, silently
    /// matching nothing. One predicate now decides it on both paths.
    #[test]
    fn odd_length_hex_tag_value_queries_the_plain_column() {
        let filter = ReqFilter {
            ids: None,
            kinds: None,
            since: None,
            until: None,
            authors: None,
            limit: None,
            tags: Some(HashMap::from([(
                "t".to_string(),
                TagOperand::Or(HashSet::from(["abc".to_owned()])),
            )])),
            force_no_match: false,
        };
        let q = query_from_filter(&filter).unwrap();
        let sql = q.sql().as_str().to_owned();
        assert!(
            !sql.contains("value_hex\" in ()"),
            "generated invalid SQL: {sql}"
        );
        assert!(
            sql.contains("\"value\" in ("),
            "odd-length hex must use the regular column: {sql}"
        );
    }

    #[test]
    fn test_query_gen_tag_value_hex() {
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
                TagOperand::Or(HashSet::from([
                    "63fe6318dc58583cfe16810f86dd09e18bfd76aabc24a0081ce2856f330504ed".to_owned(),
                ])),
            )])),
            force_no_match: false,
        };

        let q = query_from_filter(&filter).unwrap();
        assert_eq!(q.sql(), "SELECT e.\"content\", e.created_at FROM \"event\" e JOIN tag t1 on e.id = t1.event_id AND t1.\"name\" = $1 AND (t1.\"value_hex\" in ($2)) WHERE (e.pub_key in ($3) OR e.delegated_by in ($4)) AND e.kind in ($5) AND e.hidden != 1::bit(1) AND (e.expires_at IS NULL OR e.expires_at > now()) ORDER BY e.created_at ASC LIMIT 1000")
    }

    #[test]
    fn test_query_gen_tag_value() {
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

        let q = query_from_filter(&filter).unwrap();
        assert_eq!(q.sql(), "SELECT e.\"content\", e.created_at FROM \"event\" e JOIN tag t1 on e.id = t1.event_id AND t1.\"name\" = $1 AND (t1.\"value\" in ($2)) WHERE (e.pub_key in ($3) OR e.delegated_by in ($4)) AND e.kind in ($5) AND e.hidden != 1::bit(1) AND (e.expires_at IS NULL OR e.expires_at > now()) ORDER BY e.created_at ASC LIMIT 1000")
    }

    #[test]
    fn test_query_gen_tag_value_and_value_hex() {
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
                TagOperand::And(HashSet::from([
                    "test".to_owned(),
                    "63fe6318dc58583cfe16810f86dd09e18bfd76aabc24a0081ce2856f330504ed".to_owned(),
                ])),
            )])),
            force_no_match: false,
        };

        let q = query_from_filter(&filter).unwrap();
        assert_eq!(q.sql(), "SELECT e.\"content\", e.created_at FROM \"event\" e JOIN \"tag\" t1 on e.id = t1.event_id AND t1.\"name\" = $1 AND t1.\"value_hex\" = $2 JOIN \"tag\" t2 on e.id = t2.event_id AND t2.\"name\" = $3 AND t2.\"value\" = $4 WHERE (e.pub_key in ($5) OR e.delegated_by in ($6)) AND e.kind in ($7) AND e.hidden != 1::bit(1) AND (e.expires_at IS NULL OR e.expires_at > now()) ORDER BY e.created_at ASC LIMIT 1000")
    }

    #[test]
    fn test_query_multiple_tags() {
        let filter = ReqFilter {
            ids: None,
            kinds: Some(vec![30_001]),
            since: None,
            until: None,
            authors: None,
            limit: None,
            tags: Some(HashMap::from([(
                "d".to_string(),
                TagOperand::Or(HashSet::from([
                    "test".to_owned(),
                    "63fe6318dc58583cfe16810f86dd09e18bfd76aabc24a0081ce2856f330504ed".to_owned(),
                ])),
            )])),
            force_no_match: false,
        };

        let q = query_from_filter(&filter).unwrap();
        assert_eq!(q.sql(), "SELECT e.\"content\", e.created_at FROM \"event\" e JOIN tag t1 on e.id = t1.event_id AND t1.\"name\" = $1 AND (t1.\"value\" in ($2) OR t1.\"value_hex\" in ($3)) WHERE e.kind in ($4) AND e.hidden != 1::bit(1) AND (e.expires_at IS NULL OR e.expires_at > now()) ORDER BY e.created_at ASC LIMIT 1000")
    }

    #[test]
    fn test_query_gen_tag_value_hex_and() {
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
        let q = query_from_filter(&filter).unwrap();
        assert_eq!(q.sql(), "SELECT e.\"content\", e.created_at FROM \"event\" e JOIN \"tag\" t1 on e.id = t1.event_id AND t1.\"name\" = $1 AND t1.\"value_hex\" = $2 JOIN \"tag\" t2 on e.id = t2.event_id AND t2.\"name\" = $3 AND t2.\"value_hex\" = $4 WHERE (e.pub_key in ($5) OR e.delegated_by in ($6)) AND e.kind in ($7) AND e.hidden != 1::bit(1) AND (e.expires_at IS NULL OR e.expires_at > now()) ORDER BY e.created_at ASC LIMIT 1000")
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
        let sql = query_from_filter(&filter).unwrap().sql().to_owned();
        assert!(!sql.as_str().contains("JOIN tag"));
        let mut empty_or = filter;
        empty_or.tags = Some(HashMap::from([("a".to_string(), TagOperand::Or(HashSet::new()))]));
        assert!(query_from_filter(&empty_or).is_none());
    }
}
