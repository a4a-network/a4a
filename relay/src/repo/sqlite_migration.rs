//! Database schema and migrations
use crate::db::PooledConnection;
use crate::error::Result;
use crate::event::{single_char_tagname, Event};
use crate::utils::is_lower_hex;
use const_format::formatcp;
use indicatif::{ProgressBar, ProgressStyle};
use rusqlite::limits::Limit;
use rusqlite::params;
use rusqlite::Connection;
use std::cmp::Ordering;
use std::time::Instant;
use tracing::{debug, error, info};

/// Startup DB Pragmas
pub const STARTUP_SQL: &str = r##"
PRAGMA main.synchronous = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA journal_size_limit = 32768;
PRAGMA temp_store = 2; -- use memory, not temp files
-- Page cache is NOT configured here. `build_pool` applies the configured value
-- when creating a connection. Upstream set 20,000 pages (80 MiB PER CONNECTION)
-- here, and reran the same line after migrations, overwriting operator settings.
pragma mmap_size = 0; -- disable mmap (default)
"##;

/// Latest database version
pub const DB_VERSION: usize = 21;

/// Schema definition
const INIT_SQL: &str = formatcp!(
    r##"
-- Database settings
PRAGMA encoding = "UTF-8";
PRAGMA journal_mode = WAL;
PRAGMA auto_vacuum = FULL;
PRAGMA main.synchronous=NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA application_id = 1654008667;
PRAGMA user_version = {};

-- Event Table
CREATE TABLE IF NOT EXISTS delegation_archive (
event_hash BLOB PRIMARY KEY, -- id of replaced delegation (31000)
content TEXT NOT NULL, -- complete event JSON
replaced_at INTEGER NOT NULL -- replacement time (Unix)
);
CREATE TABLE IF NOT EXISTS event (
id INTEGER PRIMARY KEY,
event_hash BLOB NOT NULL, -- 32-byte SHA256 hash
first_seen INTEGER NOT NULL, -- when the event was first seen (not authored!) (seconds since 1970)
created_at INTEGER NOT NULL, -- when the event was authored
expires_at INTEGER, -- when the event expires and may be deleted
author BLOB NOT NULL, -- author pubkey
delegated_by BLOB, -- delegator pubkey (NIP-26)
kind INTEGER NOT NULL, -- event kind
hidden INTEGER, -- relevant for queries
content TEXT NOT NULL -- serialized json of event object
);

-- Event Indexes
CREATE UNIQUE INDEX IF NOT EXISTS event_hash_index ON event(event_hash);
CREATE INDEX IF NOT EXISTS event_first_seen_index ON event(first_seen, event_hash);
CREATE INDEX IF NOT EXISTS author_index ON event(author);
CREATE INDEX IF NOT EXISTS kind_index ON event(kind);
CREATE INDEX IF NOT EXISTS created_at_index ON event(created_at);
CREATE INDEX IF NOT EXISTS delegated_by_index ON event(delegated_by);
CREATE INDEX IF NOT EXISTS event_composite_index ON event(kind,created_at);
CREATE INDEX IF NOT EXISTS kind_author_index ON event(kind,author);
CREATE INDEX IF NOT EXISTS kind_created_at_index ON event(kind,created_at);
CREATE INDEX IF NOT EXISTS author_created_at_index ON event(author,created_at);
CREATE INDEX IF NOT EXISTS author_kind_index ON event(author,kind);
CREATE INDEX IF NOT EXISTS event_expiration ON event(expires_at);

-- Tag Table
-- Tag values are stored as either a BLOB (if they come in as a
-- hex-string), or TEXT otherwise.
-- This means that searches need to select the appropriate column.
-- We duplicate the kind/created_at to make indexes much more efficient.
CREATE TABLE IF NOT EXISTS tag (
id INTEGER PRIMARY KEY,
event_id INTEGER NOT NULL, -- an event ID that contains a tag.
name TEXT, -- the tag name ("p", "e", whatever)
value TEXT, -- the tag value, if not hex.
value_hex BLOB, -- the tag value, if it can be interpreted as a lowercase hex string.
created_at INTEGER NOT NULL, -- when the event was authored
kind INTEGER NOT NULL, -- event kind
FOREIGN KEY(event_id) REFERENCES event(id) ON UPDATE CASCADE ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS tag_val_index ON tag(value);
CREATE INDEX IF NOT EXISTS tag_composite_index ON tag(event_id,name,value);
CREATE INDEX IF NOT EXISTS tag_name_eid_index ON tag(name,event_id,value);
CREATE INDEX IF NOT EXISTS tag_covering_index ON tag(name,kind,value,created_at,event_id);
CREATE INDEX IF NOT EXISTS tag_name_value_index ON tag(name, value, event_id);

-- NIP-05 User Validation
CREATE TABLE IF NOT EXISTS user_verification (
id INTEGER PRIMARY KEY,
metadata_event INTEGER NOT NULL, -- the metadata event used for this validation.
name TEXT NOT NULL, -- the nip05 field value (user@domain).
verified_at INTEGER, -- timestamp this author/nip05 was most recently verified.
failed_at INTEGER, -- timestamp a verification attempt failed (host down).
failure_count INTEGER DEFAULT 0, -- number of consecutive failures.
FOREIGN KEY(metadata_event) REFERENCES event(id) ON UPDATE CASCADE ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS user_verification_name_index ON user_verification(name);
CREATE INDEX IF NOT EXISTS user_verification_event_index ON user_verification(metadata_event);

-- Create account table
CREATE TABLE IF NOT EXISTS account (
pubkey TEXT PRIMARY KEY,
is_admitted INTEGER NOT NULL DEFAULT 0,
balance INTEGER NOT NULL DEFAULT 0,
tos_accepted_at INTEGER
);

-- Create account index
CREATE INDEX IF NOT EXISTS user_pubkey_index ON account(pubkey);

-- Invoice table
CREATE TABLE IF NOT EXISTS invoice (
payment_hash TEXT PRIMARY KEY,
pubkey TEXT NOT NULL,
invoice TEXT NOT NULL,
amount INTEGER NOT NULL,
status TEXT CHECK ( status IN ('Paid', 'Unpaid', 'Expired' ) ) NOT NUll DEFAULT 'Unpaid',
description TEXT,
created_at INTEGER NOT NULL,
confirmed_at INTEGER,
CONSTRAINT invoice_pubkey_fkey FOREIGN KEY (pubkey) REFERENCES account (pubkey) ON DELETE CASCADE
);

-- Create invoice index
CREATE INDEX IF NOT EXISTS invoice_pubkey_index ON invoice(pubkey);


"##,
    DB_VERSION
);

/// Determine the current application database schema version.
pub fn curr_db_version(conn: &mut Connection) -> Result<usize> {
    let query = "PRAGMA user_version;";
    let curr_version: usize = conn.query_row(query, [], |row| row.get::<_, i64>(0))? as usize;
    Ok(curr_version)
}

/// Determine event count
pub fn db_event_count(conn: &mut Connection) -> Result<usize> {
    let query = "SELECT count(*) FROM event;";
    let count: usize = conn.query_row(query, [], |row| row.get::<_, i64>(0))? as usize;
    Ok(count)
}

/// Determine tag count
pub fn db_tag_count(conn: &mut Connection) -> Result<usize> {
    let query = "SELECT count(*) FROM tag;";
    let count: usize = conn.query_row(query, [], |row| row.get::<_, i64>(0))? as usize;
    Ok(count)
}

fn mig_init(conn: &mut PooledConnection) -> usize {
    match conn.execute_batch(INIT_SQL) {
        Ok(()) => {
            info!(
                "database pragma/schema initialized to v{}, and ready",
                DB_VERSION
            );
        }
        Err(err) => {
            error!("update (init) failed: {}", err);
            panic!("database could not be initialized");
        }
    }
    DB_VERSION
}

/// Upgrade DB to latest version, and execute pragma settings
pub fn upgrade_db(conn: &mut PooledConnection) -> Result<usize> {
    // check the version.
    let mut curr_version = curr_db_version(conn)?;
    info!("DB version = {:?}", curr_version);

    debug!(
        "SQLite max query parameters: {}",
        conn.limit(Limit::SQLITE_LIMIT_VARIABLE_NUMBER).unwrap_or(-1)
    );
    debug!(
        "SQLite max table/blob/text length: {} MB",
        (f64::from(conn.limit(Limit::SQLITE_LIMIT_LENGTH).unwrap_or(-1)) / f64::from(1024 * 1024)).floor()
    );
    debug!(
        "SQLite max SQL length: {} MB",
        (f64::from(conn.limit(Limit::SQLITE_LIMIT_SQL_LENGTH).unwrap_or(-1)) / f64::from(1024 * 1024)).floor()
    );

    match curr_version.cmp(&DB_VERSION) {
        // Database is new or not current
        Ordering::Less => {
            // initialize from scratch
            if curr_version == 0 {
                curr_version = mig_init(conn);
            }
            // for initialized but out-of-date schemas, proceed to
            // upgrade sequentially until we are current.
            if curr_version == 1 {
                curr_version = mig_1_to_2(conn)?;
            }
            if curr_version == 2 {
                curr_version = mig_2_to_3(conn)?;
            }
            if curr_version == 3 {
                curr_version = mig_3_to_4(conn)?;
            }
            if curr_version == 4 {
                curr_version = mig_4_to_5(conn)?;
            }
            if curr_version == 5 {
                curr_version = mig_5_to_6(conn)?;
            }
            if curr_version == 6 {
                curr_version = mig_6_to_7(conn)?;
            }
            if curr_version == 7 {
                curr_version = mig_7_to_8(conn)?;
            }
            if curr_version == 8 {
                curr_version = mig_8_to_9(conn)?;
            }
            if curr_version == 9 {
                curr_version = mig_9_to_10(conn)?;
            }
            if curr_version == 10 {
                curr_version = mig_10_to_11(conn)?;
            }
            if curr_version == 11 {
                curr_version = mig_11_to_12(conn)?;
            }
            if curr_version == 12 {
                curr_version = mig_12_to_13(conn)?;
            }
            if curr_version == 13 {
                curr_version = mig_13_to_14(conn)?;
            }
            if curr_version == 14 {
                curr_version = mig_14_to_15(conn)?;
            }
            if curr_version == 15 {
                curr_version = mig_15_to_16(conn)?;
            }
            if curr_version == 16 {
                curr_version = mig_16_to_17(conn)?;
            }
            if curr_version == 17 {
                curr_version = mig_17_to_18(conn)?;
            }
            if curr_version == 18 {
                curr_version = mig_18_to_19(conn)?;
            }
            if curr_version == 19 {
                curr_version = mig_19_to_20(conn)?;
            }
            if curr_version == 20 {
                curr_version = mig_20_to_21(conn)?;
            }

            if curr_version == DB_VERSION {
                info!(
                    "All migration scripts completed successfully.  Welcome to v{}.",
                    DB_VERSION
                );
            }
        }
        // Database is current, all is good
        Ordering::Equal => {
            debug!("Database version was already current (v{DB_VERSION})");
        }
        // Database is newer than what this code understands, abort.
        //
        // RETURN an error rather than panicking. This runs in a worker thread, so
        // the panic did NOT stop the relay. A 2026-09-14 test against a newer schema
        // panicked in migration while continuing to accept and serve events. Failure
        // must be a value the caller handles, not a message lost in logs.
        Ordering::Greater => {
            return Err(crate::error::Error::DatabaseSchemaTooNew {
                found: curr_version,
                supported: DB_VERSION,
            });
        }
    }

    // Setup PRAGMA
    conn.execute_batch(STARTUP_SQL)?;
    debug!("SQLite PRAGMA startup completed");
    Ok(DB_VERSION)
}

pub fn rebuild_tags(conn: &mut PooledConnection) -> Result<()> {
    // Check how many events we have to process
    let count = db_event_count(conn)?;
    let update_each_percent = 0.05;
    let mut percent_done = 0.0;
    let mut events_processed = 0;
    let start = Instant::now();
    let tx = conn.transaction()?;
    {
        // Clear out table
        tx.execute("DELETE FROM tag;", [])?;
        let mut stmt = tx.prepare("select id, content from event order by id;")?;
        let mut tag_rows = stmt.query([])?;
        while let Some(row) = tag_rows.next()? {
            if (events_processed as f32) / (count as f32) > percent_done {
                info!("Tag update {}% complete...", (100.0 * percent_done).round());
                percent_done += update_each_percent;
            }
            // we want to capture the event_id that had the tag, the tag name, and the tag hex value.
            let event_id: u64 = crate::utils::sql_to_u64(row.get::<_, i64>(0)?);
            let event_json: String = row.get(1)?;
            let event: Event = serde_json::from_str(&event_json)?;
            // look at each event, and each tag, creating new tag entries if appropriate.
            for t in event.tags.iter().filter(|x| x.len() > 1) {
                let tagname = t.first().unwrap();
                let tagnamechar_opt = single_char_tagname(tagname);
                if tagnamechar_opt.is_none() {
                    continue;
                }
                // safe because len was > 1
                let tagval = t.get(1).unwrap();
                // insert as BLOB if we can restore it losslessly.
                // this means it needs to be even length and lowercase.
                if (tagval.len() % 2 == 0) && is_lower_hex(tagval) {
                    tx.execute(
                        "INSERT INTO tag (event_id, name, value_hex) VALUES (?1, ?2, ?3);",
                        params![crate::utils::u64_to_sql(event_id), tagname, hex::decode(tagval).ok()],
                    )?;
                } else {
                    // otherwise, insert as text
                    tx.execute(
                        "INSERT INTO tag (event_id, name, value) VALUES (?1, ?2, ?3);",
                        params![crate::utils::u64_to_sql(event_id), tagname, &tagval],
                    )?;
                }
            }
            events_processed += 1;
        }
    }
    tx.commit()?;
    info!("rebuilt tags in {:?}", start.elapsed());
    Ok(())
}

// Migration Scripts

fn mig_1_to_2(conn: &mut PooledConnection) -> Result<usize> {
    // only change is adding a hidden column to events.
    let upgrade_sql = r##"
ALTER TABLE event ADD hidden INTEGER;
UPDATE event SET hidden=FALSE;
PRAGMA user_version = 2;
"##;
    match conn.execute_batch(upgrade_sql) {
        Ok(()) => {
            info!("database schema upgraded v1 -> v2");
        }
        Err(err) => {
            error!("update (v1->v2) failed: {}", err);
            panic!("database could not be upgraded");
        }
    }
    Ok(2)
}

fn mig_2_to_3(conn: &mut PooledConnection) -> Result<usize> {
    // this version lacks the tag column
    info!("database schema needs update from 2->3");
    let upgrade_sql = r##"
CREATE TABLE IF NOT EXISTS tag (
id INTEGER PRIMARY KEY,
event_id INTEGER NOT NULL, -- an event ID that contains a tag.
name TEXT, -- the tag name ("p", "e", whatever)
value TEXT, -- the tag value, if not hex.
value_hex BLOB, -- the tag value, if it can be interpreted as a hex string.
FOREIGN KEY(event_id) REFERENCES event(id) ON UPDATE CASCADE ON DELETE CASCADE
);
PRAGMA user_version = 3;
"##;
    // Known migration limitation inherited from upstream: v2 event references are
    // not backfilled into the new tag table. Fresh databases are unaffected; operators
    // upgrading such an old database must rebuild the tag index before relying on it.
    match conn.execute_batch(upgrade_sql) {
        Ok(()) => {
            info!("database schema upgraded v2 -> v3");
        }
        Err(err) => {
            error!("update (v2->v3) failed: {}", err);
            panic!("database could not be upgraded");
        }
    }
    // iterate over every event/pubkey tag
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare("select event_id, \"e\", lower(hex(referenced_event)) from event_ref union select event_id, \"p\", lower(hex(referenced_pubkey)) from pubkey_ref;")?;
        let mut tag_rows = stmt.query([])?;
        while let Some(row) = tag_rows.next()? {
            // we want to capture the event_id that had the tag, the tag name, and the tag hex value.
            let event_id: u64 = crate::utils::sql_to_u64(row.get::<_, i64>(0)?);
            let tag_name: String = row.get(1)?;
            let tag_value: String = row.get(2)?;
            // this will leave behind p/e tags that were non-hex, but they are invalid anyways.
            if is_lower_hex(&tag_value) {
                tx.execute(
                    "INSERT INTO tag (event_id, name, value_hex) VALUES (?1, ?2, ?3);",
                    params![crate::utils::u64_to_sql(event_id), tag_name, hex::decode(&tag_value).ok()],
                )?;
            }
        }
    }
    info!("Updated tag values");
    tx.commit()?;
    Ok(3)
}

fn mig_3_to_4(conn: &mut PooledConnection) -> Result<usize> {
    info!("database schema needs update from 3->4");
    let upgrade_sql = r##"
-- incoming metadata events with nip05
CREATE TABLE IF NOT EXISTS user_verification (
id INTEGER PRIMARY KEY,
metadata_event INTEGER NOT NULL, -- the metadata event used for this validation.
name TEXT NOT NULL, -- the nip05 field value (user@domain).
verified_at INTEGER, -- timestamp this author/nip05 was most recently verified.
failed_at INTEGER, -- timestamp a verification attempt failed (host down).
failure_count INTEGER DEFAULT 0, -- number of consecutive failures.
FOREIGN KEY(metadata_event) REFERENCES event(id) ON UPDATE CASCADE ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS user_verification_name_index ON user_verification(name);
CREATE INDEX IF NOT EXISTS user_verification_event_index ON user_verification(metadata_event);
PRAGMA user_version = 4;
"##;
    match conn.execute_batch(upgrade_sql) {
        Ok(()) => {
            info!("database schema upgraded v3 -> v4");
        }
        Err(err) => {
            error!("update (v3->v4) failed: {}", err);
            panic!("database could not be upgraded");
        }
    }
    Ok(4)
}

fn mig_4_to_5(conn: &mut PooledConnection) -> Result<usize> {
    info!("database schema needs update from 4->5");
    let upgrade_sql = r##"
DROP TABLE IF EXISTS event_ref;
DROP TABLE IF EXISTS pubkey_ref;
PRAGMA user_version=5;
"##;
    match conn.execute_batch(upgrade_sql) {
        Ok(()) => {
            info!("database schema upgraded v4 -> v5");
        }
        Err(err) => {
            error!("update (v4->v5) failed: {}", err);
            panic!("database could not be upgraded");
        }
    }
    Ok(5)
}

fn mig_5_to_6(conn: &mut PooledConnection) -> Result<usize> {
    info!("database schema needs update from 5->6");
    // We need to rebuild the tags table.  iterate through the
    // event table.  build event from json, insert tags into a
    // fresh tag table.  This was needed due to a logic error in
    // how hex-like tags got indexed.
    let start = Instant::now();
    let tx = conn.transaction()?;
    {
        // Clear out table
        tx.execute("DELETE FROM tag;", [])?;
        let mut stmt = tx.prepare("select id, content from event order by id;")?;
        let mut tag_rows = stmt.query([])?;
        while let Some(row) = tag_rows.next()? {
            let event_id: u64 = crate::utils::sql_to_u64(row.get::<_, i64>(0)?);
            let event_json: String = row.get(1)?;
            let event: Event = serde_json::from_str(&event_json)?;
            // look at each event, and each tag, creating new tag entries if appropriate.
            for t in event.tags.iter().filter(|x| x.len() > 1) {
                let tagname = t.first().unwrap();
                let tagnamechar_opt = single_char_tagname(tagname);
                if tagnamechar_opt.is_none() {
                    continue;
                }
                // safe because len was > 1
                let tagval = t.get(1).unwrap();
                // insert as BLOB if we can restore it losslessly.
                // this means it needs to be even length and lowercase.
                if (tagval.len() % 2 == 0) && is_lower_hex(tagval) {
                    tx.execute(
                        "INSERT INTO tag (event_id, name, value_hex) VALUES (?1, ?2, ?3);",
                        params![crate::utils::u64_to_sql(event_id), tagname, hex::decode(tagval).ok()],
                    )?;
                } else {
                    // otherwise, insert as text
                    tx.execute(
                        "INSERT INTO tag (event_id, name, value) VALUES (?1, ?2, ?3);",
                        params![crate::utils::u64_to_sql(event_id), tagname, &tagval],
                    )?;
                }
            }
        }
        tx.execute("PRAGMA user_version = 6;", [])?;
    }
    tx.commit()?;
    info!("database schema upgraded v5 -> v6 in {:?}", start.elapsed());
    // vacuum after large table modification
    let start = Instant::now();
    conn.execute("VACUUM;", [])?;
    info!("vacuumed DB after tags rebuild in {:?}", start.elapsed());
    Ok(6)
}

fn mig_6_to_7(conn: &mut PooledConnection) -> Result<usize> {
    info!("database schema needs update from 6->7");
    let upgrade_sql = r##"
ALTER TABLE event ADD delegated_by BLOB;
CREATE INDEX IF NOT EXISTS delegated_by_index ON event(delegated_by);
PRAGMA user_version = 7;
"##;
    match conn.execute_batch(upgrade_sql) {
        Ok(()) => {
            info!("database schema upgraded v6 -> v7");
        }
        Err(err) => {
            error!("update (v6->v7) failed: {}", err);
            panic!("database could not be upgraded");
        }
    }
    Ok(7)
}

fn mig_7_to_8(conn: &mut PooledConnection) -> Result<usize> {
    info!("database schema needs update from 7->8");
    // Remove redundant indexes, and add a better multi-column index.
    let upgrade_sql = r##"
DROP INDEX IF EXISTS created_at_index;
DROP INDEX IF EXISTS kind_index;
CREATE INDEX IF NOT EXISTS event_composite_index ON event(kind,created_at);
PRAGMA user_version = 8;
"##;
    match conn.execute_batch(upgrade_sql) {
        Ok(()) => {
            info!("database schema upgraded v7 -> v8");
        }
        Err(err) => {
            error!("update (v7->v8) failed: {}", err);
            panic!("database could not be upgraded");
        }
    }
    Ok(8)
}

fn mig_8_to_9(conn: &mut PooledConnection) -> Result<usize> {
    info!("database schema needs update from 8->9");
    // Those old indexes were actually helpful...
    let upgrade_sql = r##"
CREATE INDEX IF NOT EXISTS created_at_index ON event(created_at);
CREATE INDEX IF NOT EXISTS event_composite_index ON event(kind,created_at);
PRAGMA user_version = 9;
"##;
    match conn.execute_batch(upgrade_sql) {
        Ok(()) => {
            info!("database schema upgraded v8 -> v9");
        }
        Err(err) => {
            error!("update (v8->v9) failed: {}", err);
            panic!("database could not be upgraded");
        }
    }
    Ok(9)
}

fn mig_9_to_10(conn: &mut PooledConnection) -> Result<usize> {
    info!("database schema needs update from 9->10");
    // Those old indexes were actually helpful...
    let upgrade_sql = r##"
CREATE INDEX IF NOT EXISTS tag_composite_index ON tag(event_id,name,value_hex,value);
PRAGMA user_version = 10;
"##;
    match conn.execute_batch(upgrade_sql) {
        Ok(()) => {
            info!("database schema upgraded v9 -> v10");
        }
        Err(err) => {
            error!("update (v9->v10) failed: {}", err);
            panic!("database could not be upgraded");
        }
    }
    Ok(10)
}

fn mig_10_to_11(conn: &mut PooledConnection) -> Result<usize> {
    info!("database schema needs update from 10->11");
    // Those old indexes were actually helpful...
    let upgrade_sql = r##"
CREATE INDEX IF NOT EXISTS tag_name_eid_index ON tag(name,event_id,value_hex);
reindex;
pragma optimize;
PRAGMA user_version = 11;
"##;
    match conn.execute_batch(upgrade_sql) {
        Ok(()) => {
            info!("database schema upgraded v10 -> v11");
        }
        Err(err) => {
            error!("update (v10->v11) failed: {}", err);
            panic!("database could not be upgraded");
        }
    }
    Ok(11)
}

fn mig_11_to_12(conn: &mut PooledConnection) -> Result<usize> {
    info!("database schema needs update from 11->12");
    let start = Instant::now();
    let tx = conn.transaction()?;
    {
        // Lookup every replaceable event
        let mut stmt = tx.prepare("select kind,author from event where kind in (0,3,41) or (kind>=10000 and kind<20000) order by id;")?;
        let mut replaceable_rows = stmt.query([])?;
        info!("updating replaceable events; this could take awhile...");
        while let Some(row) = replaceable_rows.next()? {
            // we want to capture the event_id that had the tag, the tag name, and the tag hex value.
            let event_kind: u64 = crate::utils::sql_to_u64(row.get::<_, i64>(0)?);
            let event_author: Vec<u8> = row.get(1)?;
            tx.execute(
                "UPDATE event SET hidden=TRUE WHERE hidden!=TRUE and kind=? and author=? and id NOT IN (SELECT id FROM event WHERE kind=? AND author=? ORDER BY created_at DESC LIMIT 1)",
                params![crate::utils::u64_to_sql(event_kind), event_author, crate::utils::u64_to_sql(event_kind), event_author],
            )?;
        }
        tx.execute("PRAGMA user_version = 12;", [])?;
    }
    tx.commit()?;
    info!(
        "database schema upgraded v11 -> v12 in {:?}",
        start.elapsed()
    );
    // vacuum after large table modification
    let start = Instant::now();
    conn.execute("VACUUM;", [])?;
    info!(
        "vacuumed DB after hidden event cleanup in {:?}",
        start.elapsed()
    );
    Ok(12)
}

fn mig_12_to_13(conn: &mut PooledConnection) -> Result<usize> {
    info!("database schema needs update from 12->13");
    let upgrade_sql = r##"
CREATE INDEX IF NOT EXISTS kind_author_index ON event(kind,author);
reindex;
pragma optimize;
PRAGMA user_version = 13;
"##;
    match conn.execute_batch(upgrade_sql) {
        Ok(()) => {
            info!("database schema upgraded v12 -> v13");
        }
        Err(err) => {
            error!("update (v12->v13) failed: {}", err);
            panic!("database could not be upgraded");
        }
    }
    Ok(13)
}

fn mig_13_to_14(conn: &mut PooledConnection) -> Result<usize> {
    info!("database schema needs update from 13->14");
    let upgrade_sql = r##"
CREATE INDEX IF NOT EXISTS kind_index ON event(kind);
CREATE INDEX IF NOT EXISTS kind_created_at_index ON event(kind,created_at);
pragma optimize;
PRAGMA user_version = 14;
"##;
    match conn.execute_batch(upgrade_sql) {
        Ok(()) => {
            info!("database schema upgraded v13 -> v14");
        }
        Err(err) => {
            error!("update (v13->v14) failed: {}", err);
            panic!("database could not be upgraded");
        }
    }
    Ok(14)
}

fn mig_14_to_15(conn: &mut PooledConnection) -> Result<usize> {
    info!("database schema needs update from 14->15");
    let upgrade_sql = r##"
CREATE INDEX IF NOT EXISTS author_created_at_index ON event(author,created_at);
CREATE INDEX IF NOT EXISTS author_kind_index ON event(author,kind);
PRAGMA user_version = 15;
"##;
    match conn.execute_batch(upgrade_sql) {
        Ok(()) => {
            info!("database schema upgraded v14 -> v15");
        }
        Err(err) => {
            error!("update (v14->v15) failed: {}", err);
            panic!("database could not be upgraded");
        }
    }
    // clear out hidden events
    let clear_hidden_sql = r##"DELETE FROM event WHERE HIDDEN=true;"##;
    info!("removing hidden events; this may take awhile...");
    match conn.execute_batch(clear_hidden_sql) {
        Ok(()) => {
            info!("all hidden events removed");
        }
        Err(err) => {
            error!("delete failed: {}", err);
            panic!("could not remove hidden events");
        }
    }
    Ok(15)
}

fn mig_15_to_16(conn: &mut PooledConnection) -> Result<usize> {
    let count = db_event_count(conn)?;
    info!("database schema needs update from 15->16 (this may take a few minutes)");
    let upgrade_sql = r##"
DROP TABLE tag;
CREATE TABLE tag (
id INTEGER PRIMARY KEY,
event_id INTEGER NOT NULL, -- an event ID that contains a tag.
name TEXT, -- the tag name ("p", "e", whatever)
value TEXT, -- the tag value, if not hex.
created_at INTEGER NOT NULL, -- when the event was authored
kind INTEGER NOT NULL, -- event kind
FOREIGN KEY(event_id) REFERENCES event(id) ON UPDATE CASCADE ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS tag_val_index ON tag(value);
CREATE INDEX IF NOT EXISTS tag_composite_index ON tag(event_id,name,value);
CREATE INDEX IF NOT EXISTS tag_name_eid_index ON tag(name,event_id,value);
CREATE INDEX IF NOT EXISTS tag_covering_index ON tag(name,kind,value,created_at,event_id);
"##;

    let start = Instant::now();
    let tx = conn.transaction()?;

    let bar = ProgressBar::new(count.try_into().unwrap()).with_message("rebuilding tags table");
    bar.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}] {bar:40.white/blue} {pos:>7}/{len:7} [{percent}%] {msg}",
        )
        .unwrap(),
    );
    {
        tx.execute_batch(upgrade_sql)?;
        let mut stmt =
            tx.prepare("select id, kind, created_at, content from event order by id;")?;
        let mut tag_rows = stmt.query([])?;
        let mut count = 0;
        while let Some(row) = tag_rows.next()? {
            count += 1;
            if count % 10 == 0 {
                bar.inc(10);
            }
            let event_id: u64 = crate::utils::sql_to_u64(row.get::<_, i64>(0)?);
            let kind: u64 = crate::utils::sql_to_u64(row.get::<_, i64>(1)?);
            let created_at: u64 = crate::utils::sql_to_u64(row.get::<_, i64>(2)?);
            let event_json: String = row.get(3)?;
            let event: Event = serde_json::from_str(&event_json)?;
            // look at each event, and each tag, creating new tag entries if appropriate.
            for t in event.tags.iter().filter(|x| x.len() > 1) {
                let tagname = t.first().unwrap();
                let tagnamechar_opt = single_char_tagname(tagname);
                if tagnamechar_opt.is_none() {
                    continue;
                }
                // safe because len was > 1
                let tagval = t.get(1).unwrap();
                // otherwise, insert as text
                tx.execute(
                    "INSERT INTO tag (event_id, name, value, kind, created_at) VALUES (?1, ?2, ?3, ?4, ?5);",
                    params![crate::utils::u64_to_sql(event_id), tagname, &tagval, crate::utils::u64_to_sql(kind), crate::utils::u64_to_sql(created_at)],
                )?;
            }
        }
        tx.execute("PRAGMA user_version = 16;", [])?;
    }
    bar.finish();
    tx.commit()?;
    info!(
        "database schema upgraded v15 -> v16 in {:?}",
        start.elapsed()
    );
    Ok(16)
}

fn mig_16_to_17(conn: &mut PooledConnection) -> Result<usize> {
    info!("database schema needs update from 16->17");
    let upgrade_sql = r##"
ALTER TABLE event ADD COLUMN expires_at INTEGER;
CREATE INDEX IF NOT EXISTS event_expiration ON event(expires_at);
PRAGMA user_version = 17;
"##;
    match conn.execute_batch(upgrade_sql) {
        Ok(()) => {
            info!("database schema upgraded v16 -> v17");
        }
        Err(err) => {
            error!("update (v16->v17) failed: {}", err);
            panic!("database could not be upgraded");
        }
    }
    Ok(17)
}

fn mig_17_to_18(conn: &mut PooledConnection) -> Result<usize> {
    info!("database schema needs update from 17->18");
    let upgrade_sql = r##"
-- Create invoices table
CREATE TABLE IF NOT EXISTS invoice (
payment_hash TEXT PRIMARY KEY,
pubkey TEXT NOT NULL,
invoice TEXT NOT NULL,
amount INTEGER NOT NULL,
status TEXT CHECK ( status IN ('Paid', 'Unpaid', 'Expired' ) ) NOT NUll DEFAULT 'Unpaid',
description TEXT,
created_at INTEGER NOT NULL,
confirmed_at INTEGER,
CONSTRAINT invoice_pubkey_fkey FOREIGN KEY (pubkey) REFERENCES account (pubkey) ON DELETE CASCADE
);

-- Create invoice index
CREATE INDEX IF NOT EXISTS invoice_pubkey_index ON invoice(pubkey);

-- Create account table

CREATE TABLE IF NOT EXISTS account (
pubkey TEXT PRIMARY KEY,
is_admitted INTEGER NOT NULL DEFAULT 0,
balance INTEGER NOT NULL DEFAULT 0,
tos_accepted_at INTEGER
);

-- Create account index
CREATE INDEX IF NOT EXISTS account_pubkey_index ON account(pubkey);


pragma optimize;
PRAGMA user_version = 18;
"##;
    match conn.execute_batch(upgrade_sql) {
        Ok(()) => {
            info!("database schema upgraded v17 -> v18");
        }
        Err(err) => {
            error!("update (v17->v18) failed: {}", err);
            panic!("database could not be upgraded");
        }
    }
    Ok(18)
}

fn mig_18_to_19(conn: &mut PooledConnection) -> Result<usize> {
    info!("database schema needs update from 18->19");
    // A4A `#category`-style multi-char tag filters search by (name,
    // value) without necessarily constraining `kind`, so
    // `tag_covering_index(name,kind,value,...)` can't be used
    // sargably. Add a dedicated (name, value, event_id) index.
    let upgrade_sql = r##"
CREATE INDEX IF NOT EXISTS tag_name_value_index ON tag(name, value, event_id);
PRAGMA user_version = 19;
"##;
    match conn.execute_batch(upgrade_sql) {
        Ok(()) => {
            info!("database schema upgraded v18 -> v19");
        }
        Err(err) => {
            error!("update (v18->v19) failed: {}", err);
            panic!("database could not be upgraded");
        }
    }
    Ok(19)
}

fn mig_19_to_20(conn: &mut PooledConnection) -> Result<usize> {
    info!("database schema needs update from 19->20");
    // Archive replaced delegations (internal finding 65 / F4). NIP-33 replacement
    // physically deleted the old kind-31000 event, making older agent events that
    // referenced it unverifiable even with a timestamp. The archive is a separate
    // table, invisible to intake and coordinate lookup and exposed only through REST
    // /v1/delegation-history/<id>.
    let upgrade_sql = r##"
CREATE TABLE IF NOT EXISTS delegation_archive (
event_hash BLOB PRIMARY KEY,
content TEXT NOT NULL,
replaced_at INTEGER NOT NULL
);
PRAGMA user_version = 20;
"##;
    match conn.execute_batch(upgrade_sql) {
        Ok(()) => {
            info!("database schema upgraded v19 -> v20");
        }
        Err(err) => {
            error!("update (v19->v20) failed: {}", err);
            panic!("database could not be upgraded");
        }
    }
    Ok(20)
}

fn mig_20_to_21(conn: &mut PooledConnection) -> Result<usize> {
    let tx = conn.transaction()?;
    tx.execute_batch(
        "CREATE INDEX IF NOT EXISTS event_first_seen_index ON event(first_seen, event_hash); \
         PRAGMA user_version = 21;"
    )?;
    tx.commit()?;
    info!("database schema upgraded v20 -> v21 (bounded history scan)");
    Ok(21)
}
