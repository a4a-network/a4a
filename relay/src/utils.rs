//! Common utility functions
use bech32::FromBase32;
use std::time::SystemTime;
use url::Url;

/// Seconds since 1970, or `None` when `now` is before the epoch.
///
/// `None` is a third outcome: the clock could not be read. Callers that
/// decide whether a mandate or NIP-05 record is still live must not treat it
/// as zero. Zero made every `exp > 0` look unexpired.
#[must_use]
pub fn unix_time_from(now: SystemTime) -> Option<u64> {
    now.duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .map(|x| x.as_secs())
}

/// Seconds since 1970.
///
/// A clock before 1970 used to become 0 via `unwrap_or(0)`. Every mandate
/// with `exp > 0` then looked unexpired, and a NIP-05 record looked fresh.
/// `u64::MAX` fails closed for those comparisons (`exp > now` is false,
/// `exp <= now` is true). Callers that need the distinct "clock unusable"
/// answer use [`unix_time_from`].
#[must_use]
pub fn unix_time() -> u64 {
    unix_time_from(SystemTime::now()).unwrap_or(u64::MAX)
}

/// Whether `exp` is still in the future.
///
/// `None` means the clock could not be read. That is not "still open":
/// `unwrap_or(0)` used to make `exp > 0` return true.
#[must_use]
pub fn deadline_still_open(exp: u64, now: Option<u64>) -> Option<bool> {
    now.map(|now| exp > now)
}

/// Check if a string contains only hex characters.
#[must_use]
/// Parse an unsigned integer written CANONICALLY: decimal digits only, 1..=19 of
/// them. Mirrors `parse_uint` in the Python SDK (`[0-9]{1,19}`).
///
/// `str::parse::<u64>` accepts a leading `+`, which the SDK does not, and a
/// counterparty found the consequence on the wire: a delegation whose
/// `expiration` read `"+N"` was valid for this relay and invalid for every SDK
/// client (third wave, 04.09.2026). Two readers of one protocol must agree on
/// what a number is, so the relay takes the stricter grammar.
pub fn parse_canonical_u64(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 19 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // Forbid leading zeroes except in "0". The first canonical form allowed them,
    // making "045000" hash like "45000" for a normalizing client but differently
    // for a literal client. Grammar 0|[1-9][0-9]{0,18} is shared by relay, SDK,
    // and specification section 1.1 rule 7.
    if s.len() > 1 && s.starts_with('0') {
        return None;
    }
    s.parse::<u64>().ok()
}

#[must_use]
pub fn is_hex(s: &str) -> bool {
    s.chars().all(|x| char::is_ascii_hexdigit(&x))
}

/// Check if string is an A4A Bech32 address string
pub fn is_nip19(s: &str) -> bool {
    s.starts_with("apub") || s.starts_with("note")
}

pub fn nip19_to_hex(s: &str) -> Result<String, bech32::Error> {
    let (_hrp, data, _checksum) = bech32::decode(s)?;
    let data = Vec::<u8>::from_base32(&data)?;
    Ok(hex::encode(data))
}

/// Check if a string contains only lower-case hex chars.
#[must_use]
pub fn is_lower_hex(s: &str) -> bool {
    s.chars().all(|x| {
        (char::is_ascii_lowercase(&x) || char::is_ascii_digit(&x)) && char::is_ascii_hexdigit(&x)
    })
}

/// True if a tag value is stored in the `value_hex` column rather than `value`.
///
/// The write path has always required BOTH lower-case hex AND an even length
/// (`hex::decode` needs whole bytes), but the query builder classified values by
/// `is_lower_hex` alone. An odd-length hex value such as `"abc"` was therefore
/// written to `value` and looked for in `value_hex` -- and worse, it counted as
/// "there are hex values here", opening `value_hex in (` and then being filtered
/// back out when the list was filled. The result was `value_hex in ()`, which
/// Postgres rejects outright: one such value in a filter killed the whole query.
/// Both paths now ask the same question in one place.
#[must_use]
pub fn is_hex_tag_value(s: &str) -> bool {
    s.len().is_multiple_of(2) && is_lower_hex(s)
}

pub fn host_str(url: &str) -> Option<String> {
    Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|s| s.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_before_epoch_does_not_become_zero() {
        let before = SystemTime::UNIX_EPOCH - std::time::Duration::from_secs(86_400);
        assert_eq!(unix_time_from(before), None);
        assert_eq!(unix_time_from(SystemTime::UNIX_EPOCH), Some(0));
        // `None` is "could not read the clock", not "the deadline is open".
        // `Some(0)` is what the old `unwrap_or(0)` produced, and it opens exp=1.
        assert_eq!(deadline_still_open(1, None), None);
        assert_eq!(deadline_still_open(1, Some(0)), Some(true));
        assert_eq!(deadline_still_open(1, Some(1)), Some(false));
    }

    #[test]
    fn lower_hex() {
        let hexstr = "abcd0123";
        assert!(is_lower_hex(hexstr));
    }

    #[test]
    fn nip19() {
        let hexkey = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
        let nip19key = "apub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwscxttfz";
        assert!(!is_nip19(hexkey));
        assert!(is_nip19(nip19key));
    }

    #[test]
    fn nip19_hex() {
        let nip19key = "apub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwscxttfz";
        let expected = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
        let got = nip19_to_hex(nip19key).unwrap();

        assert_eq!(expected, got);
    }
}

/// SQLite stores SIGNED integers (i64). rusqlite 0.40 intentionally removed
/// automatic `u64` <-> `i64` conversions because they silently overflowed. Using
/// `as` would restore that defect, so conversions here are explicit and saturating.
///
/// This is reachable: `created_at` comes from the network and may be any value. On
/// overflow, a far-future timestamp would become negative and appear ancient,
/// changing the event's behavior in time comparisons.
pub fn u64_to_sql(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Reverse conversion. A negative database value is corrupt or a legacy overflow;
/// treat it as zero rather than a huge unsigned number.
pub fn sql_to_u64(v: i64) -> u64 {
    v.max(0) as u64
}

/// True if the client that asked for a query is no longer waiting for it.
///
/// The abandon channel signals cancellation two ways, and only one of them used
/// to be honoured. An explicit `send(())` (what the WS path does on CLOSE and on
/// connection cleanup) makes `try_recv` return `Ok`. But a DROPPED sender makes
/// it return `Err(Closed)` -- and the checks read `.is_ok()`, so a dropped
/// sender was indistinguishable from "still waiting". `/v1/search` cancels
/// purely by dropping: its handler returns after a 10 s timeout while the
/// blocking thread keeps scanning the table for a receiver that no longer
/// exists. Only `Err(Empty)` means "keep going"; everything else means nobody
/// will ever read the rows.
pub fn client_abandoned_query(rx: &mut tokio::sync::oneshot::Receiver<()>) -> bool {
    !matches!(
        rx.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    )
}

/// Seconds since the epoch as a chrono timestamp, saturating instead of panicking.
///
/// `created_at`, `since` and `until` arrive from the network as `u64` and are not
/// bounded by anything before they reach the storage layer (`reject_future_seconds`
/// is optional and unset in production). `Utc.timestamp_opt` returns `None` outside
/// chrono's range, and the Postgres backend called `.unwrap()` on it -- so a single
/// event with an absurd `created_at` panicked inside `db_writer`. That task dying
/// takes the relay's whole write path with it: `event_tx` sends fail from then on,
/// the WS path swallows the error, and the relay keeps serving reads while quietly
/// accepting nothing at all until it is restarted. The SQLite backend already
/// saturates (`u64_to_sql`); this is the same decision for chrono.
#[must_use]
pub fn u64_to_timestamp(secs: u64) -> chrono::DateTime<chrono::Utc> {
    use chrono::TimeZone;
    chrono::Utc
        .timestamp_opt(u64_to_sql(secs), 0)
        .latest()
        .unwrap_or(chrono::DateTime::<chrono::Utc>::MAX_UTC)
}

#[cfg(test)]
mod a4a_conversion_tests {
    use super::*;

    /// A `created_at` far outside chrono's range used to panic inside `db_writer`
    /// on the Postgres backend, and that task dying silently stops the relay from
    /// accepting ANY event until restart. Saturate, exactly as `u64_to_sql` does.
    #[test]
    fn absurd_timestamps_saturate_instead_of_panicking() {
        let _ = u64_to_timestamp(900_000_000_000_000_000);
        let _ = u64_to_timestamp(u64::MAX);
        assert_eq!(u64_to_timestamp(0).timestamp(), 0);
        assert_eq!(u64_to_timestamp(1_700_000_000).timestamp(), 1_700_000_000);
    }

    /// The write path stores a tag value in `value_hex` only when it is lower-case
    /// hex AND of even length; the query path must agree, or values are looked for
    /// in the column they were never written to.
    #[test]
    fn odd_length_hex_is_not_a_hex_tag_value() {
        assert!(is_hex_tag_value("abcd"));
        assert!(!is_hex_tag_value("abc"), "odd length cannot fit value_hex");
        assert!(!is_hex_tag_value("ABCD"), "uppercase uses the regular column");
        assert!(!is_hex_tag_value("zz"));
    }
}
