//! Server process
use crate::close::Close;
use crate::close::CloseCmd;
use crate::config::{Settings, VerifiedUsersMode};
use crate::conn;
use crate::db;
use crate::db::SubmittedEvent;
use crate::error::{Error, Result};
use crate::event::Event;
use crate::event::EventCmd;
use crate::event::EventWrapper;
use crate::info::RelayInfo;
use crate::nip05;
use crate::notice::{EventResultStatus, Notice};
use crate::repo::NostrRepo;
use crate::server::Error::CommandUnknownError;
use crate::server::EventWrapper::{WrappedAuth, WrappedEvent};
use crate::subscription::{ReqFilter, Subscription};
use futures::SinkExt;
use futures::StreamExt;
use governor::{Jitter, Quota, RateLimiter};
use http::header::HeaderMap;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::ACCEPT;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{header, upgrade, Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use prometheus::IntCounterVec;
use prometheus::IntGauge;
use prometheus::{Encoder, Histogram, HistogramOpts, IntCounter, Opts, Registry, TextEncoder};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::convert::Infallible;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::mpsc::Receiver as MpscReceiver;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use tokio::runtime::Builder;
use tokio::sync::broadcast::{self, Receiver, Sender};
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, error, info, trace, warn};
use tungstenite::error::CapacityError::MessageTooLong;
use tungstenite::error::Error as WsError;
use tungstenite::handshake;
use tungstenite::protocol::Message;
use tungstenite::protocol::WebSocketConfig;

/// Response body. Hyper 1.x has no concrete `hyper::Body`; body is a trait and
/// implementations live in `http-body-util`. Box it so every handler branch returns
/// one type.
type ResBody = BoxBody<Bytes, hyper::Error>;

/// Complete body from bytes or a string.
fn full<T: Into<Bytes>>(chunk: T) -> ResBody {
    // Full is infallible, so this map_err branch is unreachable.
    Full::new(chunk.into()).map_err(|never| match never {}).boxed()
}

/// Empty body.
fn empty() -> ResBody {
    Empty::<Bytes>::new().map_err(|never| match never {}).boxed()
}

/// Write-buffer limit for ONE connection (tungstenite >=0.20 measures bytes).
/// 4 MiB is about 16 default maximum-size messages (256 KiB). The buffer grows only
/// when socket writes cannot proceed, as with a stalled client; this cap keeps it from
/// consuming relay memory. It replaces max_send_queue = 1024, removed in 0.20.
const MAX_WRITE_BUFFER_BYTES: usize = 4 * 1024 * 1024;

/// How long to wait for a client write before closing the connection.
///
/// A subscribed client that stops reading and closes its TCP window can otherwise hang
/// `send().await` forever. The connection loop then serves neither reads nor pings, and
/// the idle watchdog cannot run because its branch is never polled. Several such clients
/// degrade the entire relay (review R3, 2026-08-28).
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

// Absolute response write lifetime, not an idle timeout or a WS session timeout.
const HTTP_RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

struct HttpResponseWrites {
    timeout: Duration,
    next_id: std::sync::atomic::AtomicU64,
    active: std::sync::Mutex<HashMap<u64, tokio::time::Instant>>,
    changed: tokio::sync::Notify,
}

impl HttpResponseWrites {
    fn new(timeout: Duration) -> Arc<Self> {
        Arc::new(Self { timeout, next_id: std::sync::atomic::AtomicU64::new(0),
            active: std::sync::Mutex::new(HashMap::new()), changed: tokio::sync::Notify::new() })
    }

    async fn response<F>(self: Arc<Self>, response: F) -> Result<Response<ResBody>, Infallible>
    where F: std::future::Future<Output = Result<Response<ResBody>, Infallible>> {
        let response = response.await?;
        // The upgraded transport has its own WS write/idle limits.
        if response.status() == StatusCode::SWITCHING_PROTOCOLS { return Ok(response); }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.active.lock().unwrap().insert(id, tokio::time::Instant::now() + self.timeout);
        self.changed.notify_one();
        let lifetime = Arc::new(HttpResponseWrite { id, writes: self });
        Ok(response.map(|inner| HttpResponseBody { inner, lifetime }.boxed()))
    }

    async fn expired(&self) {
        loop {
            let changed = self.changed.notified();
            let deadline = self.active.lock().unwrap().values().copied().min();
            if let Some(deadline) = deadline {
                if deadline <= tokio::time::Instant::now() { return; }
                tokio::select! {
                    _ = tokio::time::sleep_until(deadline) => {},
                    _ = changed => {},
                }
            } else { changed.await; }
        }
    }

    async fn run<F: std::future::Future>(&self, connection: F) -> Option<F::Output> {
        // Dropping the connection drops Hyper's pending buffers. Never release
        // a history permit separately while those buffers are still retained.
        tokio::select! {
            result = connection => Some(result),
            _ = self.expired() => None,
        }
    }
}

struct HttpResponseWrite { id: u64, writes: Arc<HttpResponseWrites> }

impl Drop for HttpResponseWrite {
    fn drop(&mut self) {
        self.writes.active.lock().unwrap().remove(&self.id);
        self.writes.changed.notify_one();
    }
}

struct HttpResponseChunk { bytes: Bytes, _lifetime: Arc<HttpResponseWrite> }
impl AsRef<[u8]> for HttpResponseChunk {
    fn as_ref(&self) -> &[u8] { &self.bytes }
}

struct HttpResponseBody { inner: ResBody, lifetime: Arc<HttpResponseWrite> }

impl hyper::body::Body for HttpResponseBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>)
        -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, hyper::Error>>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.inner).poll_frame(cx).map(|frame| {
            frame.map(|result| result.map(|frame| frame.map_data(|bytes| {
                Bytes::from_owner(HttpResponseChunk { bytes, _lifetime: this.lifetime.clone() })
            })))
        })
    }

    fn is_end_stream(&self) -> bool { self.inner.is_end_stream() }
    fn size_hint(&self) -> hyper::body::SizeHint { self.inner.size_hint() }
}

/// Send with a timeout. `false` means delivery failed and the connection should close.
async fn send_or_timeout<S>(ws: &mut S, msg: Message) -> bool
where
    S: SinkExt<Message> + Unpin,
{
    matches!(tokio::time::timeout(WRITE_TIMEOUT, ws.send(msg)).await, Ok(Ok(())))
}

/// Handle arbitrary HTTP requests, including for `WebSocket` upgrades.
#[allow(clippy::too_many_arguments)]
/// Bounds how many `/v1/search` requests may hold a database reader thread at
/// once.
///
/// Query threads are already capped by the repo's own reader semaphore
/// (`database.max_conn`, 8 by default), and that cap is shared with the
/// historical-events queries that every WS subscription runs. So a burst of
/// REST searches does not need to exhaust Tokio's blocking pool to hurt: taking
/// all eight reader slots is enough to stall every subscriber on the relay.
/// `/v1/search` is unauthenticated and one HTTP request buys one slot, so it
/// gets a smaller budget of its own and leaves readers for WS.
static V1_SEARCH_SLOTS: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> =
    std::sync::OnceLock::new();

static V1_HISTORY_SLOTS: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> =
    std::sync::OnceLock::new();

// Bytes owns the permit, so a slow response cannot free the slot while its
// buffer is still retained by Hyper. Cancellation of the handler is safe too.
struct HistoryResponseBytes {
    data: Vec<u8>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl AsRef<[u8]> for HistoryResponseBytes {
    fn as_ref(&self) -> &[u8] { &self.data }
}

fn history_body(data: Vec<u8>, permit: tokio::sync::OwnedSemaphorePermit) -> ResBody {
    full(Bytes::from_owner(HistoryResponseBytes { data, _permit: permit }))
}

fn v1_search_slots(settings: &Settings) -> &'static Arc<tokio::sync::Semaphore> {
    V1_SEARCH_SLOTS.get_or_init(|| {
        let half = (settings.database.max_conn as usize) / 2;
        Arc::new(tokio::sync::Semaphore::new(half.max(1)))
    })
}

/// Kinds that carry direct messages and are gated by `authorization.nip42_dms`
/// on the WS path.
const DM_KINDS: [u64; 3] = [4, 44, 1059];

/// Parse `?after=<u64>&limit=<1..5000>` for `/v1/history`. A non-numeric value is a
/// 400 error rather than silently becoming zero: `after=abc` otherwise returned all
/// history from the beginning and hid the client error. Clamp `limit` to 1..5000.
#[derive(Debug)]
struct HistoryQuery {
    after: u64,
    limit: usize,
    after_id: String,
    paged: bool,
}

fn parse_history_query(query: Option<&str>) -> Result<HistoryQuery, String> {
    let (mut after, mut limit) = (0u64, 1000usize);
    let (mut after_id, mut paged) = (String::new(), false);
    let mut seen = std::collections::HashSet::new();
    for pair in query.unwrap_or("").split('&').filter(|p| !p.is_empty()) {
        let name = pair.split('=').next().unwrap_or("");
        if matches!(name, "after" | "limit" | "after_id" | "page") && !seen.insert(name) {
            return Err(format!("duplicate history parameter: {name}"));
        }
        match pair.split_once('=') {
            Some(("after", v)) => {
                after = v.parse().map_err(|_| format!("after: expected an integer, got {v:?}"))?
            }
            Some(("limit", v)) => {
                limit = v.parse().map_err(|_| format!("limit: expected an integer, got {v:?}"))?
            }
            Some(("after_id", v)) => {
                if !v.is_empty() && (v.len() != 64 || !crate::utils::is_lower_hex(v)) {
                    return Err("after_id must be empty or 64 lowercase hex characters".into());
                }
                after_id = v.to_owned();
            }
            Some(("page", "2")) => paged = true,
            Some(("page", _)) => return Err("only history page=2 is supported".into()),
            _ => {}
        }
    }
    if !after_id.is_empty() && !paged {
        return Err("after_id requires page=2".into());
    }
    Ok(HistoryQuery { after, limit: limit.clamp(1, 5000), after_id, paged })
}

#[derive(Serialize)]
struct HistoryRow<'a> { first_seen: u64, event: &'a Event }

#[derive(Serialize)]
struct HistoryCursor<'a> { first_seen: u64, id: &'a str }

#[derive(Serialize)]
struct HistoryPage<'a> {
    version: u8,
    rows: Vec<HistoryRow<'a>>,
    next_cursor: Option<HistoryCursor<'a>>,
}

async fn history_response(
    repo: Arc<dyn NostrRepo>, query: HistoryQuery,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Response<ResBody> {
    let result = async {
        let rows = repo.history_after_id(query.after, &query.after_id, query.limit).await?;
        let entries = rows.iter().map(|(fs, event)| HistoryRow { first_seen: *fs, event }).collect();
        let body = if query.paged {
            serde_json::to_vec(&HistoryPage {
                version: 2, rows: entries,
                next_cursor: rows.last().map(|(fs, e)| HistoryCursor { first_seen: *fs, id: &e.id }),
            })?
        } else {
            serde_json::to_vec(&entries)?
        };
        if body.len() > crate::repo::MAX_HISTORY_PAGE_BYTES {
            return Err(Error::HistoryEventTooLarge);
        }
        Ok(body)
    }.await;
    let (status, data) = match result {
        Ok(data) => (StatusCode::OK, data),
        Err(Error::HistoryEventTooLarge) => (StatusCode::PAYLOAD_TOO_LARGE,
            b"stored history event exceeds the response limit; cursor was not advanced".to_vec()),
        Err(e) => {
            warn!("/v1/history: {e}");
            let status = if matches!(e, Error::CustomError(_)) {
                StatusCode::NOT_IMPLEMENTED
            } else { StatusCode::INTERNAL_SERVER_ERROR };
            (status, b"history unavailable; cursor was not advanced".to_vec())
        }
    };
    Response::builder().status(status)
        .header("Content-Type", if status == StatusCode::OK { "application/json" } else { "text/plain; charset=utf-8" })
        .body(history_body(data, permit)).unwrap()
}

async fn history_request(
    repo: Arc<dyn NostrRepo>, query: Option<&str>, slots: Arc<tokio::sync::Semaphore>,
) -> Response<ResBody> {
    let query = match parse_history_query(query) {
        Ok(query) => query,
        Err(reason) => return Response::builder().status(StatusCode::BAD_REQUEST)
            .header("Content-Type", "text/plain; charset=utf-8").body(full(reason)).unwrap(),
    };
    let Ok(permit) = slots.try_acquire_owned() else {
        return Response::builder().status(StatusCode::TOO_MANY_REQUESTS)
            .header("Retry-After", "1").body(full("history busy; retry this cursor")).unwrap();
    };
    // The task keeps its slot if the HTTP handler is cancelled while SQLite
    // still owns a blocking reader. On success the response Bytes takes over.
    tokio::spawn(history_response(repo, query, permit)).await.unwrap_or_else(|_| {
        Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(full("history unavailable; retry this cursor")).unwrap()
    })
}

#[derive(Debug)]
struct InboxQuery {
    recipient: String,
    after: u64,
    after_id: String,
    limit: usize,
}

fn parse_inbox_query(query: Option<&str>) -> Result<InboxQuery, String> {
    let mut recipient = None;
    let (mut after, mut after_id, mut limit) = (0, String::new(), 250usize);
    let mut paged = false;
    let mut seen = std::collections::HashSet::new();
    for pair in query.unwrap_or("").split('&') {
        let (name, value) = pair.split_once('=').ok_or("inbox parameters require name=value")?;
        if !seen.insert(name) { return Err(format!("duplicate inbox parameter: {name}")); }
        match name {
            "recipient" => {
                if value.len() != 64 || !crate::utils::is_lower_hex(value) {
                    return Err("recipient must be 64 lowercase hex characters".into());
                }
                recipient = Some(value.to_owned());
            }
            "after" | "limit" => {
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(format!("{name} must be an unsigned integer"));
                }
                if name == "after" {
                    after = value.parse().map_err(|_| "after exceeds u64")?;
                } else {
                    limit = value.parse().map_err(|_| "limit exceeds usize")?;
                }
            }
            "after_id" => {
                if !value.is_empty() && (value.len() != 64 || !crate::utils::is_lower_hex(value)) {
                    return Err("after_id must be empty or 64 lowercase hex characters".into());
                }
                after_id = value.to_owned();
            }
            "page" if value == "2" => paged = true,
            "page" => return Err("inbox requires page=2".into()),
            _ => return Err(format!("unknown inbox parameter: {name}")),
        }
    }
    if !paged { return Err("inbox requires page=2".into()); }
    Ok(InboxQuery { recipient: recipient.ok_or("recipient is required")?,
        after, after_id, limit: limit.clamp(1, 5000) })
}

#[derive(Serialize)]
struct InboxPage<'a> {
    version: u8,
    recipient: &'a str,
    rows: Vec<HistoryRow<'a>>,
    next_cursor: Option<HistoryCursor<'a>>,
}

async fn inbox_response(repo: Arc<dyn NostrRepo>, query: InboxQuery,
                        permit: tokio::sync::OwnedSemaphorePermit) -> Response<ResBody> {
    let result = async {
        let rows = repo.inbox_after_id(&query.recipient, query.after, &query.after_id, query.limit).await?;
        let body = serde_json::to_vec(&InboxPage {
            version: 2, recipient: &query.recipient,
            rows: rows.iter().map(|(fs, event)| HistoryRow { first_seen: *fs, event }).collect(),
            next_cursor: rows.last().map(|(fs, event)| HistoryCursor { first_seen: *fs, id: &event.id }),
        })?;
        if body.len() > crate::repo::MAX_HISTORY_PAGE_BYTES { return Err(Error::HistoryEventTooLarge); }
        Ok(body)
    }.await;
    let (status, data) = match result {
        Ok(data) => (StatusCode::OK, data),
        Err(Error::HistoryEventTooLarge) => (StatusCode::PAYLOAD_TOO_LARGE,
            b"stored inbox event exceeds the response limit; cursor was not advanced".to_vec()),
        Err(Error::SqlError(rusqlite::Error::SqliteFailure(error, _)))
            if error.code == rusqlite::ErrorCode::OperationInterrupted =>
                (StatusCode::SERVICE_UNAVAILABLE,
                 b"inbox query exceeded its work budget; cursor was not advanced".to_vec()),
        Err(e) => {
            warn!("/v1/inbox: {e}");
            let status = if matches!(e, Error::CustomError(_)) { StatusCode::NOT_IMPLEMENTED }
                         else { StatusCode::INTERNAL_SERVER_ERROR };
            (status, b"inbox unavailable; cursor was not advanced".to_vec())
        }
    };
    Response::builder().status(status)
        .header("Content-Type", if status == StatusCode::OK { "application/json" } else { "text/plain; charset=utf-8" })
        .header("Cache-Control", "no-store")
        .body(history_body(data, permit)).unwrap()
}

/// Maximum age or future skew allowed for signed proof, in seconds.
///
/// Intentionally narrow. The window is how long an intercepted header can be replayed;
/// one hour would mean an hour of inbox access from one observed line. One minute is
/// enough for reasonable clock skew between machines.
const INBOX_AUTH_WINDOW_SECS: u64 = 60;

/// Signed HTTP-proof event kind (NIP-98).
const KIND_HTTP_AUTH: u64 = 27235;

/// The public key PROVEN by this request. `Err` contains an operator-facing reason.
///
/// Why this exists: `/v1/inbox?recipient=<key>` accepts the key as a PARAMETER, so any
/// caller could name another key and retrieve its envelopes. The content is encrypted,
/// but ciphertext can be harvested now for future decryption, while recipient and timing
/// metadata is immediately visible. Reproduced on a production node with an unrelated
/// key on 2026-09-14.
///
/// This proves exactly one fact: the requester owns the private key for the named public
/// key. The signature uses the standard `Event::validate()` path shared by every event,
/// not a parallel implementation. Divergent signature validators are a classic source
/// of authentication vulnerabilities.
fn proven_reader(
    headers: &hyper::HeaderMap,
    uri: &hyper::Uri,
    relay_url: Option<&str>,
) -> Result<String, &'static str> {
    let raw = headers
        .get(hyper::header::AUTHORIZATION)
        .ok_or("inbox requires a signed Authorization header")?
        .to_str()
        .map_err(|_| "Authorization header is not text")?;
    let encoded = raw
        .strip_prefix("Nostr ")
        .or_else(|| raw.strip_prefix("nostr "))
        .ok_or("Authorization must use the Nostr scheme")?
        .trim();
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
        .map_err(|_| "Authorization payload is not base64")?;
    let event: Event = serde_json::from_slice(&decoded)
        .map_err(|_| "Authorization payload is not an event")?;
    if event.kind != KIND_HTTP_AUTH {
        return Err("Authorization event has the wrong kind");
    }
    event.validate().map_err(|_| "Authorization event signature is invalid")?;

    // Time binding. Without it, a signed header remains valid forever.
    let now = crate::utils::unix_time();
    let skew = now.abs_diff(event.created_at);
    if skew > INBOX_AUTH_WINDOW_SECS {
        return Err("Authorization event is outside the accepted time window");
    }

    // Request binding. Without it, proof signed for one address works for every other
    // address, including endpoints added later.
    let mut expected = url::Url::parse(
        relay_url.ok_or("inbox authentication requires info.relay_url")?,
    )
    .map_err(|_| "info.relay_url is not a URL")?;
    let http_scheme = match expected.scheme() {
        "ws" => "http",
        "wss" => "https",
        _ => return Err("info.relay_url must use ws or wss"),
    };
    expected
        .set_scheme(http_scheme)
        .map_err(|_| "info.relay_url scheme cannot be converted to HTTP")?;
    expected.set_path(uri.path());
    expected.set_query(uri.query());
    expected.set_fragment(None);
    let urls = event.tag_values_by_name("u");
    if urls.len() != 1 {
        return Err("Authorization event must contain exactly one u tag");
    }
    let supplied = url::Url::parse(&urls[0])
        .map_err(|_| "Authorization u tag is not an absolute URL")?;
    if supplied != expected {
        return Err("Authorization event is not bound to this request");
    }
    let methods = event.tag_values_by_name("method");
    if methods.len() != 1 || !methods[0].eq_ignore_ascii_case("GET") {
        return Err("Authorization event is not bound to GET");
    }
    Ok(event.pubkey.clone())
}

async fn inbox_request(repo: Arc<dyn NostrRepo>, query: Option<&str>,
                       slots: Arc<tokio::sync::Semaphore>, nip42_dms: bool,
                       auth: Option<(&hyper::HeaderMap, &hyper::Uri, Option<&str>)>) -> Response<ResBody> {
    let query = match parse_inbox_query(query) {
        Ok(query) => query,
        Err(reason) => return Response::builder().status(StatusCode::BAD_REQUEST)
            .header("Content-Type", "text/plain; charset=utf-8").body(full(reason)).unwrap(),
    };
    // Require key proof when configured. `None` is compatibility mode: the node still
    // returns an inbox from a named key alone, documented as a known vulnerability rather
    // than intended behavior.
    if let Some((headers, uri, relay_url)) = auth {
        match proven_reader(headers, uri, relay_url) {
            Err(reason) => {
                return Response::builder().status(StatusCode::UNAUTHORIZED)
                    .header("Content-Type", "text/plain; charset=utf-8")
                    .body(full(reason)).unwrap();
            }
            Ok(proven) if proven != query.recipient => {
                // A DIFFERENT key was proven. This is not "unauthenticated" but "not your
                // inbox." The distinction matters: the former should retry with a
                // signature, while repeating the latter is pointless.
                return Response::builder().status(StatusCode::FORBIDDEN)
                    .header("Content-Type", "text/plain; charset=utf-8")
                    .body(full("the proven key is not the requested recipient")).unwrap();
            }
            Ok(_) => {}
        }
    }
    // REST has no NIP-42 session. Never turn the recipient selector into auth.
    if nip42_dms {
        return Response::builder().status(StatusCode::FORBIDDEN)
            .body(full("direct messages are not served over REST while nip42_dms is enabled")).unwrap();
    }
    let Ok(permit) = slots.try_acquire_owned() else {
        return Response::builder().status(StatusCode::TOO_MANY_REQUESTS)
            .header("Retry-After", "1").body(full("inbox busy; retry this cursor")).unwrap();
    };
    // Detached work keeps the permit through cancellation, then response Bytes
    // owns it until Hyper releases even the last retained buffer clone.
    tokio::spawn(inbox_response(repo, query, permit)).await.unwrap_or_else(|_| {
        Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(full("inbox unavailable; retry this cursor")).unwrap()
    })
}

/// True if the REST read paths must refuse to serve `kind`.
///
/// `nip42_dms` promises the operator that DM kinds go only to the sender or the
/// recipient, and the WS path keeps that promise by checking the connection's
/// NIP-42 identity. REST has no session at all -- it publishes with
/// `auth_pubkey: None` -- so on the WS path an equivalent client would be
/// refused every one of these events. Serving them over `/v1/*` therefore did
/// not merely bypass a limit, it inverted the setting: turning `nip42_dms` on
/// left DMs readable by anyone over HTTP. Refuse instead.
fn rest_kind_is_withheld(kind: u64, settings: &Settings) -> bool {
    settings.authorization.nip42_dms && DM_KINDS.contains(&kind)
}

/// Client IP for a REST request, honouring `network.remote_ip_header` exactly as
/// the WS path does. Behind a reverse proxy the socket address is the proxy's,
/// so without this every REST publish looked like it came from one client.
fn rest_source_ip(
    settings: &Settings,
    headers: &header::HeaderMap,
    remote_addr: SocketAddr,
) -> String {
    settings
        .network
        .remote_ip_header
        .as_ref()
        .and_then(|h| get_header_string(h, headers))
        .unwrap_or_else(|| remote_addr.ip().to_string())
}

// Hyper's service boundary supplies request-local state plus the relay's shared channels,
// metrics, and immutable settings. Keeping them explicit makes test fixtures and ownership
// visible; a bag-of-state parameter would conceal rather than reduce the dependencies.
#[allow(clippy::too_many_arguments)]
async fn handle_web_request(
    mut request: Request<Incoming>,
    repo: Arc<dyn NostrRepo>,
    settings: Settings,
    remote_addr: SocketAddr,
    broadcast: Sender<Event>,
    event_tx: tokio::sync::mpsc::Sender<SubmittedEvent>,
    shutdown: Receiver<()>,
    favicon: Option<Vec<u8>>,
    registry: Registry,
    metrics: NostrMetrics,
) -> Result<Response<ResBody>, Infallible> {
    match (
        request.uri().path(),
        request.headers().contains_key(header::UPGRADE),
    ) {
        // Request for / as websocket
        ("/", true) => {
            trace!("websocket with upgrade request");
            //assume request is a handshake, so create the handshake response
            let response = match handshake::server::create_response_with_body(&request, || {
                empty()
            }) {
                Ok(response) => {
                    //in case the handshake response creation succeeds,
                    //spawn a task to handle the websocket connection
                    tokio::spawn(async move {
                        //using the hyper feature of upgrading a connection
                        match upgrade::on(&mut request).await {
                            //if successfully upgraded
                            Ok(upgraded) => {
                                // set WebSocket configuration options
                                // Tungstenite 0.20 removed the old max_send_queue = 1024,
                                // and its replacement max_write_buffer_size defaults to
                                // unlimited. Set an explicit defensive ceiling.
                                // WARNING: this does NOT protect against a stalled reader.
                                // Sending waits for a flush, so at most one message remains
                                // buffered and the ceiling is unreachable. WRITE_TIMEOUT
                                // below handles clients that stop reading (review R3,
                                // 2026-08-28; the old comment promised protection that did
                                // not exist). Since 0.26 this non_exhaustive struct is built
                                // through methods.
                                let config = WebSocketConfig::default()
                                    .max_write_buffer_size(MAX_WRITE_BUFFER_BYTES)
                                    .max_message_size(settings.limits.max_ws_message_bytes)
                                    .max_frame_size(settings.limits.max_ws_frame_bytes);
                                //create a websocket stream from the upgraded object
                                let ws_stream = WebSocketStream::from_raw_socket(
                                    // Hyper 1.x returns Upgraded, which does NOT implement
                                    // tokio::io::AsyncRead/AsyncWrite. TokioIo bridges
                                    // hyper-io and tokio-io.
                                    TokioIo::new(upgraded),
                                    tokio_tungstenite::tungstenite::protocol::Role::Server,
                                    Some(config),
                                )
                                .await;
                                let origin = get_header_string("origin", request.headers());
                                let user_agent = get_header_string("user-agent", request.headers());
                                // determine the remote IP from headers if the exist
                                let header_ip = settings
                                    .network
                                    .remote_ip_header
                                    .as_ref()
                                    .and_then(|x| get_header_string(x, request.headers()));
                                // use the socket addr as a backup
                                let remote_ip =
                                    header_ip.unwrap_or_else(|| remote_addr.ip().to_string());
                                let client_info = ClientInfo {
                                    remote_ip,
                                    user_agent,
                                    origin,
                                };
                                // spawn a nostr server with our websocket
                                tokio::spawn(nostr_server(
                                    repo,
                                    client_info,
                                    settings,
                                    ws_stream,
                                    broadcast,
                                    event_tx,
                                    shutdown,
                                    metrics,
                                ));
                            }
                            // Upstream behavior: handshake upgrade failures go to
                            // stdout rather than the structured tracing pipeline.
                            Err(e) => println!(
                                "error when trying to upgrade connection \
                                 from address {remote_addr} to websocket connection. \
                                 Error is: {e}",
                            ),
                        }
                    });
                    //return the response to the handshake request
                    response
                }
                Err(error) => {
                    warn!("websocket response failed");
                    let mut res =
                        Response::new(full(format!("Failed to create websocket: {error}")));
                    *res.status_mut() = StatusCode::BAD_REQUEST;
                    return Ok(res);
                }
            };
            Ok::<_, Infallible>(response)
        }
        // Request for Relay info
        ("/", false) => {
            // handle request at root with no upgrade header
            // Check if this is a nostr server info request
            let accept_header = &request.headers().get(ACCEPT);
            // check if application/nostr+json is included
            if let Some(media_types) = accept_header {
                if let Ok(mt_str) = media_types.to_str() {
                    if mt_str.contains("application/nostr+json") {
                        // build a relay info response
                        debug!("Responding to server info request");
                        let rinfo = RelayInfo::from(settings);
                        let b = full(serde_json::to_string_pretty(&rinfo).unwrap());
                        return Ok(Response::builder()
                            .status(200)
                            .header("Content-Type", "application/nostr+json")
                            .header("Access-Control-Allow-Origin", "*")
                            .body(b)
                            .unwrap());
                    }
                }
            }


            if let Some(relay_file_path) = settings.info.relay_page {
                match file_bytes(&relay_file_path) {
                    Ok(file_content) => {
                        return Ok(Response::builder()
                            .status(200)
                            .header("Content-Type", "text/html; charset=UTF-8")
                            .body(full(file_content))
                            .expect("request builder"));
                    }
                    Err(err) => {
                        error!("Failed to read relay_page file: {}. Will use default", err);
                    }
                }
            }

            Ok(Response::builder()
                .status(200)
                .header("Content-Type", "text/plain")
                .body(full("A4A Relay — connect with an A4A agent or SDK (https://a4a.network)"))
                .unwrap())
        }
        ("/metrics", false) => {
            let mut buffer = vec![];
            let encoder = TextEncoder::new();
            let metric_families = registry.gather();
            encoder.encode(&metric_families, &mut buffer).unwrap();

            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain")
                .body(full(buffer))
                .unwrap())
        }
        ("/favicon.ico", false) => {
            if let Some(favicon_bytes) = favicon {
                info!("returning favicon");
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "image/x-icon")
                    // 1 month cache
                    .header("Cache-Control", "public, max-age=2419200")
                    .body(full(favicon_bytes))
                    .unwrap())
            } else {
                Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(full(""))
                    .unwrap())
            }
        }
        // LN bits callback endpoint for paid invoices
        // Node health. This endpoint had two defects, both measured on 2026-09-14:
        //
        // 1. It returned `200 ok` UNCONDITIONALLY, even when the node did not understand
        //    its own schema and should not serve traffic. Deployment checks saw "ok."
        // 2. It returned the UPSTREAM crate version (0.10.0), identical across our builds.
        //    The endpoint could not identify the running build; only NIP-11 could.
        //
        // Now unready nodes return 503 with a REASON, giving machines a status code and
        // humans an explanation, while both fork and upstream versions are reported.
        ("/v1/health", false) if settings.a4a.rest_enabled => {
            let (code, status) = match crate::db::not_ready_reason() {
                None => (StatusCode::OK, "ok"),
                Some(_) => (StatusCode::SERVICE_UNAVAILABLE, "not_ready"),
            };
            let mut body = json!({
                "status": status,
                "version": crate::info::CARGO_PKG_VERSION.unwrap_or("unknown"),
                "a4a_version": crate::info::A4A_RELAY_VERSION,
                "schema_version": crate::repo::sqlite_migration::DB_VERSION,
            });
            if let Some(reason) = crate::db::not_ready_reason() {
                body["reason"] = json!(reason);
            }
            Ok(Response::builder()
                .status(code)
                .header("Content-Type", "application/json")
                .body(full(body.to_string()))
                .unwrap())
        }
        // A4A REST: fetch a single event by id. Dynamic segment, so matched via
        // a path-prefix guard rather than a static literal (see blueprint §3).
        // Gated by settings.a4a.rest_enabled; malformed/unknown id -> 404.
        (path, false) if settings.a4a.rest_enabled && path.starts_with("/v1/event/") => {
            let id = path.strip_prefix("/v1/event/").unwrap_or("");
            // Missing and unreadable are different. Both used to be 404, so a
            // database failure was indistinguishable from "no such event".
            match classify_repo_read(repo.get_event_by_id(id).await) {
                RepoRead::Found(event) if rest_kind_is_withheld(event.kind, &settings) => {
                    Ok(not_found())
                }
                RepoRead::Found(event) => Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json")
                    .body(full(serde_json::to_string(&event).unwrap()))
                    .unwrap()),
                RepoRead::Missing => Ok(not_found()),
                RepoRead::Failed => Ok(unavailable("could not read the event")),
            }
        }
        // A4A REST: node history ordered by INTAKE time for the time notary (§2.9).
        // `REQ` filters only by `created_at`, so an event backdated by two days was never
        // timestamped (finding 86). `after` is inclusive and `limit` is 1..5000. An
        // engine without intake history returns 501 rather than an empty list.
        (path, false) if settings.a4a.rest_enabled && path == "/v1/history" => {
            let slots = V1_HISTORY_SLOTS.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(1)));
            Ok(history_request(repo, request.uri().query(), slots.clone()).await)
        }
        ("/v1/inbox", false) if settings.a4a.rest_enabled => {
            let slots = V1_HISTORY_SLOTS.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(1)));
            let auth = settings.a4a.inbox_auth.then(|| {
                (request.headers(), request.uri(), settings.info.relay_url.as_deref())
            });
            Ok(inbox_request(repo, request.uri().query(), slots.clone(),
                settings.authorization.nip42_dms, auth).await)
        }
        // A4A REST: delegation by id, LIVE or REPLACED (archive, F4). Kind 31000 only.
        // Standard REQ omits an expired live delegation under NIP-40, while replacement
        // deletes a reissued copy. This endpoint retrieves the copy referenced by an old
        // agent event so a reader can combine it with a timestamp (§2.9) and answer
        // "was the agent authorized then?" Other kinds return 404; this is not a second
        // `/v1/event`.
        (path, false) if settings.a4a.rest_enabled && path.starts_with("/v1/delegation-history/") => {
            let id = path.strip_prefix("/v1/delegation-history/").unwrap_or("");
            // A failed live read must not fall through to the archive. The
            // archive can hold an older mandate; returning it with 200 tells
            // the caller that copy is the current authorization.
            match classify_repo_read(repo.get_event_by_id(id).await) {
                RepoRead::Failed => Ok(unavailable("could not read the live delegation")),
                RepoRead::Found(ev)
                    if ev.kind == crate::a4a_delegation::A4A_KIND_DELEGATION =>
                {
                    Ok(json_event(ev))
                }
                RepoRead::Found(_) => Ok(not_found()),
                RepoRead::Missing => match classify_repo_read(repo.get_archived_delegation(id).await)
                {
                    RepoRead::Found(event) => Ok(json_event(event)),
                    RepoRead::Missing => Ok(not_found()),
                    RepoRead::Failed => Ok(unavailable("could not read the delegation archive")),
                },
            }
        }
        // A4A REST: publish an event over HTTP, reusing the SAME admission
        // pipeline as the WS EVENT path (event.rs::From<EventCmd> for
        // validate()+build_index()+update_delegation(), then event_tx ->
        // db_writer() for kind blacklist/allowlist, nauthz, A4A delegation
        // check, and persistence). This is deliberately NOT a second write
        // path: the body is wrapped as an EventCmd and sent through the
        // exact same `event_tx` channel the WS handler uses, so REST events
        // inherit every admission check (see blueprint §3).
        ("/v1/publish", false) if settings.a4a.rest_enabled => {
            // Write endpoint: require POST so a GET from a prefetcher/proxy
            // can't be mistaken for a publish attempt.
            if request.method() != Method::POST {
                return Ok(method_not_allowed());
            }
            let origin = get_header_string("origin", request.headers());
            let user_agent = get_header_string("user-agent", request.headers());
            // read_body_capped consumes request, so capture the headers first.
            let headers_for_ip = request.headers().clone();
            let cap = rest_body_cap(&settings);
            let body = match read_body_capped(request, cap).await {
                Ok(b) => b,
                Err(resp) => return Ok(*resp),
            };
            let raw_event: serde_json::Value = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(e) => return Ok(bad_request(&format!("invalid JSON: {e}"))),
            };
            // Wrap as {"cmd":"EVENT","event":<body>} to go through the exact
            // same EventCmd -> Result<EventWrapper> conversion the WS path
            // uses, instead of duplicating validate()/build_index()/
            // update_delegation() here.
            let ec: EventCmd = match serde_json::from_value(json!({"cmd": "EVENT", "event": raw_event})) {
                Ok(ec) => ec,
                Err(e) => return Ok(bad_request(&format!("invalid event: {e}"))),
            };
            let evid = ec.event_id().to_owned();
            let e = match Result::<EventWrapper>::from(ec) {
                Ok(WrappedEvent(e)) => e,
                Ok(WrappedAuth(_)) => {
                    return Ok(bad_request("AUTH events cannot be published via /v1/publish"))
                }
                Err(err) => {
                    return Ok(publish_response(
                        StatusCode::BAD_REQUEST,
                        &evid,
                        false,
                        &format!("{err}"),
                    ))
                }
            };
            // NOT_READY is set when startup storage failed. Health already
            // reports it. Publish used to accept events anyway.
            if let Some(reason) = crate::db::not_ready_reason() {
                return Ok(publish_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &e.id,
                    false,
                    reason,
                ));
            }
            if crate::utils::unix_time_from(std::time::SystemTime::now()).is_none() {
                return Ok(publish_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &e.id,
                    false,
                    "relay clock is unusable, cannot judge expiration",
                ));
            }
            if e.has_malformed_expiration() {
                return Ok(publish_response(
                    StatusCode::BAD_REQUEST,
                    &e.id,
                    false,
                    "expiration must be a canonical unix timestamp (digits only, no sign,                      no leading zero)",
                ));
            }
            if e.is_expired() {
                return Ok(publish_response(
                    StatusCode::BAD_REQUEST,
                    &e.id,
                    false,
                    "The event has already expired",
                ));
            }
            if !e.is_valid_timestamp(settings.options.reject_future_seconds) {
                return Ok(publish_response(
                    StatusCode::BAD_REQUEST,
                    &e.id,
                    false,
                    "The event created_at field is out of the acceptable range for this relay",
                ));
            }
            // One-shot reply channel: db_writer() replies with a single
            // Notice, exactly the same shape as the WS notice_tx channel,
            // just scoped to this one request instead of a whole connection.
            let (notice_tx, mut notice_rx) = tokio::sync::mpsc::channel::<Notice>(1);
            let evid_for_timeout = e.id.clone();
            let submit_event = SubmittedEvent {
                event: e,
                notice_tx,
                // As on the WebSocket path, behind a reverse proxy the socket address
                // belongs to the proxy. Without this, ALL REST publications appear to
                // originate from one IP, affecting both logs and nauthz decisions.
                source_ip: rest_source_ip(&settings, &headers_for_ip, remote_addr),
                origin,
                user_agent,
                // REST has no WS/NIP-42 session to authenticate; see blueprint §6 risk 5.
                auth_pubkey: None,
                // One HTTP request, not a connection to close. If the notice
                // cannot be queued, the handler's own timeout is the answer.
                close_tx: None,
            };
            // Bounded: the 5 s timeout below covers waiting for the WRITER'S
            // ANSWER, not getting into its queue. With the persist buffer full
            // this send parked the handler indefinitely -- and a parked handler
            // also blocks graceful shutdown.
            match tokio::time::timeout(Duration::from_secs(5), event_tx.send(submit_event)).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    return Ok(publish_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &evid_for_timeout,
                        false,
                        "internal error: could not queue event for writing",
                    ))
                }
                Err(_) => {
                    return Ok(publish_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &evid_for_timeout,
                        false,
                        "relay write queue is full, retry later",
                    ))
                }
            }
            match tokio::time::timeout(Duration::from_secs(5), notice_rx.recv()).await {
                Ok(Some(notice)) => Ok(notice_to_publish_response(notice)),
                Ok(None) => Ok(publish_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &evid_for_timeout,
                    false,
                    "db writer closed without a response",
                )),
                Err(_) => Ok(publish_response(
                    StatusCode::GATEWAY_TIMEOUT,
                    &evid_for_timeout,
                    false,
                    "timed out waiting for the database writer",
                )),
            }
        }
        // A4A REST: read-only search over A4A tags, e.g.
        // {"kinds":[31002],"#category":["development"]}. Accepts the same
        // shape as a NIP-01 REQ filter and runs it through the existing
        // ReqFilter/query_subscription machinery (F2 widened ReqFilter.tags
        // to HashMap<String, TagOperand> so multi-char A4A tags match).
        // Read-only: no admission, no event_tx involved.
        ("/v1/search", false) if settings.a4a.rest_enabled => {
            // Query endpoint takes a filter body via POST; require POST for
            // the same reason as /v1/publish (see above).
            if request.method() != Method::POST {
                return Ok(method_not_allowed());
            }
            // Hold a slot for the whole request, released on every exit path
            // (including the timeout) when this guard drops.
            let Ok(_slot) = v1_search_slots(&settings).clone().try_acquire_owned() else {
                return Ok(Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .header("Content-Type", "application/json")
                    .body(full(
                        json!({"error": "too many concurrent searches, retry later"}).to_string(),
                    ))
                    .unwrap());
            };
            const MAX_SEARCH_LIMIT: u64 = 500;
            let cap = rest_body_cap(&settings);
            let body = match read_body_capped(request, cap).await {
                Ok(b) => b,
                Err(resp) => return Ok(*resp),
            };
            let mut filter: ReqFilter = match serde_json::from_slice(&body) {
                Ok(f) => f,
                Err(e) => return Ok(bad_request(&format!("invalid filter: {e}"))),
            };
            filter.limit = Some(filter.limit.map_or(MAX_SEARCH_LIMIT, |l| l.min(MAX_SEARCH_LIMIT)));
            // No session here, so a filter that could reach a DM kind is refused
            // outright rather than served to an anonymous caller.
            if settings.authorization.nip42_dms
                && filter
                    .kinds
                    .as_ref()
                    .is_none_or(|ks| ks.iter().any(|k| DM_KINDS.contains(k)))
            {
                return Ok(Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header("Content-Type", "application/json")
                    .body(full(
                        json!({"error": "direct messages are not served over REST while nip42_dms is enabled"})
                            .to_string(),
                    ))
                    .unwrap());
            }
            let sub = Subscription {
                id: "v1-search".to_string(),
                filters: vec![filter],
            };
            // Mirror the WS REQ path: when the operator has turned scraper
            // protection on, a filter too broad to be a real query gets an empty
            // result there, and must get one here too -- otherwise `/v1/search`
            // is simply the documented way around the setting.
            if settings.limits.limit_scrapers && sub.is_scraper() {
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json")
                    .body(full("[]".to_owned()))
                    .unwrap());
            }
            let (query_tx, mut query_rx) = mpsc::channel::<db::QueryResult>(1000);
            let (abandon_tx, abandon_rx) = oneshot::channel::<()>();
            if let Err(e) = repo
                .query_subscription(sub, "v1-search".to_string(), query_tx, abandon_rx)
                .await
            {
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header("Content-Type", "application/json")
                    .body(full(
                        json!({"error": format!("query error: {e}")}).to_string(),
                    ))
                    .unwrap());
            }
            // Drain the channel to EOSE, same pattern as the WS REQ path
            // (server.rs query_rx.recv() loop), but collecting instead of
            // streaming to a socket. Bounded by a timeout so a stalled/slow
            // query can't hang the HTTP response forever.
            let mut events: Vec<String> = Vec::new();
            let mut query_failure: Option<String> = None;
            let drain = async {
                while let Some(qr) = query_rx.recv().await {
                    if qr.event == "EOSE" {
                        break;
                    }
                    if let Some(reason) = qr.event.strip_prefix("CLOSED ") {
                        query_failure = Some(reason.to_owned());
                        break;
                    }
                    events.push(qr.event);
                }
            };
            if tokio::time::timeout(Duration::from_secs(10), drain)
                .await
                .is_err()
            {
                warn!("/v1/search timed out draining query results, returning partial results");
            }
            if let Some(reason) = query_failure {
                drop(abandon_tx);
                return Ok(unavailable(&reason));
            }
            // Cancel explicitly rather than letting the sender fall out of scope
            // with the response: on timeout the blocking thread is still scanning,
            // and every row it reads past this point is work for a reader that has
            // already been answered.
            drop(abandon_tx);
            let body = format!("[{}]", events.join(","));
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(full(body))
                .unwrap())
        }
        // later balance
        (_, _) => {
            // handle any other url
            Ok(not_found())
        }
    }
}

/// Standard 404 response, shared by the catch-all route and any A4A REST
/// endpoint that needs to report "not found" (e.g. `/v1/event/:id`).
fn not_found() -> Response<ResBody> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(full("Nothing here."))
        .unwrap()
}

fn unavailable(msg: &str) -> Response<ResBody> {
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header("Content-Type", "application/json")
        .body(full(json!({"error": msg}).to_string()))
        .unwrap()
}

fn json_event(event: crate::event::Event) -> Response<ResBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(full(serde_json::to_string(&event).unwrap()))
        .unwrap()
}

/// One database read, three outcomes. `Failed` must not be folded into `Missing`:
/// callers that do so answer "not found" or "here is the archive" when the
/// question was not answered.
enum RepoRead<T> {
    Found(T),
    Missing,
    Failed,
}

fn classify_repo_read<T, E>(result: Result<Option<T>, E>) -> RepoRead<T> {
    match result {
        Ok(Some(value)) => RepoRead::Found(value),
        Ok(None) => RepoRead::Missing,
        Err(_) => RepoRead::Failed,
    }
}

/// A generic 400 for REST input that failed to parse, before it ever reaches
/// the admission pipeline.
fn bad_request(msg: &str) -> Response<ResBody> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header("Content-Type", "application/json")
        .body(full(json!({"accepted": false, "message": msg}).to_string()))
        .unwrap()
}

/// 413 for REST bodies that exceed the size cap enforced by
/// `read_body_capped()`, whether caught via `Content-Length` up front or
/// during the bounded read itself.
fn payload_too_large() -> Response<ResBody> {
    Response::builder()
        .status(StatusCode::PAYLOAD_TOO_LARGE)
        .header("Content-Type", "application/json")
        .body(full(
            json!({"accepted": false, "message": "request body too large"}).to_string(),
        ))
        .unwrap()
}

/// 405 for the REST write/query endpoints (`/v1/publish`, `/v1/search`) hit
/// with a verb other than POST, e.g. a GET from a prefetcher or proxy that
/// shouldn't be able to trigger a publish/search as a side effect.
fn method_not_allowed() -> Response<ResBody> {
    Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .header("Allow", "POST")
        .header("Content-Type", "application/json")
        .body(full(
            json!({"accepted": false, "message": "method not allowed, use POST"}).to_string(),
        ))
        .unwrap()
}

/// Cap (bytes) for REST request bodies: mirrors the WS path's use of
/// `settings.limits.max_event_bytes` to bound per-request memory use. Falls
/// back to a sane default when unset or configured as `0`.
const DEFAULT_REST_BODY_CAP: usize = 512 * 1024;

fn rest_body_cap(settings: &Settings) -> usize {
    settings
        .limits
        .max_event_bytes
        .filter(|&c| c > 0)
        .unwrap_or(DEFAULT_REST_BODY_CAP)
}

/// Read a REST request body while enforcing `cap` bytes as a hard ceiling on
/// memory use.
///
/// First checks `Content-Length`, if present, and rejects immediately
/// without reading anything if it exceeds `cap`. That alone isn't
/// sufficient: `Content-Length` can be absent (chunked transfer-encoding) or
/// simply lie, so the actual read is ALSO bounded by accumulating the body
/// chunk-by-chunk and aborting as soon as the running total would exceed
/// `cap` -- the oversized remainder is never buffered.
/// How long a REST body may take to arrive in full.
///
/// The size cap alone does not bound TIME: a client sending one chunked byte a
/// minute keeps `body.frame().await` pending forever, and every such request is
/// a live handler. Worse, `graceful.shutdown()` waits for exactly these
/// connections, so one slow body was enough to keep the relay from ever
/// stopping.
const REST_BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the relay waits for live connections during a graceful stop before
/// giving up on them. Without a ceiling a single stalled request meant the
/// process never returned from `block_on` and had to be killed.
const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a connection may take to send its request headers. `hyper_util`'s
/// auto builder has no default here, so a connection could sit open sending
/// nothing at all.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

async fn read_body_capped(
    request: Request<Incoming>,
    cap: usize,
) -> std::result::Result<Vec<u8>, Box<Response<ResBody>>> {
    match tokio::time::timeout(REST_BODY_READ_TIMEOUT, read_body_capped_inner(request, cap)).await {
        Ok(r) => r,
        Err(_) => Err(Box::new(
            Response::builder()
                .status(StatusCode::REQUEST_TIMEOUT)
                .header("Content-Type", "application/json")
                .body(full(
                    json!({"error": "timed out reading request body"}).to_string(),
                ))
                .unwrap(),
        )),
    }
}

async fn read_body_capped_inner(
    request: Request<Incoming>,
    cap: usize,
) -> std::result::Result<Vec<u8>, Box<Response<ResBody>>> {
    // Allocate only on rejection; successful reads do not carry a full HTTP response.
    if let Some(len) = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
    {
        if len > cap as u64 {
            return Err(Box::new(payload_too_large()));
        }
    }
    let mut body = request.into_body();
    let mut buf: Vec<u8> = Vec::new();
    // http-body 1.0 uses frame() rather than data() because a frame may carry trailers
    // instead of data. Preserve the behavior: count incrementally and stop before
    // buffering excess input.
    while let Some(frame) = body.frame().await {
        let frame =
            frame.map_err(|e| Box::new(bad_request(&format!("could not read request body: {e}"))))?;
        let Ok(chunk) = frame.into_data() else {
            continue;   // Trailers are not body data.
        };
        if buf.len() + chunk.len() > cap {
            return Err(Box::new(payload_too_large()));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Build the JSON body/status for `/v1/publish` from parts, used for
/// rejections that happen before (or instead of) a `db_writer()` round trip.
fn publish_response(status: StatusCode, id: &str, accepted: bool, msg: &str) -> Response<ResBody> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(full(
            json!({"id": id, "accepted": accepted, "message": msg}).to_string(),
        ))
        .unwrap()
}

/// Map the `Notice` that `db_writer()` sends back on the one-shot channel to
/// an HTTP response for `/v1/publish`. This is the same `Notice` the WS path
/// turns into an `["OK", id, bool, msg]` message (see `make_notice_message`);
/// here it becomes an HTTP status + JSON body instead.
fn notice_to_publish_response(notice: Notice) -> Response<ResBody> {
    match notice {
        Notice::EventResult(res) => {
            let (status, accepted) = match res.status {
                EventResultStatus::Saved | EventResultStatus::Duplicate => (StatusCode::OK, true),
                EventResultStatus::Invalid => (StatusCode::BAD_REQUEST, false),
                EventResultStatus::Blocked | EventResultStatus::Restricted => {
                    (StatusCode::FORBIDDEN, false)
                }
                EventResultStatus::RateLimited => (StatusCode::TOO_MANY_REQUESTS, false),
                EventResultStatus::Error => (StatusCode::INTERNAL_SERVER_ERROR, false),
            };
            publish_response(status, &res.id, accepted, &res.msg)
        }
        Notice::Message(msg) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header("Content-Type", "application/json")
            .body(full(
                json!({"accepted": false, "message": msg}).to_string(),
            ))
            .unwrap(),
        Notice::AuthChallenge(_) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header("Content-Type", "application/json")
            .body(full(
                json!({"accepted": false, "message": "unexpected response from db writer"})
                    .to_string(),
            ))
            .unwrap(),
    }
}

// Get pubkey from request query string

fn get_header_string(header: &str, headers: &HeaderMap) -> Option<String> {
    headers
        .get(header)
        .and_then(|x| x.to_str().ok().map(std::string::ToString::to_string))
}

// return on a control-c or internally requested shutdown signal
async fn ctrl_c_or_signal(mut shutdown_signal: Receiver<()>) {
    let mut term_signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("could not define signal");
    #[allow(clippy::never_loop)]
    loop {
        tokio::select! {
            _ = shutdown_signal.recv() => {
                info!("Shutting down webserver as requested");
                // server shutting down, exit loop
                break;
            },
            _ = tokio::signal::ctrl_c() => {
                info!("Shutting down webserver due to SIGINT");
                break;
            },
            _ = term_signal.recv() => {
                info!("Shutting down webserver due to SIGTERM");
                break;
            },
        }
    }
}

fn create_metrics() -> (Registry, NostrMetrics) {
    // setup prometheus registry
    let registry = Registry::new();

    let query_sub = Histogram::with_opts(HistogramOpts::new(
        "nostr_query_seconds",
        "Subscription response times",
    ))
    .unwrap();
    let query_db = Histogram::with_opts(HistogramOpts::new(
        "nostr_filter_seconds",
        "Filter SQL query times",
    ))
    .unwrap();
    let write_events = Histogram::with_opts(HistogramOpts::new(
        "nostr_events_write_seconds",
        "Event writing response times",
    ))
    .unwrap();
    let sent_events = IntCounterVec::new(
        Opts::new("nostr_events_sent_total", "Events sent to clients"),
        vec!["source"].as_slice(),
    )
    .unwrap();
    let connections =
        IntCounter::with_opts(Opts::new("nostr_connections_total", "New connections")).unwrap();
    let db_connections = IntGauge::with_opts(Opts::new(
        "nostr_db_connections",
        "Active database connections",
    ))
    .unwrap();
    let connections_active = IntGauge::with_opts(Opts::new(
        "nostr_connections_active",
        "Currently open websocket connections",
    ))
    .unwrap();
    let query_aborts = IntCounterVec::new(
        Opts::new("nostr_query_abort_total", "Aborted queries"),
        vec!["reason"].as_slice(),
    )
    .unwrap();
    let cmd_req = IntCounter::with_opts(Opts::new("nostr_cmd_req_total", "REQ commands")).unwrap();
    let cmd_event =
        IntCounter::with_opts(Opts::new("nostr_cmd_event_total", "EVENT commands")).unwrap();
    let cmd_close =
        IntCounter::with_opts(Opts::new("nostr_cmd_close_total", "CLOSE commands")).unwrap();
    let cmd_auth =
        IntCounter::with_opts(Opts::new("nostr_cmd_auth_total", "AUTH commands")).unwrap();
    let disconnects = IntCounterVec::new(
        Opts::new("nostr_disconnects_total", "Client disconnects"),
        vec!["reason"].as_slice(),
    )
    .unwrap();
    registry.register(Box::new(connections_active.clone())).unwrap();
    registry.register(Box::new(query_sub.clone())).unwrap();
    registry.register(Box::new(query_db.clone())).unwrap();
    registry.register(Box::new(write_events.clone())).unwrap();
    registry.register(Box::new(sent_events.clone())).unwrap();
    registry.register(Box::new(connections.clone())).unwrap();
    registry.register(Box::new(db_connections.clone())).unwrap();
    registry.register(Box::new(query_aborts.clone())).unwrap();
    registry.register(Box::new(cmd_req.clone())).unwrap();
    registry.register(Box::new(cmd_event.clone())).unwrap();
    registry.register(Box::new(cmd_close.clone())).unwrap();
    registry.register(Box::new(cmd_auth.clone())).unwrap();
    registry.register(Box::new(disconnects.clone())).unwrap();
    let metrics = NostrMetrics {
        query_sub,
        query_db,
        write_events,
        sent_events,
        connections,
        connections_active,
        db_connections,
        disconnects,
        query_aborts,
        cmd_req,
        cmd_event,
        cmd_close,
        cmd_auth,
    };
    (registry, metrics)
}

fn file_bytes(path: &str) -> Result<Vec<u8>> {
    let f = File::open(path)?;
    let mut reader = BufReader::new(f);
    let mut buffer = Vec::new();
    // Read file into vector.
    reader.read_to_end(&mut buffer)?;
    Ok(buffer)
}

/// Start running a Nostr relay server.
pub fn start_server(settings: &Settings, shutdown_rx: MpscReceiver<()>) -> Result<(), Error> {
    trace!("Config: {:?}", settings);
    // do some config validation.
    if !Path::new(&settings.database.data_directory).is_dir() {
        error!("Database directory does not exist");
        return Err(Error::DatabaseDirError);
    }
    let addr = format!(
        "{}:{}",
        settings.network.address.trim(),
        settings.network.port
    );
    let socket_addr: SocketAddr = addr.parse().expect("listening address not valid");
    // address whitelisting settings
    if let Some(addr_whitelist) = &settings.authorization.pubkey_whitelist {
        info!(
            "Event publishing restricted to {} pubkey(s)",
            addr_whitelist.len()
        );
    }
    // check if NIP-05 enforced user verification is on
    if settings.verified_users.is_active() {
        info!(
            "NIP-05 user verification mode:{:?}",
            settings.verified_users.mode
        );
        if let Some(d) = settings.verified_users.verify_update_duration() {
            info!("NIP-05 check user verification every:   {:?}", d);
        }
        if let Some(d) = settings.verified_users.verify_expiration_duration() {
            info!("NIP-05 user verification expires after: {:?}", d);
        }
        if let Some(wl) = &settings.verified_users.domain_whitelist {
            info!("NIP-05 domain whitelist: {:?}", wl);
        }
        if let Some(bl) = &settings.verified_users.domain_blacklist {
            info!("NIP-05 domain blacklist: {:?}", bl);
        }
    }
    // configure tokio runtime
    let rt = Builder::new_multi_thread()
        .enable_all()
        .thread_name_fn(|| {
            // give each thread a unique numeric name
            static ATOMIC_ID: std::sync::atomic::AtomicUsize =
                std::sync::atomic::AtomicUsize::new(0);
            let id = ATOMIC_ID.fetch_add(1, Ordering::SeqCst);
            format!("tokio-ws-{id}")
        })
        // limit concurrent SQLite blocking threads
        .max_blocking_threads(settings.limits.max_blocking_threads)
        .on_thread_start(|| {
            trace!("started new thread: {:?}", std::thread::current().name());
        })
        .on_thread_stop(|| {
            trace!("stopped thread: {:?}", std::thread::current().name());
        })
        .build()
        .unwrap();
    // start tokio
    rt.block_on(async {
        let broadcast_buffer_limit = settings.limits.broadcast_buffer;
        let persist_buffer_limit = settings.limits.event_persist_buffer;
        let verified_users_active = settings.verified_users.is_active();
        let settings = settings.clone();
        info!("listening on: {}", socket_addr);
        // all client-submitted valid events are broadcast to every
        // other client on this channel.  This should be large enough
        // to accommodate slower readers (messages are dropped if
        // clients can not keep up).
        let (bcast_tx, _) = broadcast::channel::<Event>(broadcast_buffer_limit);
        // validated events that need to be persisted are sent to the
        // database on via this channel.
        let (event_tx, event_rx) = mpsc::channel::<SubmittedEvent>(persist_buffer_limit);
        // establish a channel for letting all threads now about a
        // requested server shutdown.
        let (invoke_shutdown, shutdown_listen) = broadcast::channel::<()>(1);
        // create a channel for sending any new metadata event.  These
        // will get processed relatively slowly (a potentially
        // multi-second blocking HTTP call) on a single thread, so we
        // buffer requests on the channel.  No harm in dropping events
        // here, since we are protecting against DoS.  This can make
        // it difficult to setup initial metadata in bulk, since
        // overwhelming this will drop events and won't register
        // metadata events.
        let (metadata_tx, metadata_rx) = broadcast::channel::<Event>(4096);

        let (registry, metrics) = create_metrics();

        // build a repository for events
        let repo = db::build_repo(&settings, metrics.clone()).await;
        // start the database writer task.  Give it a channel for
        // writing events, and for publishing events that have been
        // written (to all connected clients).
        tokio::task::spawn(db::db_writer(
            repo.clone(),
            settings.clone(),
            event_rx,
            bcast_tx.clone(),
            metadata_tx.clone(),
            shutdown_listen,
        ));
        info!("db writer created");

        // create a nip-05 verifier thread; if enabled.
        if settings.verified_users.mode != VerifiedUsersMode::Disabled {
            let verifier_opt = nip05::Verifier::new(
                repo.clone(),
                metadata_rx,
                bcast_tx.clone(),
                settings.clone(),
            );
            if let Ok(mut v) = verifier_opt {
                if verified_users_active {
                    tokio::task::spawn(async move {
                        info!("starting up NIP-05 verifier...");
                        v.run().await;
                    });
                }
            }
        }


        // listen for (external to tokio) shutdown request
        let controlled_shutdown = invoke_shutdown.clone();
        tokio::spawn(async move {
            info!("control message listener started");
            match shutdown_rx.recv() {
                Ok(()) => {
                    info!("control message requesting shutdown");
                    controlled_shutdown.send(()).ok();
                }
                Err(std::sync::mpsc::RecvError) => {
                    trace!("shutdown requestor is disconnected (this is normal)");
                }
            };
        });
        // listen for ctrl-c interruupts
        let ctrl_c_shutdown = invoke_shutdown.clone();
        // listener for webserver shutdown
        let webserver_shutdown_listen = invoke_shutdown.subscribe();

        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.unwrap();
            info!("shutting down due to SIGINT (main)");
            ctrl_c_shutdown.send(()).ok();
        });
        // spawn a task to check the pool size.
        //let pool_monitor = pool.clone();
        //tokio::spawn(async move {db::monitor_pool("reader", pool_monitor).await;});

        // Read in the favicon if it exists
        let favicon = settings.info.favicon.as_ref().and_then(|x| {
            info!("reading favicon...");
            file_bytes(x).ok()
        });

        // Hyper 1.x has no `Server`; the listening socket and accept loop are now ours.
        // `hyper-util` provides connection serving, automatic HTTP/1 or HTTP/2 selection,
        // and graceful shutdown that waits for live connections.
        let listener = match tokio::net::TcpListener::bind(socket_addr).await {
            Ok(l) => l,
            Err(e) => {
                // Exit NONZERO. A plain return used to report success when the port was
                // occupied, so supervisors neither restarted the relay nor raised an alert.
                eprintln!("could not bind {socket_addr}: {e}");
                std::process::exit(1);
            }
        };
        let graceful = hyper_util::server::graceful::GracefulShutdown::new();
        let mut shutdown = std::pin::pin!(ctrl_c_or_signal(webserver_shutdown_listen));
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, remote_addr) = match accepted {
                        Ok(pair) => pair,
                        // One accept failure must not stop the relay: a failed client or
                        // exhausted descriptors is no reason to abandon other connections.
                        // But do not spin either. Under descriptor exhaustion, accept fails
                        // immediately and a tight loop burns a core while flooding logs.
                        // This delay lets the system release resources. Hyper 0.14 handled
                        // it in AddrIncoming::sleep_on_errors; the migration lost that logic.
                        Err(e) => {
                            warn!("connection accept failed: {e}");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                    };
                    let repo = repo.clone();
                    let bcast = bcast_tx.clone();
                    let event = event_tx.clone();
                    let stop = invoke_shutdown.clone();
                    let settings = settings.clone();
                    let favicon = favicon.clone();
                    let registry = registry.clone();
                    let metrics = metrics.clone();
                    let writes = HttpResponseWrites::new(HTTP_RESPONSE_WRITE_TIMEOUT);
                    let response_writes = writes.clone();
                    let svc = service_fn(move |request: Request<Incoming>| {
                        response_writes.clone().response(handle_web_request(
                            request,
                            repo.clone(),
                            settings.clone(),
                            remote_addr,
                            bcast.clone(),
                            event.clone(),
                            stop.subscribe(),
                            favicon.clone(),
                            registry.clone(),
                            metrics.clone(),
                        ))
                    });
                    let mut builder = hyper_util::server::conn::auto::Builder::new(
                        TokioExecutor::new());
                    // .timer() is REQUIRED with header_read_timeout. Without it, hyper
                    // panics on EVERY connection ("timeout set, but no timer set"). Unit
                    // tests do not exercise this HTTP path; a live check found it on
                    // 2026-08-29.
                    builder
                        .http1()
                        .timer(hyper_util::rt::TokioTimer::new())
                        .header_read_timeout(HEADER_READ_TIMEOUT);
                    // ...with_upgrades is required for WebSocket upgrade support.
                    let conn = builder.serve_connection_with_upgrades(
                        TokioIo::new(stream), svc);
                    let conn = graceful.watch(conn.into_owned());
                    tokio::spawn(async move {
                        match writes.run(conn).await {
                            Some(Err(e)) => debug!("connection ended with an error: {e}"),
                            None => debug!("HTTP response write deadline exceeded; connection closed"),
                            Some(Ok(())) => {},
                        }
                    });
                }
                _ = &mut shutdown => {
                    info!("shutdown signal received; waiting for live connections");
                    break;
                }
            }
        }
        if tokio::time::timeout(GRACEFUL_SHUTDOWN_TIMEOUT, graceful.shutdown())
            .await
            .is_err()
        {
            warn!("connections did not close within {GRACEFUL_SHUTDOWN_TIMEOUT:?}; forcing shutdown");
        }
    });
    Ok(())
}

/// Nostr protocol messages from a client
#[derive(Deserialize, Serialize, Clone, PartialEq, Eq, Debug)]
#[serde(untagged)]
pub enum NostrMessage {
    /// `EVENT` and  `AUTH` messages
    EventMsg(EventCmd),
    /// A `REQ` message
    SubMsg(Subscription),
    /// A `CLOSE` message
    CloseMsg(CloseCmd),
}

/// Extract a subscription id from RAW `["REQ", "<id>", ...]` text even when filters
/// fail to parse. Without this, rejection becomes an unaddressed `NOTICE`, leaving a
/// client waiting for its subscription's `EOSE` until timeout: "relay did not answer"
/// instead of "filter is invalid." Internal finding 111 surfaced after finding 90 made
/// filter parsing strict. `None` means non-REQ or non-string id, retaining `NOTICE`.
fn subscription_id_of(msg: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(msg).ok()?;
    let arr = v.as_array()?;
    if arr.first()?.as_str()? != "REQ" {
        return None;
    }
    Some(arr.get(1)?.as_str()?.to_owned())
}

/// NIP-01 `["CLOSED", <sub_id>, <reason>]`. The reason already carries the required
/// prefix (`invalid: ` or `error: `). Serialize with serde so quotes and newlines in
/// the reason cannot break JSON.
fn make_closed_message(sub_id: &str, reason: &str) -> String {
    serde_json::json!(["CLOSED", sub_id, reason]).to_string()
}

/// Convert Message to `NostrMessage`
fn convert_to_msg(msg: &str, max_bytes: Option<usize>) -> Result<NostrMessage> {
    let parsed_res: Result<NostrMessage> =
        serde_json::from_str(msg).map_err(std::convert::Into::into);
    match parsed_res {
        Ok(m) => {
            if let NostrMessage::SubMsg(_) = m {
                // note; this only prints the first 16k of a REQ and then truncates.
                trace!("REQ: {:?}", msg);
            };
            if let NostrMessage::EventMsg(_) = m {
                if let Some(max_size) = max_bytes {
                    // check length, ensure that some max size is set.
                    if msg.len() > max_size && max_size > 0 {
                        return Err(Error::EventMaxLengthError(msg.len()));
                    }
                }
            }
            Ok(m)
        }
        Err(e) => {
            trace!("proto parse error: {:?}", e);
            trace!("parse error on message: {:?}", msg.trim());
            Err(Error::ProtoParseError)
        }
    }
}

/// Turn a string into a NOTICE message ready to send over a `WebSocket`
fn make_notice_message(notice: &Notice) -> Message {
    let json = match notice {
        Notice::Message(ref msg) => json!(["NOTICE", msg]),
        Notice::EventResult(ref res) => json!(["OK", res.id, res.status.to_bool(), res.msg]),
        Notice::AuthChallenge(ref challenge) => json!(["AUTH", challenge]),
    };

    Message::text(json.to_string())
}

fn allowed_to_send(event_str: &str, conn: &conn::ClientConn, settings: &Settings) -> bool {
    // Performance limitation: the kind is not passed separately, so NIP-42 DM
    // authorization deserializes the event before deciding whether it applies.
    if settings.authorization.nip42_dms {
        match serde_json::from_str::<Event>(event_str) {
            Ok(event) => {
                if event.kind == 4 || event.kind == 44 || event.kind == 1059 {
                    match (conn.auth_pubkey(), event.tag_values_by_name("p").first()) {
                        (Some(auth_pubkey), Some(recipient_pubkey)) => {
                            recipient_pubkey == auth_pubkey || &event.pubkey == auth_pubkey
                        }
                        (_, _) => false,
                    }
                } else {
                    true
                }
            }
            Err(_) => false,
        }
    } else {
        true
    }
}

struct ClientInfo {
    remote_ip: String,
    user_agent: Option<String>,
    origin: Option<String>,
}

/// Handle new client connections.  This runs through an event loop
/// for all client communication.
#[allow(clippy::too_many_arguments)]
async fn nostr_server(
    repo: Arc<dyn NostrRepo>,
    client_info: ClientInfo,
    settings: Settings,
    mut ws_stream: WebSocketStream<TokioIo<Upgraded>>,
    broadcast: Sender<Event>,
    event_tx: mpsc::Sender<SubmittedEvent>,
    mut shutdown: Receiver<()>,
    metrics: NostrMetrics,
) {
    // the time this websocket nostr server started
    let orig_start = Instant::now();
    // get a broadcast channel for clients to communicate on
    let mut bcast_rx = broadcast.subscribe();
    // Track internal client state
    let mut conn = conn::ClientConn::new(client_info.remote_ip);
    // subscription creation rate limiting
    let mut sub_lim_opt = None;
    // 100ms jitter when the rate limiter returns
    let jitter = Jitter::up_to(Duration::from_millis(100));
    let sub_per_min_setting = settings.limits.subscriptions_per_min;
    if let Some(sub_per_min) = sub_per_min_setting {
        if sub_per_min > 0 {
            trace!("Rate limits for sub creation ({}/min)", sub_per_min);
            let quota_time = core::num::NonZeroU32::new(sub_per_min).unwrap();
            let quota = Quota::per_minute(quota_time);
            sub_lim_opt = Some(RateLimiter::direct(quota));
        }
    }
    // Use the remote IP as the client identifier
    let cid = conn.get_client_prefix();
    // Create a channel for receiving query results from the database.
    // we will send out the tx handle to any query we generate.
    // this has capacity for some of the larger requests we see, which
    // should allow the DB thread to release the handle earlier.
    let (query_tx, mut query_rx) = mpsc::channel::<db::QueryResult>(20_000);
    // Create channel for receiving NOTICEs
    let (notice_tx, mut notice_rx) = mpsc::channel::<Notice>(128);
    // The writer asks the connection to close when this client's notice
    // channel is full. Capacity 1: the signal itself never waits, and a
    // second request while one is queued is a no-op.
    let (disconnect_tx, mut disconnect_rx) = mpsc::channel::<()>(1);

    // last time this client sent data (message, ping, etc.)
    let mut last_message_time = Instant::now();

    // ping interval (every 5 minutes)
    let default_ping_dur = Duration::from_secs(settings.network.ping_interval_seconds.into());

    // disconnect after 20 minutes without a ping response or event.
    let max_quiet_time = Duration::from_secs(60 * 20);

    let start = tokio::time::Instant::now() + default_ping_dur;
    let mut ping_interval = tokio::time::interval_at(start, default_ping_dur);

    // maintain a hashmap of a oneshot channel for active subscriptions.
    // when these subscriptions are cancelled, make a message
    // available to the executing query so it knows to stop.
    let mut running_queries: HashMap<String, oneshot::Sender<()>> = HashMap::new();
    // for stats, keep track of how many events the client published,
    // and how many it received from queries.
    let mut client_published_event_count: usize = 0;
    let mut client_received_event_count: usize = 0;

    let unspec = "<unspecified>".to_string();
    info!("new client connection (cid: {}, ip: {:?})", cid, conn.ip());
    let origin = client_info.origin.as_ref().unwrap_or(&unspec);
    let user_agent = client_info.user_agent.as_ref().unwrap_or(&unspec);
    info!(
        "cid: {}, origin: {:?}, user-agent: {:?}",
        cid, origin, user_agent
    );

    // Measure connections
    metrics.connections.inc();
    // Decrement on EVERY exit path: disconnect, write timeout, or relay shutdown. Use
    // a guard rather than a manual decrement at the end so early returns and panics are
    // covered too.
    struct ConnGuard(IntGauge);
    impl Drop for ConnGuard {
        fn drop(&mut self) {
            self.0.dec();
        }
    }
    metrics.connections_active.inc();
    let _conn_guard = ConnGuard(metrics.connections_active.clone());

    if settings.authorization.nip42_auth {
        conn.generate_auth_challenge();
        if let Some(challenge) = conn.auth_challenge() {
            ws_stream
                .send(make_notice_message(&Notice::AuthChallenge(
                    challenge.to_string(),
                )))
                .await
                .ok();
        }
    }

    loop {
        tokio::select! {
            _ = shutdown.recv() => {
                metrics.disconnects.with_label_values(&["shutdown"]).inc();
                info!("Close connection down due to shutdown, client: {}, ip: {:?}, connected: {:?}", cid, conn.ip(), orig_start.elapsed());
                // server shutting down, exit loop
                break;
            },
            Some(()) = disconnect_rx.recv() => {
                // db_writer could not queue a decision. Waiting for this
                // client would stall every other publish, so the writer
                // returned immediately and asked us to close. The reason is
                // best-effort: a wedged socket still ends at WRITE_TIMEOUT.
                info!("closing connection; the client was not reading relay decisions (cid: {})", cid);
                metrics.disconnects.with_label_values(&["notice_overflow"]).inc();
                let notice = Notice::message(
                    "relay closed the connection: decisions were not being read".into(),
                );
                let _ = send_or_timeout(&mut ws_stream, make_notice_message(&notice)).await;
                break;
            },
            _ = ping_interval.tick() => {
                // check how long since we talked to client
                // if it has been too long, disconnect
                if last_message_time.elapsed() > max_quiet_time {
                    debug!("ending connection due to lack of client ping response");
                    metrics.disconnects.with_label_values(&["timeout"]).inc();
                    break;
                }
                // Send a ping
                if !send_or_timeout(&mut ws_stream, Message::Ping(Bytes::new())).await {
                    debug!("failed to send ping, closing connection (cid: {})", cid);
                    metrics.disconnects.with_label_values(&["send_error"]).inc();
                    break;
                }
            },
            Some(notice_msg) = notice_rx.recv() => {
                if !send_or_timeout(&mut ws_stream, make_notice_message(&notice_msg)).await {
                    debug!("failed to send ping, closing connection (cid: {})", cid);
                    metrics.disconnects.with_label_values(&["send_error"]).inc();
                    break;
                }
            },
            Some(query_result) = query_rx.recv() => {
                // database informed us of a query result we asked for
                let subesc = query_result.sub_id.replace('"', "");
                if query_result.event == "EOSE" {
                    let send_str = format!("[\"EOSE\",\"{subesc}\"]");
                    if !send_or_timeout(&mut ws_stream, Message::Text(send_str.into())).await {
                        debug!("failed to send message, closing connection (cid: {})", cid);
                        metrics.disconnects.with_label_values(&["send_error"]).inc();
                        break;
                    }
                } else if let Some(reason) = query_result.event.strip_prefix("CLOSED ") {
                    // Query failed or was aborted. EOSE here would mean "the
                    // stored set is empty", which is a different fact.
                    let send_str = make_closed_message(&subesc, reason);
                    if !send_or_timeout(&mut ws_stream, Message::Text(send_str.into())).await {
                        debug!("failed to send CLOSED, closing connection (cid: {})", cid);
                        metrics.disconnects.with_label_values(&["send_error"]).inc();
                        break;
                    }
                } else if allowed_to_send(&query_result.event, &conn, &settings) {
                    metrics.sent_events.with_label_values(&["db"]).inc();
                    client_received_event_count += 1;
                    // send a result
                    let send_str = format!("[\"EVENT\",\"{}\",{}]", subesc, query_result.event);
                    if !send_or_timeout(&mut ws_stream, Message::Text(send_str.into())).await {
                        debug!("failed to send message, closing connection (cid: {})", cid);
                        metrics.disconnects.with_label_values(&["send_error"]).inc();
                        break;
                    }
                }
            },
            // Lagged broadcast notifications are intentionally not logged here; the
            // receiver resumes with the next available event.
            Ok(global_event) = bcast_rx.recv() => {
                let mut should_disconnect = false;
                // an event has been broadcast to all clients
                // first check if there is a subscription for this event.
                for (s, sub) in conn.subscriptions() {
                    if !sub.interested_in_event(&global_event) {
                        continue;
                    }
                    // Performance limitation: the event is serialized per consumer,
                    // rather than once when it enters the broadcast channel.
                    if let Ok(event_str) = serde_json::to_string(&global_event) {
                        if allowed_to_send(&event_str, &conn, &settings) {
                            // create an event response and send it
                            trace!("sub match for client: {}, sub: {:?}, event: {:?}",
                               cid, s,
                               global_event.get_event_id_prefix());
                            let subesc = s.replace('"', "");
                            metrics.sent_events.with_label_values(&["realtime"]).inc();
                            if !send_or_timeout(&mut ws_stream, Message::Text(format!("[\"EVENT\",\"{subesc}\",{event_str}]").into())).await {
                                debug!("failed to send message, closing connection (cid: {})", cid);
                                metrics.disconnects.with_label_values(&["send_error"]).inc();
                                should_disconnect = true;
                                break;
                            }
                        }
                    } else {
                        warn!("could not serialize event: {:?}", global_event.get_event_id_prefix());
                    }
                }
                if should_disconnect {
                    break;
                }
            },
            ws_next = ws_stream.next() => {
                // update most recent message time for client
                last_message_time = Instant::now();
                // Consume text messages from the client, parse into Nostr messages.
                // Extract the subscription id from RAW text before parsing. If parsing
                // fails, there is otherwise no way to address CLOSED (finding 111).
                let (nostr_msg, req_sub_id) = match ws_next {
                    Some(Ok(Message::Text(m))) => {
                        let req_sub_id = subscription_id_of(&m);
                        (convert_to_msg(&m,settings.limits.max_event_bytes), req_sub_id)
                    },
                    Some(Ok(Message::Binary(_))) => {

                        if !send_or_timeout(&mut ws_stream, make_notice_message(&Notice::message("binary messages are not accepted".into()))).await {
                            debug!("failed to send notice, closing connection (cid: {})", cid);
                            metrics.disconnects.with_label_values(&["send_error"]).inc();
                            break;
                        }
                        continue;
                    },
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {
                        // get a ping/pong, ignore.  tungstenite will
                        // send responses automatically.
                        continue;
                    },
                    Some(Err(WsError::Capacity(MessageTooLong{size, max_size}))) => {
                        if !send_or_timeout(&mut ws_stream, make_notice_message(&Notice::message(format!("message too large ({size} > {max_size})")))).await {
                            debug!("failed to send notice, closing connection (cid: {})", cid);
                            metrics.disconnects.with_label_values(&["send_error"]).inc();
                            break;
                        }
                        continue;
                    },
                    None |
                    Some(Ok(Message::Close(_)) |
                         Err(WsError::AlreadyClosed | WsError::ConnectionClosed |
                             WsError::Protocol(tungstenite::error::ProtocolError::ResetWithoutClosingHandshake)))
                        => {
                            debug!("websocket close from client (cid: {}, ip: {:?})",cid, conn.ip());
                            metrics.disconnects.with_label_values(&["normal"]).inc();
                            break;
                        },
                    Some(Err(WsError::Io(e))) => {
                        // IO errors are considered fatal
                        warn!("IO error (cid: {}, ip: {:?}): {:?}", cid, conn.ip(), e);
                        metrics.disconnects.with_label_values(&["error"]).inc();
                        break;
                    }
                    x => {
                        // default condition on error is to close the client connection
                        info!("unknown error (cid: {}, ip: {:?}): {:?} (closing conn)", cid, conn.ip(), x);
                        metrics.disconnects.with_label_values(&["error"]).inc();
                        break;
                    }
                };

                // convert ws_next into proto_next
                match nostr_msg {
                    Ok(NostrMessage::EventMsg(ec)) => {
                        // An EventCmd needs to be validated to be converted into an Event
                        // handle each type of message
                        let evid = ec.event_id().to_owned();
                        let parsed : Result<EventWrapper> = Result::<EventWrapper>::from(ec);
                        match parsed {
                            Ok(WrappedEvent(e)) => {
                                metrics.cmd_event.inc();
                                let id_prefix:String = e.id.chars().take(8).collect();
                                debug!("successfully parsed/validated event: {:?} (cid: {}, kind: {})", id_prefix, cid, e.kind);
                                if let Some(reason) = crate::db::not_ready_reason() {
                                    let notice = Notice::error(e.id, reason);
                                    if !send_or_timeout(&mut ws_stream, make_notice_message(&notice)).await {
                                        debug!("failed to send notice, closing connection (cid: {})", cid);
                                        metrics.disconnects.with_label_values(&["send_error"]).inc();
                                        break;
                                    }
                                    continue;
                                }
                                if crate::utils::unix_time_from(std::time::SystemTime::now()).is_none() {
                                    let notice = Notice::error(
                                        e.id,
                                        "relay clock is unusable, cannot judge expiration",
                                    );
                                    if !send_or_timeout(&mut ws_stream, make_notice_message(&notice)).await {
                                        debug!("failed to send notice, closing connection (cid: {})", cid);
                                        metrics.disconnects.with_label_values(&["send_error"]).inc();
                                        break;
                                    }
                                    continue;
                                }
                                // The relay cannot parse a non-canonical deadline. Before
                                // finding 125, such an event looked UNBOUNDED: it was accepted
                                // even with a past intended deadline and returned forever, a
                                // one-step NIP-40 bypass. Expiration is the only number the
                                // relay parses itself, so it must be canonical.
                                if e.has_malformed_expiration() {
                                    let notice = Notice::invalid(
                                        e.id,
                                        "expiration must be a canonical unix timestamp                                          (digits only, no sign, no leading zero)",
                                    );
                                    if !send_or_timeout(&mut ws_stream, make_notice_message(&notice)).await {
                                        debug!("failed to send notice, closing connection (cid: {})", cid);
                                        metrics.disconnects.with_label_values(&["send_error"]).inc();
                                        break;
                                    }
                                    continue;
                                }
                                // check if event is expired
                                if e.is_expired() {
                                    let notice = Notice::invalid(e.id, "The event has already expired");
                                    if !send_or_timeout(&mut ws_stream, make_notice_message(&notice)).await {
                                        debug!("failed to send notice, closing connection (cid: {})", cid);
                                        metrics.disconnects.with_label_values(&["send_error"]).inc();
                                        break;
                                    }
                                    // check if the event is too far in the future.
                                } else if e.is_valid_timestamp(settings.options.reject_future_seconds) {
                                    // Write this to the database.
                                    let auth_pubkey = conn.auth_pubkey().and_then(|pubkey| hex::decode(pubkey).ok());
                                    let submit_event = SubmittedEvent {
                                        event: e.clone(),
                                        notice_tx: notice_tx.clone(),
                                        close_tx: Some(disconnect_tx.clone()),
                                        source_ip: conn.ip().to_string(),
                                        origin: client_info.origin.clone(),
                                        user_agent: client_info.user_agent.clone(),
                                        auth_pubkey };
                                    // A dead writer is not an acceptance. `.ok()` used to
                                    // hide it and the counter still moved.
                                    match event_tx.send(submit_event).await {
                                        Ok(()) => client_published_event_count += 1,
                                        Err(_) => {
                                            warn!("event writer is gone; event was not queued (cid: {})", cid);
                                            let notice = Notice::error(
                                                e.id,
                                                "relay cannot accept events right now",
                                            );
                                            let _ = send_or_timeout(&mut ws_stream, make_notice_message(&notice)).await;
                                            metrics.disconnects.with_label_values(&["error"]).inc();
                                            break;
                                        }
                                    }
                                } else {
                                    info!("client: {} sent a far future-dated event", cid);
                                    if let Some(fut_sec) = settings.options.reject_future_seconds {
                                        let msg = format!("The event created_at field is out of the acceptable range (+{fut_sec}sec) for this relay.");
                                        let notice = Notice::invalid(e.id, &msg);
                                        if !send_or_timeout(&mut ws_stream, make_notice_message(&notice)).await {
                                            debug!("failed to send notice, closing connection (cid: {})", cid);
                                            metrics.disconnects.with_label_values(&["send_error"]).inc();
                                            break;

                                        }
                                    }
                                }
                            },
                            Ok(WrappedAuth(event)) => {
                                metrics.cmd_auth.inc();
                                if settings.authorization.nip42_auth {
                                    let id_prefix:String = event.id.chars().take(8).collect();
                                    debug!("successfully parsed auth: {:?} (cid: {})", id_prefix, cid);
                                    match &settings.info.relay_url {
                                        None => {
                                            error!("AUTH command received, but relay_url is not set in the config file (cid: {})", cid);
                                        },
                                        Some(relay) => {
                                            match conn.authenticate(&event, relay) {
                                                Ok(_) => {
                                                    let pubkey = match conn.auth_pubkey() {
                                                        Some(k) => k.chars().take(8).collect(),
                                                        None => "<unspecified>".to_string(),
                                                    };
                                                    info!("client is authenticated: (cid: {}, pubkey: {:?})", cid, pubkey);
                                                    // Send OK message to confirm successful authentication (NIP-42)
                                                    if !send_or_timeout(&mut ws_stream, make_notice_message(&Notice::saved(event.id))).await {
                                                        debug!("failed to send notice, closing connection (cid: {})", cid);
                                                        metrics.disconnects.with_label_values(&["send_error"]).inc();
                                                        break;
                                                    }
                                                },
                                                Err(e) => {
                                                    info!("authentication error: {} (cid: {})", e, cid);
                                                    if !send_or_timeout(&mut ws_stream, make_notice_message(&Notice::restricted(event.id, format!("authentication error: {e}").as_str()))).await {
                                                        debug!("failed to send notice, closing connection (cid: {})", cid);
                                                        metrics.disconnects.with_label_values(&["send_error"]).inc();
                                                        break;
                                                    }
                                                },
                                            }
                                        }
                                    }
                                } else {
                                    let e = CommandUnknownError;
                                    info!("client sent an invalid event (cid: {})", cid);
                                    if !send_or_timeout(&mut ws_stream, make_notice_message(&Notice::invalid(evid, &format!("{e}")))).await {
                                        debug!("failed to send notice, closing connection (cid: {})", cid);
                                        metrics.disconnects.with_label_values(&["send_error"]).inc();
                                        break;
                                    }
                                }
                            },
                            Err(e) => {
                                metrics.cmd_event.inc();
                                info!("client sent an invalid event (cid: {})", cid);
                                if !send_or_timeout(&mut ws_stream, make_notice_message(&Notice::invalid(evid, &format!("{e}")))).await {
                                    debug!("failed to send notice, closing connection (cid: {})", cid);
                                    metrics.disconnects.with_label_values(&["send_error"]).inc();
                                    break;
                                }
                            }
                        }
                    },
                    Ok(NostrMessage::SubMsg(s)) => {
                        debug!("subscription requested (cid: {}, sub: {:?})", cid, s.id);
                        // subscription handling consists of:
                        // * check for rate limits
                        // * registering the subscription so future events can be matched
                        // * making a channel to cancel to request later
                        // * sending a request for a SQL query
                        // Do nothing if the sub already exists.
                        if conn.has_subscription(&s) {
                            info!("client sent duplicate subscription, ignoring (cid: {}, sub: {:?})", cid, s.id);
                        } else {
                            metrics.cmd_req.inc();
                            if let Some(ref lim) = sub_lim_opt {
                                lim.until_ready_with_jitter(jitter).await;
                            }
                            if settings.limits.limit_scrapers && s.is_scraper() {
                                info!("subscription was scraper, ignoring (cid: {}, sub: {:?})", cid, s.id);
                                if !send_or_timeout(&mut ws_stream, Message::Text(format!("[\"EOSE\",\"{}\"]", s.id).into())).await {
                                    debug!("failed to send message, closing connection (cid: {})", cid);
                                    metrics.disconnects.with_label_values(&["send_error"]).inc();
                                    break;
                                }
                                continue
                            }
                            let (abandon_query_tx, abandon_query_rx) = oneshot::channel::<()>();
                            match conn.subscribe(s.clone()) {
                                Ok(()) => {
                                    // when we insert, if there was a previous query running with the same name, cancel it.
                                    if let Some(previous_query) = running_queries.insert(s.id.clone(), abandon_query_tx) {
                                        previous_query.send(()).ok();
                                    }
                                    if s.needs_historical_events() {
                                        // start a database query.  this spawns a blocking database query on a worker thread.
                                        repo.query_subscription(s, cid.clone(), query_tx.clone(), abandon_query_rx).await.ok();
                                    }
                                },
                                Err(e) => {
                                    info!("Subscription error: {} (cid: {}, sub: {:?})", e, cid, s.id);
                                    if !send_or_timeout(&mut ws_stream, make_notice_message(&Notice::message(format!("Subscription error: {e}")))).await {
                                        debug!("failed to send notice, closing connection (cid: {})", cid);
                                        metrics.disconnects.with_label_values(&["send_error"]).inc();
                                        break;

                                    }
                                }
                            }
                        }
                    },
                    Ok(NostrMessage::CloseMsg(cc)) => {
                        // closing a request simply removes the subscription.
                        let parsed : Result<Close> = Result::<Close>::from(cc);
                        if let Ok(c) = parsed {
                            metrics.cmd_close.inc();
                            // check if a query is currently
                            // running, and remove it if so.
                            let stop_tx = running_queries.remove(&c.id);
                            if let Some(tx) = stop_tx {
                                tx.send(()).ok();
                            }
                            // stop checking new events against
                            // the subscription
                            conn.unsubscribe(&c);
                        } else {
                            info!("invalid command ignored");
                            if !send_or_timeout(&mut ws_stream, make_notice_message(&Notice::message("could not parse command".into()))).await {
                                debug!("failed to send notice, closing connection (cid: {})", cid);
                                metrics.disconnects.with_label_values(&["send_error"]).inc();
                                break;
                            }
                        }
                    },
                    Err(Error::ConnError) => {
                        debug!("got connection close/error, disconnecting cid: {}, ip: {:?}",cid, conn.ip());
                        break;
                    }
                    Err(Error::EventMaxLengthError(s)) => {
                        info!("client sent command larger ({} bytes) than max size (cid: {})", s, cid);
                        if !send_or_timeout(&mut ws_stream, make_notice_message(&Notice::message("event exceeded max size".into()))).await {
                            debug!("failed to send notice, closing connection (cid: {})", cid);
                            metrics.disconnects.with_label_values(&["send_error"]).inc();
                            break;
                        }
                    },
                    // Parsing failed. If this was a REQ with a readable subscription id,
                    // return NIP-01 CLOSED so the client learns that ITS subscription was
                    // rejected instead of waiting for EOSE until timeout (finding 111).
                    Err(Error::ProtoParseError) if req_sub_id.is_some() => {
                        let sub_id = req_sub_id.clone().unwrap_or_default();
                        debug!("REQ rejected (cid: {}, sub: {})", cid, sub_id);
                        let msg = make_closed_message(
                            &sub_id,
                            "invalid: could not parse REQ (a filter field has the wrong type \
                             or the message is malformed)",
                        );
                        if !send_or_timeout(&mut ws_stream, Message::Text(msg.into())).await {
                            debug!("failed to send CLOSED, closing connection (cid: {})", cid);
                            metrics.disconnects.with_label_values(&["send_error"]).inc();
                            break;
                        }
                    },
                    Err(Error::ProtoParseError) => {
                        info!("client sent command that could not be parsed (cid: {})", cid);
                        if !send_or_timeout(&mut ws_stream, make_notice_message(&Notice::message("could not parse command".into()))).await {
                            debug!("failed to send notice, closing connection (cid: {})", cid);
                            metrics.disconnects.with_label_values(&["send_error"]).inc();
                            break;
                        }
                    },
                    Err(e) => {
                        info!("got non-fatal error from client (cid: {}, error: {:?}", cid, e);
                    },
                }
            },
        }
    }
    // connection cleanup - ensure any still running queries are terminated.
    for (_, stop_tx) in running_queries {
        stop_tx.send(()).ok();
    }
    info!(
        "stopping client connection (cid: {}, ip: {:?}, sent: {} events, recv: {} events, connected: {:?})",
        cid,
        conn.ip(),
        client_published_event_count,
        client_received_event_count,
        orig_start.elapsed()
    );
}

#[derive(Clone)]
pub struct NostrMetrics {
    pub query_sub: Histogram,        // response time of successful subscriptions
    pub query_db: Histogram,         // individual database query execution time
    pub db_connections: IntGauge,    // database connections in use
    pub write_events: Histogram,     // response time of event writes
    pub sent_events: IntCounterVec,  // count of events sent to clients
    pub connections: IntCounter,     // count of websocket connections
    // Connections open RIGHT NOW. connections_total only increases and cannot answer
    // "is it time to add a relay?" Capacity planning needs the current level (added
    // 2026-08-29).
    pub connections_active: IntGauge,
    pub disconnects: IntCounterVec,  // client disconnects
    pub query_aborts: IntCounterVec, // count of queries aborted by server
    pub cmd_req: IntCounter,         // count of REQ commands received
    pub cmd_event: IntCounter,       // count of EVENT commands received
    pub cmd_close: IntCounter,       // count of CLOSE commands received
    pub cmd_auth: IntCounter,        // count of AUTH commands received
}

#[cfg(test)]
mod clippy_boundary_tests {
    use super::*;

    async fn rejected_body_error_size(use_inner: bool) -> usize {
        let (client, server) = tokio::io::duplex(4096);
        let serving = tokio::spawn(async move {
            let service = service_fn(move |request: Request<Incoming>| async move {
                let result = if use_inner {
                    read_body_capped_inner(request, 1).await
                } else {
                    read_body_capped(request, 1).await
                };
                let error = result.unwrap_err();
                let bytes = std::mem::size_of_val(&error);
                assert_eq!(error.status(), StatusCode::PAYLOAD_TOO_LARGE);
                assert_eq!(error.headers()["Content-Type"], "application/json");
                let body = error.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                    json!({"accepted": false, "message": "request body too large"})
                );
                Ok::<_, Infallible>(Response::new(full(bytes.to_string())))
            });
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(server), service)
                .await
        });
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client))
            .await
            .unwrap();
        let connection = tokio::spawn(connection);
        let request = Request::builder()
            .method(Method::POST)
            .uri("/")
            .header("Host", "local")
            .body(Full::new(Bytes::from_static(b"oversized")))
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(5), sender.send_request(request))
            .await
            .unwrap()
            .unwrap();
        let bytes = tokio::time::timeout(Duration::from_secs(5), response.into_body().collect())
            .await
            .unwrap()
            .unwrap()
            .to_bytes();
        let inline_size = std::str::from_utf8(&bytes).unwrap().parse().unwrap();
        drop(sender);
        tokio::time::timeout(Duration::from_secs(5), connection)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), serving)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        inline_size
    }

    #[tokio::test]
    async fn timed_body_reader_error_stays_below_the_inline_error_limit() {
        let bytes = rejected_body_error_size(false).await;
        assert!(bytes < 128, "timed REST body error grew to {bytes} bytes");
    }

    #[tokio::test]
    async fn inner_body_reader_error_stays_below_the_inline_error_limit() {
        let bytes = rejected_body_error_size(true).await;
        assert!(bytes < 128, "inner REST body error grew to {bytes} bytes");
    }
}

#[cfg(test)]
mod closed_reason_tests {
    use super::{classify_repo_read, make_closed_message, subscription_id_of, RepoRead};

    #[test]
    fn database_error_is_not_a_missing_row() {
        assert!(matches!(
            classify_repo_read::<(), &str>(Ok(None)),
            RepoRead::Missing
        ));
        assert!(matches!(
            classify_repo_read::<(), &str>(Err("database")),
            RepoRead::Failed
        ));
    }

    /// Finding 111: recover the subscription id from raw REQ even when filters fail to
    /// parse, or CLOSED has no address for the client.
    #[test]
    fn subscription_id_is_recovered_from_a_broken_req() {
        assert_eq!(
            subscription_id_of(r#"["REQ","sub-1",{"kinds":["a"]}]"#).as_deref(),
            Some("sub-1")
        );
        assert_eq!(
            subscription_id_of(r#"[ "REQ" , "日本語" , {"authors":[null]} ]"#).as_deref(),
            Some("日本語")
        );
        // Non-REQ, non-array, non-string id, and truncated JSON have no id; retain NOTICE.
        assert_eq!(subscription_id_of(r#"["EVENT",{"id":"x"}]"#), None);
        assert_eq!(subscription_id_of(r#"["REQ",42,{}]"#), None);
        assert_eq!(subscription_id_of(r#"["REQ","only-id""#), None);
        assert_eq!(subscription_id_of("not json at all"), None);
        assert_eq!(subscription_id_of(r#"["CLOSE","sub-1"]"#), None);
    }

    /// NIP-01 CLOSED shape: a three-element array with an `invalid:` reason prefix.
    #[test]
    fn closed_message_follows_nip01_shape() {
        let json = make_closed_message("sub-1", "invalid: filter field \"kinds\" has the wrong type");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v[0], "CLOSED");
        assert_eq!(v[1], "sub-1");
        assert!(v[2].as_str().unwrap().starts_with("invalid: "), "{json}");
        assert_eq!(v.as_array().unwrap().len(), 3);
        // Quotes and newlines in the reason do not break JSON.
        let json = make_closed_message("s\"2", "invalid: \"x\"\nY");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v[1], "s\"2");
    }
}

#[cfg(test)]
mod inbox_tests {
    use super::*;

    // HTTP routing shares the process-wide response budget.
    static HTTP_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    async fn request(repo: Arc<dyn NostrRepo>, settings: Settings, uri: &str) -> Response<Vec<u8>> {
        let (client, server) = tokio::io::duplex(4096);
        let serving = tokio::spawn(async move {
            let (events, _) = broadcast::channel(4);
            let (event_tx, _event_rx) = mpsc::channel(4);
            let (shutdown, _) = broadcast::channel(4);
            let (registry, metrics) = create_metrics();
            let writes = HttpResponseWrites::new(HTTP_RESPONSE_WRITE_TIMEOUT);
            let response_writes = writes.clone();
            let service = service_fn(move |request| {
                response_writes.clone().response(handle_web_request(request, repo.clone(), settings.clone(),
                    "127.0.0.1:1".parse().unwrap(), events.clone(), event_tx.clone(),
                    shutdown.subscribe(), None, registry.clone(), metrics.clone()))
            });
            writes.run(hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(server), service)).await
        });
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client)).await.unwrap();
        let connection = tokio::spawn(connection);
        let request = Request::builder().uri(uri).header("Host", "local")
            .header("Connection", "close").body(Empty::<Bytes>::new()).unwrap();
        let response = tokio::time::timeout(Duration::from_secs(5), sender.send_request(request))
            .await.unwrap().unwrap();
        let (parts, body) = response.into_parts();
        let bytes = tokio::time::timeout(Duration::from_secs(5), body.collect())
            .await.unwrap().unwrap().to_bytes();
        drop(sender);
        connection.await.unwrap().unwrap();
        serving.await.unwrap().unwrap().unwrap();
        Response::from_parts(parts, bytes.to_vec())
    }

    fn settings() -> Settings {
        let mut settings = Settings::default();
        settings.a4a.rest_enabled = true;
        settings
    }

    #[test]
    fn inbox_query_defaults_limits_and_u64_boundary() {
        let base = format!("recipient={}&page=2", "a".repeat(64));
        let q = parse_inbox_query(Some(&base)).unwrap();
        assert_eq!((q.after, q.after_id.as_str(), q.limit), (0, "", 250));
        assert_eq!(parse_inbox_query(Some(&format!("{base}&limit=0"))).unwrap().limit, 1);
        assert_eq!(parse_inbox_query(Some(&format!("{base}&limit=5001"))).unwrap().limit, 5000);
        let q = parse_inbox_query(Some(&format!("{base}&after={}&after_id={}", u64::MAX, "f".repeat(64)))).unwrap();
        assert_eq!(q.after, u64::MAX);
        assert_eq!(q.after_id, "f".repeat(64));
        for tail in ["after=", "limit=", "limit=-1", "limit=18446744073709551616",
                     "after_id=%20", "recipient", "", "=1", "page=2", "page=02"] {
            assert!(parse_inbox_query(Some(&format!("{base}&{tail}"))).is_err(), "{tail}");
        }
    }

    #[tokio::test]
    async fn inbox_http_filters_pages_and_preserves_notary_history() {
        let _guard = HTTP_TEST_LOCK.lock().await;
        let repo: Arc<dyn NostrRepo> = Arc::new(crate::repo::sqlite::tests::inbox_fixture().await);
        let recipient = "a".repeat(64);
        let mut after = 0;
        let mut id = String::new();
        for seed in [1001, 1002] {
            let response = request(repo.clone(), settings(), &format!(
                "/v1/inbox?recipient={recipient}&after={after}&after_id={id}&limit=1&page=2")).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()["Content-Type"], "application/json");
            let page: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
            let event = repo.get_event_by_id(&format!("{seed:064x}")).await.unwrap().unwrap();
            assert_eq!(page, json!({"version": 2, "recipient": recipient,
                "rows": [{"first_seen": 100, "event": event}],
                "next_cursor": {"first_seen": 100, "id": event.id}}));
            after = 100;
            id = event.id;
        }
        let response = request(repo.clone(), settings(), &format!(
            "/v1/inbox?recipient={recipient}&after={after}&after_id={id}&page=2")).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(serde_json::from_slice::<serde_json::Value>(response.body()).unwrap(),
            json!({"version": 2, "recipient": recipient, "rows": [], "next_cursor": null}));
        let response = request(repo.clone(), settings(), &format!(
            "/v1/inbox?recipient={}&page=2", "c".repeat(64))).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(serde_json::from_slice::<serde_json::Value>(response.body()).unwrap(),
            json!({"version": 2, "recipient": "c".repeat(64), "rows": [], "next_cursor": null}));
        let response = request(repo, settings(), "/v1/history?page=2").await;
        assert_eq!(response.status(), StatusCode::OK);
        let history: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(history["rows"].as_array().unwrap().len(), 1);
        assert_eq!(history["rows"][0]["event"]["kind"], 31005);
    }

    #[tokio::test]
    async fn inbox_http_validates_parameters_and_fails_closed_for_private_dms() {
        let _guard = HTTP_TEST_LOCK.lock().await;
        let repo: Arc<dyn NostrRepo> = Arc::new(crate::repo::sqlite::tests::inbox_fixture().await);
        let recipient = "a".repeat(64);
        for query in [String::new(), "page=2".into(), format!("recipient={recipient}"),
            format!("recipient={recipient}&page=1"), "recipient=&page=2".into(),
            format!("recipient={}&page=2", "A".repeat(64)),
            format!("recipient={}&page=2", "a".repeat(63)),
            format!("recipient={}&page=2", "g".repeat(64)),
        ].into_iter().chain([
            "after=bad", "after=-1", "after=18446744073709551616", "after=+1",
            "limit=x", "after_id=bad", "after_id=AA", "unknown=1", "after",
            "recipient=", "page=2", "after=1&after=2", "after_id=&after_id=",
            "limit=1&limit=2", "unknown=1&unknown=2",
        ].into_iter().map(|tail| format!("recipient={recipient}&page=2&{tail}"))) {
            let response = request(repo.clone(), settings(), &format!("/v1/inbox?{query}")).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "accepted query: {query}");
        }
        let uri = format!("/v1/inbox?recipient={recipient}&page=2");
        let mut private = settings();
        private.authorization.nip42_dms = true;
        assert_eq!(request(repo.clone(), private, &uri).await.status(), StatusCode::FORBIDDEN);
        let mut disabled = settings();
        disabled.a4a.rest_enabled = false;
        assert_eq!(request(repo, disabled, &uri).await.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn inbox_http_postgres_is_unsupported_not_empty_success() {
        let _guard = HTTP_TEST_LOCK.lock().await;
        // Lazy pools with no minimum connections never contact a database.
        let pool = sqlx::postgres::PgPoolOptions::new().min_connections(0)
            .connect_lazy("postgres://synthetic:synthetic@127.0.0.1:1/synthetic").unwrap();
        let repo: Arc<dyn NostrRepo> = Arc::new(crate::repo::postgres::PostgresRepo::new(
            pool.clone(), pool.clone(), create_metrics().1));
        let uri = format!("/v1/inbox?recipient={}&page=2", "a".repeat(64));
        assert_eq!(request(repo.clone(), settings(), &uri).await.status(), StatusCode::NOT_IMPLEMENTED);
        let mut private = settings();
        private.authorization.nip42_dms = true;
        assert_eq!(request(repo, private, &uri).await.status(), StatusCode::FORBIDDEN);
        pool.close().await;
    }

    /// Sign `/v1/inbox` proof with `secret`.
    fn signed_proof(secret: &secp256k1::SecretKey, path_and_query: &str,
                    created_at: u64, kind: u64, method: &str) -> String {
        signed_proof_with_tags(
            secret,
            vec![
                vec!["u".to_owned(), format!("https://node.example{path_and_query}")],
                vec!["method".to_owned(), method.to_owned()],
            ],
            created_at,
            kind,
        )
    }

    fn signed_proof_with_tags(
        secret: &secp256k1::SecretKey,
        tags: Vec<Vec<String>>,
        created_at: u64,
        kind: u64,
    ) -> String {
        let secp = secp256k1::Secp256k1::new();
        let keys = secp256k1::Keypair::from_secret_key(&secp, secret);
        let pubkey = hex::encode(keys.x_only_public_key().0.serialize());
        use bitcoin_hashes::Hash as _;
        let canonical = serde_json::json!([0, pubkey, created_at, kind, tags, ""]);
        let digest: bitcoin_hashes::sha256::Hash =
            bitcoin_hashes::sha256::Hash::hash(canonical.to_string().as_bytes());
        let id = format!("{digest:x}");
        // The signature consumes a BYTE SLICE exactly as validation in event.rs does.
        // Signing anything else would make this test fail for the wrong reason.
        let sig = hex::encode(secp.sign_schnorr(digest.as_ref(), &keys).as_ref());
        let event = serde_json::json!({
            "id": id, "pubkey": pubkey, "created_at": created_at, "kind": kind,
            "tags": tags, "content": "", "sig": sig});
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD,
                               event.to_string().as_bytes())
    }

    fn secret_from(byte: u8) -> secp256k1::SecretKey {
        secp256k1::SecretKey::from_slice(&[byte; 32]).unwrap()
    }

    fn pubkey_of(secret: &secp256k1::SecretKey) -> String {
        let secp = secp256k1::Secp256k1::new();
        hex::encode(secp256k1::Keypair::from_secret_key(&secp, secret)
            .x_only_public_key().0.serialize())
    }

    /// Inbox reads require PROOF of the key, not merely naming it in a parameter.
    ///
    /// Before this rule, `/v1/inbox?recipient=<another key>` returned envelopes to any
    /// caller, reproduced on a production node with an unrelated key on 2026-09-14.
    /// Content is encrypted, but ciphertext can be harvested for future decryption and
    /// metadata is visible immediately.
    ///
    /// Three outcomes intentionally differ: 401 means "prove ownership," 403 means
    /// "proof accepted, but this is not your inbox," and 200 means "yours." Retry the
    /// first with a signature; retrying the second is pointless. Clients must distinguish
    /// them.
    #[tokio::test]
    async fn inbox_read_requires_proof_of_the_recipient_key() {
        let repo: Arc<dyn NostrRepo> = Arc::new(crate::repo::sqlite::tests::inbox_fixture().await);
        let slots = Arc::new(tokio::sync::Semaphore::new(4));
        let mine = secret_from(7);
        let other = secret_from(9);
        let recipient = pubkey_of(&mine);
        // The complete query is required: otherwise validation rejects the request BEFORE
        // authentication and this test fails for the wrong reason, with 400 instead of 401.
        let query = format!("recipient={recipient}&after=0&limit=5&page=2");
        let path_and_query = format!("/v1/inbox?{query}");
        let uri: hyper::Uri = format!("https://node.example{path_and_query}").parse().unwrap();
        let now = crate::utils::unix_time();

        let mut empty = hyper::HeaderMap::new();
        empty.insert("x-unrelated", "1".parse().unwrap());
        assert_eq!(
            inbox_request(repo.clone(), Some(&query), slots.clone(), false,
                          Some((&empty, &uri, Some("wss://node.example")))).await.status(),
            StatusCode::UNAUTHORIZED,
            "an inbox must not be returned without proof");

        let mut foreign = hyper::HeaderMap::new();
        foreign.insert(hyper::header::AUTHORIZATION,
            format!("Nostr {}", signed_proof(&other, &path_and_query, now, 27235, "GET"))
                .parse().unwrap());
        assert_eq!(
            inbox_request(repo.clone(), Some(&query), slots.clone(), false,
                          Some((&foreign, &uri, Some("wss://node.example")))).await.status(),
            StatusCode::FORBIDDEN,
            "proof of another key means 'not your inbox,' not 'prove again'");

        let mut ours = hyper::HeaderMap::new();
        ours.insert(hyper::header::AUTHORIZATION,
            format!("Nostr {}", signed_proof(&mine, &path_and_query, now, 27235, "GET"))
                .parse().unwrap());
        assert_eq!(
            inbox_request(repo.clone(), Some(&query), slots.clone(), false,
                          Some((&ours, &uri, Some("wss://node.example")))).await.status(),
            StatusCode::OK,
            "the key owner must be able to read their inbox");
    }

    /// Proof must be bound to TIME, REQUEST, and METHOD.
    ///
    /// Without time binding an observed header works forever; without address binding it
    /// works for any path, including future ones; without method binding it authorizes a
    /// write where only read access was proven. Each assertion fails when its own binding
    /// is removed.
    #[tokio::test]
    async fn inbox_proof_is_bound_to_time_request_and_method() {
        let repo: Arc<dyn NostrRepo> = Arc::new(crate::repo::sqlite::tests::inbox_fixture().await);
        let slots = Arc::new(tokio::sync::Semaphore::new(4));
        let mine = secret_from(7);
        let recipient = pubkey_of(&mine);
        // The complete query is required: otherwise validation rejects the request BEFORE
        // authentication and this test fails for the wrong reason, with 400 instead of 401.
        let query = format!("recipient={recipient}&after=0&limit=5&page=2");
        let path_and_query = format!("/v1/inbox?{query}");
        let uri: hyper::Uri = format!("https://node.example{path_and_query}").parse().unwrap();
        let now = crate::utils::unix_time();

        for (proof, why) in [
            (signed_proof(&mine, &path_and_query, now - 3600, 27235, "GET"), "expired"),
            (signed_proof(&mine, &path_and_query, now + 3600, 27235, "GET"), "from the future"),
            (signed_proof(&mine, "/v1/history?after=0", now, 27235, "GET"), "for another address"),
            (signed_proof(&mine, &path_and_query, now, 27235, "POST"), "for another method"),
            (signed_proof(&mine, &path_and_query, now, 1, "GET"), "wrong kind"),
        ] {
            let mut headers = hyper::HeaderMap::new();
            headers.insert(hyper::header::AUTHORIZATION,
                format!("Nostr {proof}").parse().unwrap());
            let status = inbox_request(repo.clone(), Some(&query), slots.clone(), false,
                                       Some((&headers, &uri, Some("wss://node.example")))).await.status();
            assert_eq!(status, StatusCode::UNAUTHORIZED,
                       "{why} proof was accepted but should not be");
        }
    }

    /// Path-only binding accepts a proof signed for an unrelated origin whenever both
    /// services expose the same route. Exactly one URL and method are required too:
    /// accepting any matching tag lets one signed event authorize several requests.
    #[tokio::test]
    async fn inbox_proof_is_bound_to_the_configured_origin_and_is_unambiguous() {
        let repo: Arc<dyn NostrRepo> = Arc::new(crate::repo::sqlite::tests::inbox_fixture().await);
        let slots = Arc::new(tokio::sync::Semaphore::new(4));
        let mine = secret_from(7);
        let recipient = pubkey_of(&mine);
        let query = format!("recipient={recipient}&after=0&limit=5&page=2");
        let path_and_query = format!("/v1/inbox?{query}");
        let uri: hyper::Uri = format!("https://node.example{path_and_query}").parse().unwrap();
        let now = crate::utils::unix_time();

        let cases = [
            vec![
                vec!["u".to_owned(), format!("https://other.example{path_and_query}")],
                vec!["method".to_owned(), "GET".to_owned()],
            ],
            vec![
                vec!["u".to_owned(), format!("https://node.example{path_and_query}")],
                vec!["u".to_owned(), format!("https://other.example{path_and_query}")],
                vec!["method".to_owned(), "GET".to_owned()],
            ],
            vec![
                vec!["u".to_owned(), format!("https://node.example{path_and_query}")],
                vec!["method".to_owned(), "GET".to_owned()],
                vec!["method".to_owned(), "POST".to_owned()],
            ],
        ];
        for tags in cases {
            let proof = signed_proof_with_tags(&mine, tags, now, KIND_HTTP_AUTH);
            let mut headers = hyper::HeaderMap::new();
            headers.insert(
                hyper::header::AUTHORIZATION,
                format!("Nostr {proof}").parse().unwrap(),
            );
            let status = inbox_request(
                repo.clone(),
                Some(&query),
                slots.clone(),
                false,
                Some((&headers, &uri, Some("wss://node.example"))),
            )
            .await
            .status();
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn inbox_http_default_limit_and_response_byte_bound() {
        let _guard = HTTP_TEST_LOCK.lock().await;
        let repo = crate::repo::sqlite::tests::test_repo().await;
        let recipient = "a".repeat(64);
        for seed in 2000..2253 {
            repo.write_event(&crate::repo::sqlite::tests::inbox_event(seed, 1059, &recipient)).await.unwrap();
        }
        repo.write_pool().get().unwrap().execute("UPDATE event SET first_seen=100", []).unwrap();
        let repo: Arc<dyn NostrRepo> = Arc::new(repo);
        let base = format!("/v1/inbox?recipient={recipient}&page=2");
        let response = request(repo.clone(), settings(), &base).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["Cache-Control"], "no-store");
        let page: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(page["rows"].as_array().unwrap().len(), 250);
        for (limit, expected) in [(0, 1), (1, 1), (5001, 253)] {
            let response = request(repo.clone(), settings(), &format!("{base}&limit={limit}")).await;
            assert_eq!(response.status(), StatusCode::OK);
            let page: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
            assert_eq!(page["rows"].as_array().unwrap().len(), expected);
        }
        let repo = crate::repo::sqlite::tests::test_repo().await;
        for seed in 2300..2324 {
            let mut event = crate::repo::sqlite::tests::inbox_event(seed, 1059, &recipient);
            event.content = "x".repeat(120_000);
            repo.write_event(&event).await.unwrap();
        }
        repo.write_pool().get().unwrap().execute("UPDATE event SET first_seen=100", []).unwrap();
        let repo: Arc<dyn NostrRepo> = Arc::new(repo);
        let mut cursor = String::new();
        let mut ids = Vec::new();
        loop {
            let response = request(repo.clone(), settings(), &format!("{base}{cursor}")).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert!(response.body().len() <= crate::repo::MAX_HISTORY_PAGE_BYTES);
            let page: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
            let rows = page["rows"].as_array().unwrap();
            if rows.is_empty() { assert!(page["next_cursor"].is_null()); break; }
            cursor = format!("&after={}&after_id={}", page["next_cursor"]["first_seen"],
                page["next_cursor"]["id"].as_str().unwrap());
            ids.extend(rows.iter().map(|r| r["event"]["id"].as_str().unwrap().to_owned()));
            assert!(ids.len() <= 24, "cursor failed to advance");
        }
        assert_eq!(ids, (2300..2324).map(|id| format!("{id:064x}")).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn inbox_http_oversized_event_returns_413_not_empty_page() {
        let _guard = HTTP_TEST_LOCK.lock().await;
        let repo = crate::repo::sqlite::tests::test_repo().await;
        let recipient = "a".repeat(64);
        let mut event = crate::repo::sqlite::tests::inbox_event(2400, 1059, &recipient);
        event.content = "x".repeat(crate::repo::MAX_HISTORY_PAGE_BYTES);
        repo.write_event(&event).await.unwrap();
        repo.write_pool().get().unwrap().execute("UPDATE event SET first_seen=100", []).unwrap();
        let response = request(Arc::new(repo), settings(), &format!("/v1/inbox?recipient={recipient}&page=2")).await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(response.body().len() < 1024);
        assert!(!String::from_utf8_lossy(response.body()).contains("next_cursor"));
    }

    #[tokio::test]
    async fn inbox_http_work_budget_is_explicit_error_not_empty_page() {
        let _guard = HTTP_TEST_LOCK.lock().await;
        let repo = crate::repo::sqlite::tests::inbox_large_recipient_fixture().await;
        let response = request(Arc::new(repo), settings(), &format!(
            "/v1/inbox?recipient={}&after=101&limit=1&page=2", "a".repeat(64))).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = std::str::from_utf8(response.body()).unwrap();
        assert!(body.contains("work budget"), "{body}");
        assert!(body.contains("cursor was not advanced"), "{body}");
        assert!(!body.contains("next_cursor"), "no successful page on interrupted work");
    }

    #[tokio::test]
    async fn inbox_permit_lives_through_response_bytes_and_private_gate_ignores_busy_slot() {
        let repo: Arc<dyn NostrRepo> = Arc::new(crate::repo::sqlite::tests::inbox_fixture().await);
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let query = format!("recipient={}&page=2", "a".repeat(64));
        let response = inbox_request(repo.clone(), Some(&query), slots.clone(), false, None).await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let clone = bytes.clone();
        drop(bytes);
        let busy = inbox_request(repo.clone(), Some(&query), slots.clone(), false, None).await;
        assert_eq!(busy.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(busy.headers()["Retry-After"], "1");
        assert_eq!(inbox_request(repo.clone(), Some(&query), slots.clone(), true, None).await.status(), StatusCode::FORBIDDEN);
        drop(clone);
        assert_eq!(inbox_request(repo, Some(&query), slots, false, None).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn inbox_cancelled_handler_holds_slot_until_blocked_sqlite_read_finishes() {
        let repo = crate::repo::sqlite::tests::inbox_fixture().await;
        let held = crate::repo::sqlite::tests::hold_readers(&repo);
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let repo: Arc<dyn NostrRepo> = Arc::new(repo);
        let query = format!("recipient={}&page=2", "a".repeat(64));
        let (r, s, q) = (repo.clone(), slots.clone(), query.clone());
        let task = tokio::spawn(async move { inbox_request(r, Some(&q), s, false, None).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!task.is_finished());
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(inbox_request(repo.clone(), Some(&query), slots.clone(), false, None).await.status(), StatusCode::TOO_MANY_REQUESTS);
        drop(held);
        let permit = tokio::time::timeout(Duration::from_secs(3), slots.clone().acquire_owned()).await.unwrap().unwrap();
        drop(permit);
        assert_eq!(inbox_request(repo, Some(&query), slots, false, None).await.status(), StatusCode::OK);
    }
}

#[cfg(test)]
mod http_response_write_tests {
    use super::*;

    #[tokio::test]
    async fn http_write_deadline_tracks_last_bytes_clone_not_body_end() {
        let writes = HttpResponseWrites::new(Duration::from_millis(30));
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let response = writes.clone().response(std::future::ready(Ok(Response::new(
            history_body(vec![1; 4096], slots.clone().try_acquire_owned().unwrap()))))).await.unwrap();
        let mut body = response.into_body();
        let bytes = body.frame().await.unwrap().unwrap().into_data().unwrap();
        let retained = bytes.clone();
        drop(bytes);
        drop(body);
        assert_eq!(slots.available_permits(), 0);
        tokio::time::timeout(Duration::from_secs(1), writes.expired()).await.unwrap();
        assert_eq!(slots.available_permits(), 0, "the watchdog must not release retained buffers");
        drop(retained);
        assert_eq!(slots.available_permits(), 1);
        // An old, completed response must not time out a keep-alive connection.
        assert!(writes.run(tokio::time::sleep(Duration::from_millis(60))).await.is_some());
    }

    #[tokio::test]
    async fn http_write_deadline_keeps_alive_after_small_empty_and_head_responses() {
        let (client, server) = tokio::io::duplex(4096);
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let response_slots = slots.clone();
        let serving = tokio::spawn(async move {
            let writes = HttpResponseWrites::new(Duration::from_millis(100));
            let response_writes = writes.clone();
            let service = service_fn(move |request: Request<Incoming>| {
                let body = match request.uri().path() {
                    "/empty" => empty(),
                    "/head" => history_body(vec![1; 120_000],
                        response_slots.clone().try_acquire_owned().unwrap()),
                    _ => full("ok"),
                };
                response_writes.clone().response(std::future::ready(Ok(Response::new(body))))
            });
            writes.run(hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(server), service).into_owned()).await
        });
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client)).await.unwrap();
        let connection = tokio::spawn(connection);
        for (method, path, expected) in [
            (Method::GET, "/small", "ok"), (Method::GET, "/empty", ""), (Method::HEAD, "/head", ""),
        ] {
            let response = sender.send_request(Request::builder().method(method).uri(path)
                .header("Host", "local").body(Empty::<Bytes>::new()).unwrap()).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.into_body().collect().await.unwrap().to_bytes(), expected);
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert!(!serving.is_finished(), "completed {path} response killed keep-alive");
            assert_eq!(slots.available_permits(), 1);
            let response = sender.send_request(Request::builder().uri("/small").header("Host", "local")
                .body(Empty::<Bytes>::new()).unwrap()).await.unwrap();
            assert_eq!(response.into_body().collect().await.unwrap().to_bytes(), "ok");
        }
        drop(sender);
        connection.await.unwrap().unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(1), serving).await.unwrap().unwrap().unwrap().is_ok());
    }

    #[tokio::test]
    async fn http_write_deadline_closes_flow_control_stalled_http2() {
        let repo: Arc<dyn NostrRepo> = Arc::new(crate::repo::sqlite::tests::history_fixture().await);
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let (client, server) = tokio::io::duplex(2048);
        let (r, s) = (repo.clone(), slots.clone());
        let serving = async move {
            let writes = HttpResponseWrites::new(Duration::from_millis(200));
            let response_writes = writes.clone();
            let service = service_fn(move |request: Request<Incoming>| {
                let (r, s) = (r.clone(), s.clone());
                response_writes.clone().response(async move {
                    Ok(history_request(r, request.uri().query(), s).await)
                })
            });
            writes.run(hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(server), service).into_owned()).await
        };
        let reading = async {
            let (mut sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .initial_stream_window_size(1024).initial_connection_window_size(1024)
                .handshake(TokioIo::new(client)).await.unwrap();
            let connection = tokio::spawn(connection);
            let response = sender.send_request(Request::builder().uri("http://local/v1/history?page=2")
                .body(Empty::<Bytes>::new()).unwrap()).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(slots.available_permits(), 0);
            let permit = tokio::time::timeout(Duration::from_secs(3), slots.clone().acquire_owned())
                .await.unwrap().unwrap();
            drop(permit);
            drop(response);
            drop(sender);
            let _ = tokio::time::timeout(Duration::from_secs(1), connection).await.unwrap().unwrap();
        };
        let (finished, ()) = tokio::join!(tokio::time::timeout(Duration::from_secs(3), serving), reading);
        assert!(finished.unwrap().is_none());
        assert_eq!(history_request(repo, Some("page=2"), slots).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn http_write_deadline_does_not_cut_off_upgraded_websocket() {
        let (client, server) = tokio::io::duplex(4096);
        let (tasks_tx, mut tasks_rx) = mpsc::channel(1);
        let serving = tokio::spawn(async move {
            let writes = HttpResponseWrites::new(Duration::from_millis(30));
            let response_writes = writes.clone();
            let service = service_fn(move |mut request: Request<Incoming>| {
                let response = handshake::server::create_response_with_body(&request, empty).unwrap();
                let upgraded = hyper::upgrade::on(&mut request);
                tasks_tx.try_send(tokio::spawn(async move {
                    let mut ws = WebSocketStream::from_raw_socket(
                        TokioIo::new(upgraded.await.unwrap()), tungstenite::protocol::Role::Server, None).await;
                    while let Some(Ok(message)) = ws.next().await {
                        if message.is_close() { break; }
                        ws.send(message).await.unwrap();
                    }
                })).unwrap();
                response_writes.clone().response(std::future::ready(Ok(response)))
            });
            writes.run(hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(server), service)).await
        });
        let (mut ws, response) = tokio_tungstenite::client_async("ws://local/", client).await.unwrap();
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        tokio::time::sleep(Duration::from_millis(100)).await;
        ws.send(Message::Text("after HTTP deadline".into())).await.unwrap();
        let echoed = tokio::time::timeout(Duration::from_secs(1), ws.next()).await.unwrap().unwrap().unwrap();
        assert_eq!(echoed.into_text().unwrap(), "after HTTP deadline");
        ws.close(None).await.unwrap();
        tasks_rx.recv().await.unwrap().await.unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(1), serving)
            .await.unwrap().unwrap().unwrap().is_ok());
    }
}

#[cfg(test)]
mod history_query_tests {
    use super::parse_history_query;

    #[test]
    fn history_cursor_is_validated_instead_of_silently_ignored() {
        assert!(parse_history_query(Some("page=2&after_id=bad")).is_err());
        assert!(parse_history_query(Some("page=3")).is_err());
        assert!(parse_history_query(Some("after=1&after=2")).is_err());
    }

    #[test]
    fn defaults_and_normal_values() {
        let q = parse_history_query(None).unwrap();
        assert_eq!((q.after, q.limit, q.after_id, q.paged), (0, 1000, String::new(), false));
        let q = parse_history_query(Some("after=17&limit=5&page=2")).unwrap();
        assert_eq!((q.after, q.limit, q.paged), (17, 5, true));
    }

    #[test]
    fn limit_is_clamped_to_range() {
        assert_eq!(parse_history_query(Some("limit=0")).unwrap().limit, 1);
        assert_eq!(parse_history_query(Some("limit=5001")).unwrap().limit, 5000);
    }

    #[test]
    fn non_numeric_is_an_error_not_zero() {
        let err = parse_history_query(Some("after=abc")).unwrap_err();
        assert!(err.contains("after"), "{err}");
        let err = parse_history_query(Some("after=1&limit=x")).unwrap_err();
        assert!(err.contains("limit"), "{err}");
        assert!(parse_history_query(Some("after=-1")).is_err());
    }

    #[tokio::test]
    async fn history_slot_lives_until_response_bytes_are_dropped() {
        use http_body_util::BodyExt;
        let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let body = super::history_body(vec![1; 1024], slots.clone().try_acquire_owned().unwrap());
        assert!(slots.clone().try_acquire_owned().is_err());
        let bytes = body.collect().await.unwrap().to_bytes();
        assert_eq!(bytes.len(), 1024);
        assert!(slots.clone().try_acquire_owned().is_err());
        let clone = bytes.clone();
        drop(bytes);
        assert!(slots.clone().try_acquire_owned().is_err());
        drop(clone);
        assert!(slots.clone().try_acquire_owned().is_ok());
    }

    #[tokio::test]
    async fn cancelled_history_handler_keeps_slot_until_blocked_sqlite_read_finishes() {
        let repo = crate::repo::sqlite::tests::test_repo().await;
        let held = crate::repo::sqlite::tests::hold_readers(&repo);
        let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let repo: std::sync::Arc<dyn crate::repo::NostrRepo> = std::sync::Arc::new(repo);
        let task = tokio::spawn(super::history_request(repo.clone(), Some("page=2"), slots.clone()));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!task.is_finished(), "fixture did not block the actual SQLite read");
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let busy = super::history_request(repo.clone(), Some("page=2"), slots.clone()).await;
        assert_eq!(busy.status(), hyper::StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(busy.headers()["Retry-After"], "1");
        drop(held);
        let permit = tokio::time::timeout(std::time::Duration::from_secs(3),
            slots.clone().acquire_owned()).await.unwrap().unwrap();
        drop(permit);
        assert_eq!(super::history_request(repo, Some("page=2"), slots).await.status(), hyper::StatusCode::OK);
    }

    #[tokio::test]
    async fn http_backpressure_returns_429_then_releases_on_disconnect() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let repo: std::sync::Arc<dyn crate::repo::NostrRepo> = std::sync::Arc::new(
            crate::repo::sqlite::tests::history_fixture().await);
        let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let (mut client, server) = tokio::io::duplex(1024);
        let (r, s) = (repo.clone(), slots.clone());
        let serving = tokio::spawn(async move {
            let writes = super::HttpResponseWrites::new(super::HTTP_RESPONSE_WRITE_TIMEOUT);
            let response_writes = writes.clone();
            let service = hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                let (r, s) = (r.clone(), s.clone());
                response_writes.clone().response(async move { Ok::<_, std::convert::Infallible>(
                    super::history_request(r, request.uri().query(), s).await) })
            });
            writes.run(hyper::server::conn::http1::Builder::new().serve_connection(
                hyper_util::rt::TokioIo::new(server), service)).await
        });
        client.write_all(b"GET /v1/history?page=2 HTTP/1.1\r\nHost: local\r\n\r\n").await.unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(tokio::time::timeout(std::time::Duration::from_secs(3),
                client.read_u8()).await.unwrap().unwrap());
            assert!(header.len() < 8192);
        }
        assert!(header.starts_with(b"HTTP/1.1 200"));
        assert!(!serving.is_finished());
        let busy = super::history_request(repo.clone(), Some("page=2"), slots.clone()).await;
        assert_eq!(busy.status(), hyper::StatusCode::TOO_MANY_REQUESTS);
        drop(client);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), serving).await.unwrap().unwrap();
        assert_eq!(super::history_request(repo, Some("page=2"), slots).await.status(), hyper::StatusCode::OK);
    }

    #[tokio::test]
    async fn http_write_deadline_releases_stalled_response_without_client_disconnect() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let repo: std::sync::Arc<dyn crate::repo::NostrRepo> = std::sync::Arc::new(
            crate::repo::sqlite::tests::history_fixture().await);
        let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let (mut client, server) = tokio::io::duplex(1024);
        let (r, s) = (repo.clone(), slots.clone());
        let mut serving = tokio::spawn(async move {
            let writes = super::HttpResponseWrites::new(std::time::Duration::from_millis(200));
            let response_writes = writes.clone();
            let service = hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                let (r, s) = (r.clone(), s.clone());
                response_writes.clone().response(async move { Ok::<_, std::convert::Infallible>(
                    super::history_request(r, request.uri().query(), s).await) })
            });
            writes.run(hyper::server::conn::http1::Builder::new().serve_connection(
                hyper_util::rt::TokioIo::new(server), service)).await
        });
        client.write_all(b"GET /v1/history?page=2 HTTP/1.1\r\nHost: local\r\n\r\n").await.unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(tokio::time::timeout(std::time::Duration::from_secs(3),
                client.read_u8()).await.unwrap().unwrap());
        }
        assert!(header.starts_with(b"HTTP/1.1 200"));
        assert_eq!(slots.available_permits(), 0);
        let busy = super::history_request(repo.clone(), Some("page=2"), slots.clone()).await;
        assert_eq!(busy.status(), hyper::StatusCode::TOO_MANY_REQUESTS);
        // Keep the reader open and stalled. The server, not the client, must close.
        let finished = tokio::time::timeout(std::time::Duration::from_secs(3), &mut serving).await;
        if finished.is_err() { serving.abort(); }
        assert!(finished.is_ok(), "stalled HTTP response retained its slot indefinitely");
        assert!(finished.unwrap().unwrap().is_none(), "server must close on the response deadline");
        assert_eq!(slots.available_permits(), 1);
        assert_eq!(super::history_request(repo, Some("page=2"), slots).await.status(), hyper::StatusCode::OK);
        let mut tail = Vec::new();
        client.read_to_end(&mut tail).await.unwrap();
        assert!(tail.len() < 120_000, "the body must be cut off by closing the connection");
    }
}
