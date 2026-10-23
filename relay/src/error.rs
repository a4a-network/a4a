//! Error handling
use std::result;
use thiserror::Error;
use tungstenite::error::Error as WsError;

/// Simple `Result` type for errors in this module
pub type Result<T, E = Error> = result::Result<T, E>;

/// Custom error type for Nostr
#[derive(Error, Debug)]
pub enum Error {
    #[error("Protocol parse error")]
    ProtoParseError,
    #[error("Connection error")]
    ConnError,
    #[error("Client write error")]
    ConnWriteError,
    #[error("EVENT parse failed")]
    EventParseFailed,
    #[error("CLOSE message parse failed")]
    CloseParseFailed,
    #[error("Event invalid signature")]
    EventInvalidSignature,
    #[error("Event invalid id")]
    EventInvalidId,
    #[error("Event malformed pubkey")]
    EventMalformedPubkey,
    #[error("Event could not canonicalize")]
    EventCouldNotCanonicalize,
    #[error("Event too large")]
    EventMaxLengthError(usize),
    #[error("A stored history event exceeds the response byte limit")]
    HistoryEventTooLarge,
    #[error("Subscription identifier max length exceeded")]
    SubIdMaxLengthError,
    #[error("Maximum concurrent subscription count reached")]
    SubMaxExceededError,
    // this should be used if the JSON is invalid
    #[error("JSON parsing failed")]
    JsonParseFailed(serde_json::Error),
    // Keep large transport errors behind one pointer. `Error` is the default payload of
    // every crate `Result`; embedding tungstenite's error (~136 bytes) made all those
    // results carry the same stack/call-size cost even on success.
    #[error("WebSocket proto error")]
    WebsocketError(Box<WsError>),
    #[error("Command unknown")]
    CommandUnknownError,
    #[error("SQL error")]
    SqlError(rusqlite::Error),
    #[error("Config error : {0}")]
    ConfigError(config::ConfigError),
    #[error("Data directory does not exist")]
    DatabaseDirError,
    /// The database schema is newer than this build understands.
    ///
    /// Keep this distinct from a generic SQL failure so the operator can distinguish
    /// an unsupported database from a query error. The former requires a compatible
    /// build or schema downgrade; the latter requires investigation.
    ///
    /// This used to be a worker-thread ``panic!`` that did NOT stop the relay. A
    /// 2026-09-14 test ran build 0.3.20 against schema v21: migration panicked, yet
    /// the relay accepted an event and returned it on read, continuing to serve a
    /// database it had already declared unsupported.
    #[error("Database schema is newer than this build supports (v{found} > v{supported})")]
    DatabaseSchemaTooNew { found: usize, supported: usize },
    #[error("Database Connection Pool Error")]
    DatabasePoolError(r2d2::Error),
    #[error("SQL error")]
    SqlxError(sqlx::Error),
    #[error("Database Connection Pool Error")]
    SqlxDatabasePoolError(sqlx::Error),
    #[error("Custom Error : {0}")]
    CustomError(String),
    #[error("Task join error")]
    JoinError,
    #[error("Hyper Client error")]
    HyperError(hyper::Error),
    // hyper 1.x separates protocol errors (hyper::Error) from the wrapper-client
    // errors moved to hyper-util, so they require distinct variants.
    #[error("Hyper legacy client error")]
    HyperClientError(hyper_util::client::legacy::Error),
    #[error("Hex encoding error")]
    HexError(hex::FromHexError),
    #[error("Delegation parse error")]
    DelegationParseError,
    #[error("Channel closed error")]
    ChannelClosed,
    #[error("Authz error")]
    AuthzError,
    // tonic 0.13's Status was ~176 bytes. Keep the public boxed variant and its
    // existing `From` conversion when upgrading the generated client's transport.
    #[error("Tonic GRPC error")]
    TonicError(Box<tonic::Status>),
    #[error("Invalid AUTH message")]
    AuthFailure,
    #[error("I/O Error")]
    IoError(std::io::Error),
    #[error("Payment hash mismatch")]
    PaymentHash,
    #[error("Error parsing url")]
    URLParseError(url::ParseError),
    #[error("HTTP error")]
    HTTPError(http::Error),
    #[error("Unknown/Undocumented")]
    UnknownError,
}

//impl From<Box<dyn std::error::Error>> for Error {
//    fn from(e: Box<dyn std::error::Error>) -> Self {
//        Error::CustomError("error".to_owned())
//    }
//}

impl From<hex::FromHexError> for Error {
    fn from(h: hex::FromHexError) -> Self {
        Error::HexError(h)
    }
}

impl From<hyper::Error> for Error {
    fn from(h: hyper::Error) -> Self {
        Error::HyperError(h)
    }
}

impl From<hyper_util::client::legacy::Error> for Error {
    fn from(h: hyper_util::client::legacy::Error) -> Self {
        Error::HyperClientError(h)
    }
}

impl From<r2d2::Error> for Error {
    fn from(d: r2d2::Error) -> Self {
        Error::DatabasePoolError(d)
    }
}

impl From<tokio::task::JoinError> for Error {
    /// Wrap SQL error
    fn from(_j: tokio::task::JoinError) -> Self {
        Error::JoinError
    }
}

impl From<rusqlite::Error> for Error {
    /// Wrap SQL error
    fn from(r: rusqlite::Error) -> Self {
        Error::SqlError(r)
    }
}

impl From<sqlx::Error> for Error {
    fn from(d: sqlx::Error) -> Self {
        Error::SqlxDatabasePoolError(d)
    }
}

impl From<serde_json::Error> for Error {
    /// Wrap JSON error
    fn from(r: serde_json::Error) -> Self {
        Error::JsonParseFailed(r)
    }
}

impl From<WsError> for Error {
    /// Wrap Websocket error
    fn from(r: WsError) -> Self {
        Error::WebsocketError(Box::new(r))
    }
}

impl From<config::ConfigError> for Error {
    /// Wrap Config error
    fn from(r: config::ConfigError) -> Self {
        Error::ConfigError(r)
    }
}

impl From<tonic::Status> for Error {
    /// Wrap Config error
    fn from(r: tonic::Status) -> Self {
        Error::TonicError(Box::new(r))
    }
}

impl From<std::io::Error> for Error {
    fn from(r: std::io::Error) -> Self {
        Error::IoError(r)
    }
}


impl From<url::ParseError> for Error {
    /// Wrap nostr key error
    fn from(r: url::ParseError) -> Self {
        Error::URLParseError(r)
    }
}

impl From<http::Error> for Error {
    /// Wrap nostr key error
    fn from(r: http::Error) -> Self {
        Error::HTTPError(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Clippy's `result_large_err` threshold is 128 bytes. This enum is the default
    /// error for the whole crate, so an accidentally inlined dependency error would
    /// multiply its cost across every `Result` and resurrect more than one hundred
    /// diagnostics at once.
    #[test]
    fn crate_error_stays_within_the_inline_result_budget() {
        let bytes = std::mem::size_of::<Error>();
        assert!(bytes <= 128, "crate Error grew to {bytes} bytes");
    }

    #[test]
    fn boxed_transport_conversions_preserve_the_underlying_error() {
        let websocket: Error = WsError::ConnectionClosed.into();
        assert!(matches!(
            websocket,
            Error::WebsocketError(inner) if matches!(*inner, WsError::ConnectionClosed)
        ));

        let tonic: Error = tonic::Status::permission_denied("policy denied").into();
        match tonic {
            Error::TonicError(inner) => {
                assert_eq!(inner.code(), tonic::Code::PermissionDenied);
                assert_eq!(inner.message(), "policy denied");
            }
            other => panic!("wrong conversion result: {other:?}"),
        }
    }
}
