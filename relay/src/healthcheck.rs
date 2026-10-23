//! Bounded local health probe used by the release container.

use serde_json::Value;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

const IO_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

/// Verify that the local relay reports a healthy, initialized database.
pub fn check(address: SocketAddr) -> Result<(), String> {
    let mut stream = TcpStream::connect_timeout(&address, IO_TIMEOUT)
        .map_err(|err| format!("cannot connect to {address}: {err}"))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|err| format!("cannot set healthcheck read timeout: {err}"))?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|err| format!("cannot set healthcheck write timeout: {err}"))?;
    stream
        .write_all(
            b"GET /v1/health HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        )
        .map_err(|err| format!("cannot send healthcheck request: {err}"))?;

    let mut response = Vec::new();
    stream
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut response)
        .map_err(|err| format!("cannot read healthcheck response: {err}"))?;
    if response.len() as u64 > MAX_RESPONSE_BYTES {
        return Err("healthcheck response exceeds 64 KiB".to_owned());
    }
    validate_response(&response)
}

fn validate_response(response: &[u8]) -> Result<(), String> {
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "healthcheck response has no HTTP header terminator".to_owned())?;
    let headers = std::str::from_utf8(&response[..separator])
        .map_err(|_| "healthcheck response headers are not UTF-8".to_owned())?;
    let status = headers.lines().next().unwrap_or_default();
    if status != "HTTP/1.1 200 OK" && status != "HTTP/1.0 200 OK" {
        return Err(format!("healthcheck endpoint returned {status:?}"));
    }

    let body = &response[separator + 4..];
    let document: Value = serde_json::from_slice(body)
        .map_err(|err| format!("healthcheck endpoint returned invalid JSON: {err}"))?;
    if document.get("status").and_then(Value::as_str) != Some("ok") {
        return Err("healthcheck endpoint status is not ok".to_owned());
    }
    if document.get("schema_version").and_then(Value::as_u64) == Some(0)
        || document
            .get("schema_version")
            .and_then(Value::as_u64)
            .is_none()
    {
        return Err("healthcheck endpoint has no positive schema version".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_response;

    #[test]
    fn accepts_healthy_initialized_relay() {
        validate_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\",\"schema_version\":21}",
        )
        .unwrap();
    }

    #[test]
    fn rejects_non_success_status() {
        let err = validate_response(
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\n\r\n{\"status\":\"degraded\",\"schema_version\":21}",
        )
        .unwrap_err();
        assert!(err.contains("503"), "{err}");
    }

    #[test]
    fn rejects_uninitialized_schema() {
        let err = validate_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\",\"schema_version\":0}",
        )
        .unwrap_err();
        assert!(err.contains("positive schema"), "{err}");
    }
}
