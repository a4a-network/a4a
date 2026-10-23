use crate::error::{Error, Result};
use crate::{event::Event, nip05::Nip05Name};
use nauthz_grpc::authorization_client::AuthorizationClient;
use nauthz_grpc::event::TagEntry;
use nauthz_grpc::{Decision, Event as GrpcEvent, EventReply, EventRequest};
use tracing::{info, warn};

pub mod nauthz_grpc {
    tonic::include_proto!("nauthz");
}

// A decision for the DB to act upon
pub trait AuthzDecision: Send + Sync {
    fn permitted(&self) -> bool;
    fn message(&self) -> Option<String>;
}

impl AuthzDecision for EventReply {
    fn permitted(&self) -> bool {
        self.decision == Decision::Permit as i32
    }
    fn message(&self) -> Option<String> {
        self.message.clone()
    }
}

// A connection to an event admission GRPC server
pub struct EventAuthzService {
    server_addr: String,
    conn: Option<AuthorizationClient<tonic::transport::Channel>>,
}

// conversion of Nip05Names into GRPC type
impl std::convert::From<Nip05Name> for nauthz_grpc::event_request::Nip05Name {
    fn from(value: Nip05Name) -> Self {
        nauthz_grpc::event_request::Nip05Name {
            local: value.local.clone(),
            domain: value.domain,
        }
    }
}

// conversion of event tags into gprc struct
fn tags_to_protobuf(tags: &[Vec<String>]) -> Vec<TagEntry> {
    tags.iter()
        .map(|x| TagEntry { values: x.clone() })
        .collect()
}

impl EventAuthzService {
    pub async fn connect(server_addr: &str) -> EventAuthzService {
        let mut eas = EventAuthzService {
            server_addr: server_addr.to_string(),
            conn: None,
        };
        eas.ready_connection().await;
        eas
    }

    pub async fn ready_connection(&mut self) {
        if self.conn.is_none() {
            let client = AuthorizationClient::connect(self.server_addr.to_string()).await;
            if let Err(ref msg) = client {
                warn!("could not connect to nostr authz GRPC server: {:?}", msg);
            } else {
                info!("connected to nostr authorization GRPC server");
            }
            self.conn = client.ok();
        }
    }

    pub async fn admit_event(
        &mut self,
        event: &Event,
        ip: &str,
        origin: Option<String>,
        user_agent: Option<String>,
        nip05: Option<Nip05Name>,
        auth_pubkey: Option<Vec<u8>>,
    ) -> Result<Box<dyn AuthzDecision>> {
        self.ready_connection().await;
        let id_blob = hex::decode(&event.id)?;
        let pubkey_blob = hex::decode(&event.pubkey)?;
        let sig_blob = hex::decode(&event.sig)?;
        if let Some(ref mut c) = self.conn {
            let gevent = GrpcEvent {
                id: id_blob,
                pubkey: pubkey_blob,
                sig: sig_blob,
                created_at: event.created_at,
                kind: event.kind,
                content: event.content.clone(),
                tags: tags_to_protobuf(&event.tags),
            };
            let svr_res = c
                .event_admit(EventRequest {
                    event: Some(gevent),
                    ip_addr: Some(ip.to_string()),
                    origin,
                    user_agent,
                    auth_pubkey,
                    nip05: nip05.map(nauthz_grpc::event_request::Nip05Name::from),
                })
                .await?;
            let reply = svr_res.into_inner();
            Ok(Box::new(reply))
        } else {
            Err(Error::AuthzError)
        }
    }
}

#[cfg(test)]
mod clippy_boundary_tests {
    use super::*;
    use http_body_util::{BodyExt, Full};
    use hyper::body::{Bytes, Incoming};
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use prost::Message;
    use std::convert::Infallible;
    use std::time::Duration;

    #[test]
    fn generated_client_status_stays_below_the_inline_error_limit() {
        let bytes = std::mem::size_of::<tonic::Status>();
        assert!(bytes < 128, "generated gRPC client error grew to {bytes} bytes");
    }

    #[test]
    fn authorization_reply_wire_and_fail_closed_decisions_are_unchanged() {
        for (decision, message, wire, permitted) in [
            (Decision::Permit, Some("ok".to_owned()), "080112026f6b", true),
            (Decision::Deny, Some(String::new()), "08021200", false),
            (Decision::Unspecified, None, "", false),
        ] {
            let reply = EventReply {
                decision: decision as i32,
                message,
            };
            assert_eq!(hex::encode(reply.encode_to_vec()), wire);
            assert_eq!(
                EventReply::decode(hex::decode(wire).unwrap().as_slice()).unwrap(),
                reply
            );
            assert_eq!(reply.permitted(), permitted);
        }
        // An unrecognized decision must not become permission during a codec upgrade.
        assert!(!EventReply {
            decision: 99,
            message: None
        }
        .permitted());
    }

    #[test]
    fn authorization_request_keeps_optional_empty_field_presence_on_the_wire() {
        let request = EventRequest {
            event: None,
            ip_addr: Some("x".to_owned()),
            origin: Some(String::new()),
            user_agent: Some(String::new()),
            auth_pubkey: Some(Vec::new()),
            nip05: Some(nauthz_grpc::event_request::Nip05Name {
                local: "a".to_owned(),
                domain: "b".to_owned(),
            }),
        };
        let wire = "1201781a0022002a0032060a0161120162";
        assert_eq!(hex::encode(request.encode_to_vec()), wire);
        assert_eq!(
            EventRequest::decode(hex::decode(wire).unwrap().as_slice()).unwrap(),
            request
        );
        assert!(EventRequest::default().encode_to_vec().is_empty());
    }

    #[test]
    fn authorization_event_wire_keeps_fixed_timestamp_bytes_and_tags() {
        let event = GrpcEvent {
            id: vec![1],
            pubkey: vec![2],
            created_at: 1,
            kind: 4,
            content: "c".to_owned(),
            tags: vec![TagEntry {
                values: vec!["p".to_owned(), "x".to_owned()],
            }],
            sig: vec![3],
        };
        let wire = "0a010112010219010000000000000020042a016332060a01700a01783a0103";
        assert_eq!(hex::encode(event.encode_to_vec()), wire);
        assert_eq!(
            GrpcEvent::decode(hex::decode(wire).unwrap().as_slice()).unwrap(),
            event
        );
    }

    #[tokio::test]
    async fn generated_client_preserves_http2_rpc_path_reply_and_error_details() {
        // Use an independent HTTP/2 fixture, not a server generated by the same codec.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown, stop) = tokio::sync::oneshot::channel::<()>();
        let serving = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let service = service_fn(|request: Request<Incoming>| async move {
                assert_eq!(request.method(), hyper::Method::POST);
                assert_eq!(request.uri().path(), "/nauthz.Authorization/EventAdmit");
                assert_eq!(request.headers()["content-type"], "application/grpc");
                let bytes = request.into_body().collect().await.unwrap().to_bytes();
                assert!(bytes.len() >= 5);
                assert_eq!(bytes[0], 0, "fixture expects an uncompressed gRPC message");
                let length = u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize;
                assert_eq!(length, bytes.len() - 5);
                let request = EventRequest::decode(&bytes[5..]).unwrap();
                let mut trailers = http::HeaderMap::new();
                let payload = match request.ip_addr.as_deref().unwrap() {
                    "permit" | "deny" => {
                        let permitted = request.ip_addr.as_deref() == Some("permit");
                        let reply = EventReply {
                            decision: if permitted { 1 } else { 2 },
                            message: Some("fixture".to_owned()),
                        };
                        let payload = reply.encode_to_vec();
                        let mut frame = vec![0];
                        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                        frame.extend_from_slice(&payload);
                        trailers.insert("grpc-status", "0".parse().unwrap());
                        frame
                    }
                    "error" => {
                        trailers.insert("grpc-status", "7".parse().unwrap());
                        trailers.insert("grpc-message", "blocked%20by%20policy".parse().unwrap());
                        trailers.insert("grpc-status-details-bin", "AQ==".parse().unwrap());
                        trailers.insert("policy", "deny".parse().unwrap());
                        Vec::new()
                    }
                    other => panic!("unexpected fixture request: {other}"),
                };
                let body = Full::new(Bytes::from(payload)).with_trailers(std::future::ready(
                    Some(Ok::<_, Infallible>(trailers)),
                ));
                Ok::<_, Infallible>(Response::builder()
                    .header("content-type", "application/grpc")
                    .body(body)
                    .unwrap())
            });
            let builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
            let connection = builder.serve_connection(TokioIo::new(socket), service);
            tokio::pin!(connection);
            tokio::select! {
                result = &mut connection => result.unwrap(),
                _ = stop => {
                    connection.as_mut().graceful_shutdown();
                    connection.await.unwrap();
                }
            }
        });
        let mut client = tokio::time::timeout(
            Duration::from_secs(5),
            AuthorizationClient::connect(format!("http://{address}")),
        )
        .await
        .unwrap()
        .unwrap();
        for (route, permitted) in [("permit", true), ("deny", false)] {
            let reply = tokio::time::timeout(
                Duration::from_secs(5),
                client.event_admit(EventRequest {
                    ip_addr: Some(route.to_owned()),
                    ..EventRequest::default()
                }),
            )
            .await
            .unwrap()
            .unwrap()
            .into_inner();
            assert_eq!(reply.permitted(), permitted);
            assert_eq!(AuthzDecision::message(&reply).as_deref(), Some("fixture"));
        }
        let status = tokio::time::timeout(
            Duration::from_secs(5),
            client.event_admit(EventRequest {
                ip_addr: Some("error".to_owned()),
                ..EventRequest::default()
            }),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert_eq!(status.message(), "blocked by policy");
        assert_eq!(status.details(), &[1]);
        assert_eq!(status.metadata().get("policy").unwrap().to_str().unwrap(), "deny");
        drop(client);
        shutdown.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), serving)
            .await
            .unwrap()
            .unwrap();
    }
}
