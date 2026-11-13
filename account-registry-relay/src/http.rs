//! Submissions over HTTP: `POST /v1/submit` with a [`RelayRequest`] as the body, answered with a
//! [`RelayReply`] once the relay has checked it, and `GET /v1/status`.

use std::{
    io::Read,
    sync::mpsc::{self, SyncSender, TrySendError},
    thread,
};

use account_registry_client::relay::{RelayReply, RelayRequest};
use serde_json::{Value, json};
use tiny_http::{Header, Method, Request, Response, Server};

use crate::relay::{Job, ask, refusal};

/// A submission's largest body: a log at the registry's limit, in base64, with room to spare.
const MAX_BODY_BYTES: u64 = 128 * 1024;
/// Requests served at once.
const THREADS: usize = 8;

/// Serves `server` until it fails, handing every submission to `jobs`.
pub fn serve(server: &Server, jobs: &SyncSender<Job>) {
    thread::scope(|scope| {
        for _ in 0..THREADS {
            scope.spawn(|| {
                for mut request in server.incoming_requests() {
                    let (status, body) = route(&mut request, jobs);
                    let response =
                        Response::from_data(serde_json::to_vec(&body).expect("a reply serializes"))
                            .with_status_code(status)
                            .with_header(
                                Header::from_bytes("content-type", "application/json")
                                    .expect("a valid header"),
                            );
                    let _gone = request.respond(response);
                }
            });
        }
    });
}

fn route(request: &mut Request, jobs: &SyncSender<Job>) -> (u16, Value) {
    match (request.method(), request.url()) {
        (Method::Post, "/v1/submit") => {
            let (status, reply) = match body_of(request) {
                Ok(body) => submit(&body, jobs),
                Err((status, reason)) => (status, refusal(reason)),
            };
            (
                status,
                serde_json::to_value(reply).expect("a reply serializes"),
            )
        }
        (Method::Get, "/v1/status") => status(jobs),
        _ => (404, json!({ "error": "not found" })),
    }
}

/// The relay's answer to `body`, a submission.
fn submit(body: &[u8], jobs: &SyncSender<Job>) -> (u16, RelayReply) {
    let request = match RelayRequest::from_bytes(body) {
        Ok(request) => request,
        Err(error) => return (400, refusal(error.to_string())),
    };
    match ask(jobs, request, "http") {
        Ok(reply) if reply.accepted => (202, reply),
        Ok(reply) => (422, reply),
        Err(reason) => (503, refusal(reason)),
    }
}

fn status(jobs: &SyncSender<Job>) -> (u16, Value) {
    let (reply, answer) = mpsc::channel();
    match jobs.try_send(Job::Status(reply)) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => return (503, json!({ "error": "the relay is busy" })),
        Err(TrySendError::Disconnected(_)) => {
            return (503, json!({ "error": "the relay is stopping" }));
        }
    }
    answer.recv().map_or_else(
        |_| (503, json!({ "error": "the relay is stopping" })),
        |status| (200, status),
    )
}

fn body_of(request: &mut Request) -> Result<Vec<u8>, (u16, String)> {
    let mut body = Vec::new();
    request
        .as_reader()
        .take(MAX_BODY_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|error| (400, error.to_string()))?;
    if body.len() as u64 > MAX_BODY_BYTES {
        return Err((413, "the submission is too large".into()));
    }
    Ok(body)
}
