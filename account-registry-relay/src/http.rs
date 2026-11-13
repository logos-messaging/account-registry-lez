//! Submissions over HTTP: `POST /v1/submit` with a [`RelayRequest`] as the body, answered with a
//! [`RelayReply`] once the relay has checked it, and `GET /v1/status`.

use std::{
    io::Read,
    sync::mpsc::{self, Sender},
};

use account_registry_client::relay::{RelayReply, RelayRequest};
use serde_json::{Value, json};
use tiny_http::{Header, Method, Request, Response, Server};

use crate::relay::{Job, Submission};

/// A submission's largest body: a log at the registry's limit, in base64, with room to spare.
const MAX_BODY_BYTES: u64 = 128 * 1024;

/// Serves `server` until it fails, handing every submission to `jobs`.
pub fn serve(server: &Server, jobs: &Sender<Job>) {
    for mut request in server.incoming_requests() {
        let (status, body) = route(&mut request, jobs);
        let response = Response::from_data(serde_json::to_vec(&body).expect("a reply serializes"))
            .with_status_code(status)
            .with_header(
                Header::from_bytes("content-type", "application/json").expect("a valid header"),
            );
        let _gone = request.respond(response);
    }
}

fn route(request: &mut Request, jobs: &Sender<Job>) -> (u16, Value) {
    match (request.method(), request.url()) {
        (Method::Post, "/v1/submit") => {
            let (status, reply) = match body_of(request) {
                Ok(body) => submit(&body, jobs),
                Err(reason) => (413, refusal(reason)),
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
fn submit(body: &[u8], jobs: &Sender<Job>) -> (u16, RelayReply) {
    let request = match RelayRequest::from_bytes(body) {
        Ok(request) => request,
        Err(error) => return (400, refusal(error.to_string())),
    };
    let (reply, answer) = mpsc::channel();
    let submission = Submission {
        request,
        reply: Some(reply),
        source: "http",
    };
    if jobs.send(Job::Submit(submission)).is_err() {
        return (503, refusal("the relay is stopping".into()));
    }
    match answer.recv() {
        Ok(reply) if reply.accepted => (202, reply),
        Ok(reply) => (422, reply),
        Err(_) => (503, refusal("the relay is stopping".into())),
    }
}

fn status(jobs: &Sender<Job>) -> (u16, Value) {
    let (reply, answer) = mpsc::channel();
    if jobs.send(Job::Status(reply)).is_err() {
        return (503, json!({ "error": "the relay is stopping" }));
    }
    answer.recv().map_or_else(
        |_| (503, json!({ "error": "the relay is stopping" })),
        |status| (200, status),
    )
}

fn refusal(reason: String) -> RelayReply {
    RelayReply {
        accepted: false,
        reason: Some(reason),
    }
}

fn body_of(request: &mut Request) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    request
        .as_reader()
        .take(MAX_BODY_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|error| error.to_string())?;
    if body.len() as u64 > MAX_BODY_BYTES {
        return Err("the submission is too large".into());
    }
    Ok(body)
}
