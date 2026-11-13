//! Submissions over Logos Delivery, through a `logosdeliverynode`'s Messaging API REST endpoint.
//!
//! The node keeps the subscription's history across restarts and backfills from Store, but
//! forgets the subscription itself, so it is renewed whenever the node seems to have restarted.
//! A message may arrive more than once; the relay's checks make a repeat free.

use std::{
    collections::{HashSet, VecDeque},
    sync::mpsc::Sender,
    thread,
    time::Duration,
};

use account_registry_client::relay::{RELAY_CONTENT_TOPIC, RelayRequest};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;

use crate::relay::{Job, Submission};

const POLL_INTERVAL: Duration = Duration::from_secs(1);
const RETRY_INTERVAL: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// How many message hashes to remember, to skip a repeat before it reaches the worker.
const SEEN: usize = 4096;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Received {
    message_hash: String,
    message: Message,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Message {
    payload: String,
    content_topic: String,
}

/// Hands every submission on the relay topic that the node at `rest` receives to `jobs`, until
/// the worker is gone.
pub fn listen(rest: &str, jobs: &Sender<Job>) {
    let rest = rest.trim_end_matches('/').to_owned();
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(REQUEST_TIMEOUT))
        .build()
        .into();
    let mut seen = Seen::default();
    loop {
        if let Err(error) = subscribe(&agent, &rest) {
            eprintln!("delivery: subscribing at {rest}: {error}; retrying");
            thread::sleep(RETRY_INTERVAL);
            continue;
        }
        eprintln!("delivery: listening on {RELAY_CONTENT_TOPIC} through {rest}");
        loop {
            let received = match poll(&agent, &rest) {
                Ok(received) => received,
                Err(error) => {
                    eprintln!("delivery: polling {rest}: {error}; subscribing again");
                    thread::sleep(RETRY_INTERVAL);
                    break;
                }
            };
            for item in received {
                if item.message.content_topic != RELAY_CONTENT_TOPIC
                    || !seen.insert(item.message_hash)
                {
                    continue;
                }
                let Some(request) = STANDARD
                    .decode(&item.message.payload)
                    .ok()
                    .and_then(|bytes| RelayRequest::from_bytes(&bytes).ok())
                else {
                    eprintln!("delivery: skipped a message that is not a submission");
                    continue;
                };
                let submission = Submission {
                    request,
                    reply: None,
                    source: "delivery",
                };
                if jobs.send(Job::Submit(submission)).is_err() {
                    return;
                }
            }
            thread::sleep(POLL_INTERVAL);
        }
    }
}

fn subscribe(agent: &ureq::Agent, rest: &str) -> Result<(), ureq::Error> {
    agent
        .post(format!("{rest}/messaging/v1/subscriptions"))
        .send_json([RELAY_CONTENT_TOPIC])?;
    Ok(())
}

fn poll(agent: &ureq::Agent, rest: &str) -> Result<Vec<Received>, ureq::Error> {
    agent
        .get(format!("{rest}/messaging/v1/events/received"))
        .call()?
        .body_mut()
        .read_json()
}

/// The most recent message hashes.
#[derive(Default)]
struct Seen {
    order: VecDeque<String>,
    set: HashSet<String>,
}

impl Seen {
    /// Whether `hash` is new; remembers it either way.
    fn insert(&mut self, hash: String) -> bool {
        if !self.set.insert(hash.clone()) {
            return false;
        }
        self.order.push_back(hash);
        if self.order.len() > SEEN {
            let oldest = self.order.pop_front().expect("not empty");
            self.set.remove(&oldest);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_repeat_is_skipped_and_old_hashes_are_forgotten() {
        let mut seen = Seen::default();
        assert!(seen.insert("a".into()));
        assert!(!seen.insert("a".into()));
        for i in 0..SEEN {
            seen.insert(i.to_string());
        }
        assert!(seen.insert("a".into()));
    }

    #[test]
    fn a_received_event_decodes() {
        let json = r#"[{"seq":1,"messageHash":"0xab","message":{"payload":"e30=","contentTopic":"/x/1/y/json","version":0,"timestamp":1,"ephemeral":false},"source":"live"}]"#;
        let received: Vec<Received> = serde_json::from_str(json).unwrap();
        assert_eq!(received[0].message_hash, "0xab");
        assert_eq!(received[0].message.payload, "e30=");
    }
}
