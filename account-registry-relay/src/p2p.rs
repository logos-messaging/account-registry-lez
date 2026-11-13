//! Submissions over libp2p: one request and one reply on `/logos/accounts/relay/1.0.0`, as Logos
//! Core's `libp2p_module` sends them with `protocolRequest`. That is how the RLN membership
//! allocation service is reached too, and unlike Logos Delivery it needs no RLN membership.
//!
//! The request is a [`RelayRequest`] and the reply a [`RelayReply`], both as JSON, each framed by
//! an unsigned-varint length. The client does not close its side before reading the reply, so a
//! request is read by its length, never to the end of the stream. The connection is TCP with
//! Noise and mplex, the only muxer `libp2p_module` offers over TCP.

use std::{
    fs, io,
    path::Path,
    sync::mpsc::{self, Sender},
    time::Duration,
};

use account_registry_client::relay::{RelayReply, RelayRequest};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, StreamExt};
use libp2p::{
    Multiaddr, StreamProtocol, Swarm, identify,
    identity::{Keypair, secp256k1},
    noise, ping,
    request_response::{self, ProtocolSupport},
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp,
};

use crate::relay::{Job, Submission};

/// The relay's protocol.
pub const PROTOCOL: &str = "/logos/accounts/relay/1.0.0";

/// A submission's largest frame: a log at the registry's limit, in base64, with room to spare.
const MAX_FRAME_BYTES: usize = 128 * 1024;
/// How long one submission may take, from reading it to writing the reply.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(NetworkBehaviour)]
struct Behaviour {
    relay: request_response::Behaviour<FramedJson>,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
}

/// One varint-framed message each way.
#[derive(Clone, Default)]
struct FramedJson;

#[async_trait::async_trait]
impl request_response::Codec for FramedJson {
    type Protocol = StreamProtocol;
    type Request = Vec<u8>;
    type Response = Vec<u8>;

    async fn read_request<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_frame(io).await
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_frame(io).await
    }

    async fn write_request<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        request: Vec<u8>,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(io, &request).await
    }

    async fn write_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        response: Vec<u8>,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(io, &response).await?;
        io.close().await
    }
}

async fn read_frame<T: AsyncRead + Unpin>(io: &mut T) -> io::Result<Vec<u8>> {
    let mut length: usize = 0;
    for shift in (0..).step_by(7).take(10) {
        let mut byte = [0u8];
        io.read_exact(&mut byte).await?;
        length |= usize::from(byte[0] & 0x7f) << shift;
        if byte[0] & 0x80 == 0 {
            if length > MAX_FRAME_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "frame too large",
                ));
            }
            let mut frame = vec![0; length];
            io.read_exact(&mut frame).await?;
            return Ok(frame);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "length prefix too long",
    ))
}

async fn write_frame<T: AsyncWrite + Unpin>(io: &mut T, frame: &[u8]) -> io::Result<()> {
    let mut prefix = Vec::with_capacity(10);
    let mut length = frame.len();
    loop {
        let byte = (length & 0x7f) as u8;
        length >>= 7;
        if length == 0 {
            prefix.push(byte);
            break;
        }
        prefix.push(byte | 0x80);
    }
    io.write_all(&[prefix.as_slice(), frame].concat()).await?;
    io.flush().await
}

/// The relay's libp2p identity, kept in `dir`: a secp256k1 key, as `libp2p_module` nodes and the
/// allocation service use, made on first start. Its peer id is what clients pin.
pub fn identity(dir: &Path) -> io::Result<Keypair> {
    fs::create_dir_all(dir)?;
    let path = dir.join("node_key.hex");
    match fs::read_to_string(&path) {
        Ok(text) => {
            let bytes = hex::decode(text.trim()).map_err(io::Error::other)?;
            Keypair::from_protobuf_encoding(&bytes).map_err(io::Error::other)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let key = Keypair::from(secp256k1::Keypair::generate());
            let encoded = key.to_protobuf_encoding().map_err(io::Error::other)?;
            fs::write(&path, hex::encode(encoded))?;
            Ok(key)
        }
        Err(error) => Err(error),
    }
}

/// Serves the relay protocol on `listen` until the worker is gone.
pub fn serve(key: Keypair, listen: Multiaddr, jobs: &Sender<Job>) -> Result<(), String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?
        .block_on(run(key, listen, jobs.clone()))
}

async fn run(key: Keypair, listen: Multiaddr, jobs: Sender<Job>) -> Result<(), String> {
    let mut swarm = swarm(key)?;
    swarm.listen_on(listen).map_err(|error| error.to_string())?;
    let (replies, mut ready) = tokio::sync::mpsc::unbounded_channel();
    loop {
        tokio::select! {
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    eprintln!("p2p: listening on {address}, peer {}", swarm.local_peer_id());
                }
                SwarmEvent::Behaviour(BehaviourEvent::Relay(request_response::Event::Message {
                    message: request_response::Message::Request { request, channel, .. },
                    ..
                })) => {
                    let jobs = jobs.clone();
                    let replies = replies.clone();
                    tokio::task::spawn_blocking(move || {
                        let reply = answer(&request, &jobs);
                        let _gone = replies.send((channel, reply));
                    });
                }
                SwarmEvent::Behaviour(BehaviourEvent::Relay(
                    request_response::Event::InboundFailure { peer, error, .. },
                )) => eprintln!("p2p: request from {peer} failed: {error}"),
                _ => {}
            },
            Some((channel, reply)) = ready.recv() => {
                let bytes = serde_json::to_vec(&reply).expect("a reply serializes");
                if swarm.behaviour_mut().relay.send_response(channel, bytes).is_err() {
                    eprintln!("p2p: the requester left before the reply");
                }
            }
        }
    }
}

fn swarm(key: Keypair) -> Result<Swarm<Behaviour>, String> {
    let identify = identify::Config::new("/logos/accounts/relay/1.0.0".into(), key.public())
        .with_agent_version(format!("account-relay/{}", env!("CARGO_PKG_VERSION")));
    let relay = request_response::Behaviour::new(
        [(StreamProtocol::new(PROTOCOL), ProtocolSupport::Inbound)],
        request_response::Config::default().with_request_timeout(REQUEST_TIMEOUT),
    );
    Ok(libp2p::SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            libp2p_mplex::Config::default,
        )
        .map_err(|error| error.to_string())?
        .with_behaviour(|_| Behaviour {
            relay,
            identify: identify::Behaviour::new(identify),
            ping: ping::Behaviour::default(),
        })
        .map_err(|error| error.to_string())?
        .with_swarm_config(|config| config.with_idle_connection_timeout(IDLE_TIMEOUT))
        .build())
}

/// The relay's answer to `request`, a submission.
fn answer(request: &[u8], jobs: &Sender<Job>) -> RelayReply {
    let request = match RelayRequest::from_bytes(request) {
        Ok(request) => request,
        Err(error) => return refusal(error.to_string()),
    };
    let (reply, answer) = mpsc::channel();
    let submission = Submission {
        request,
        reply: Some(reply),
        source: "p2p",
    };
    if jobs.send(Job::Submit(submission)).is_err() {
        return refusal("the relay is stopping".into());
    }
    answer
        .recv()
        .unwrap_or_else(|_| refusal("the relay is stopping".into()))
}

fn refusal(reason: String) -> RelayReply {
    RelayReply {
        accepted: false,
        reason: Some(reason),
    }
}

#[cfg(test)]
mod tests {
    use futures::io::Cursor;

    use super::*;

    #[test]
    fn a_frame_round_trips() {
        futures::executor::block_on(async {
            for size in [0, 1, 127, 128, 300, 70_000] {
                let frame = vec![7u8; size];
                let mut wire = Cursor::new(Vec::new());
                write_frame(&mut wire, &frame).await.unwrap();
                let mut wire = Cursor::new(wire.into_inner());
                assert_eq!(read_frame(&mut wire).await.unwrap(), frame);
            }
        });
    }

    #[test]
    fn a_frame_over_the_limit_is_refused() {
        futures::executor::block_on(async {
            let mut wire = Cursor::new(Vec::new());
            write_frame(&mut wire, &vec![0; MAX_FRAME_BYTES + 1])
                .await
                .unwrap();
            let mut wire = Cursor::new(wire.into_inner());
            assert!(read_frame(&mut wire).await.is_err());
        });
    }

    #[test]
    fn a_short_length_prefix_is_read_as_libp2p_writes_it() {
        futures::executor::block_on(async {
            let mut wire = Cursor::new(vec![0x03, b'a', b'b', b'c', 0xff]);
            assert_eq!(read_frame(&mut wire).await.unwrap(), b"abc");
        });
    }
}
