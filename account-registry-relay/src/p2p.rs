//! Submissions over libp2p: one request and one reply on `/logos/accounts/relay/1.0.0`, as Logos
//! Core's `libp2p_module` sends them with `protocolRequest`. That is how the RLN membership
//! allocation service is reached too.
//!
//! The request is a [`RelayRequest`] and the reply a [`RelayReply`], both as JSON, each framed by
//! an unsigned-varint length. The client does not close its side before reading the reply, so a
//! request is read by its length, never to the end of the stream. The connection is TCP with
//! Noise and mplex, the only muxer `libp2p_module` offers over TCP.

use std::{
    fs, io,
    path::Path,
    sync::{Arc, mpsc::SyncSender},
    time::Duration,
};

use account_registry_client::relay::{RelayReply, RelayRequest};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, StreamExt};
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm, identify,
    identity::{Keypair, secp256k1},
    noise, ping,
    request_response::{self, ProtocolSupport},
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp,
};

use crate::{
    metrics::Metrics,
    relay::{Reason, Refusal, Submission, ask},
    transport::Transport,
};

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
    for shift in (0..).step_by(7).take(3) {
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
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            io::Write::write_all(&mut options.open(&path)?, hex::encode(encoded).as_bytes())?;
            Ok(key)
        }
        Err(error) => Err(error),
    }
}

/// The libp2p transport: serves the relay protocol on `listen` as `key`'s peer.
pub struct P2p {
    key: Keypair,
    listen: Multiaddr,
    metrics: Arc<Metrics>,
}

impl P2p {
    #[must_use]
    pub const fn new(key: Keypair, listen: Multiaddr, metrics: Arc<Metrics>) -> Self {
        Self {
            key,
            listen,
            metrics,
        }
    }
}

impl Transport for P2p {
    fn name(&self) -> &'static str {
        "p2p"
    }

    fn serve(self: Box<Self>, jobs: SyncSender<Submission>) -> Result<(), String> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| error.to_string())?
            .block_on(run(*self, jobs))
    }
}

async fn run(p2p: P2p, jobs: SyncSender<Submission>) -> Result<(), String> {
    let P2p {
        key,
        listen,
        metrics,
    } = p2p;
    let mut swarm = swarm(key, ProtocolSupport::Inbound)?;
    swarm.listen_on(listen).map_err(|error| error.to_string())?;
    let (replies, mut ready) = tokio::sync::mpsc::unbounded_channel();
    loop {
        tokio::select! {
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    eprintln!("p2p: listening on {address}, peer {}", swarm.local_peer_id());
                }
                SwarmEvent::ConnectionEstablished { .. } => {
                    metrics.connections.inc();
                }
                SwarmEvent::ConnectionClosed { .. } => {
                    metrics.connections.dec();
                }
                SwarmEvent::Behaviour(BehaviourEvent::Relay(request_response::Event::Message {
                    message: request_response::Message::Request { request, channel, .. },
                    ..
                })) => {
                    let jobs = jobs.clone();
                    let metrics = metrics.clone();
                    let replies = replies.clone();
                    tokio::task::spawn_blocking(move || {
                        let reply = answer(&request, &jobs, &metrics);
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

fn swarm(key: Keypair, support: ProtocolSupport) -> Result<Swarm<Behaviour>, String> {
    let identify = identify::Config::new(PROTOCOL.into(), key.public())
        .with_agent_version(format!("account-relay/{}", env!("CARGO_PKG_VERSION")));
    let relay = request_response::Behaviour::new(
        [(StreamProtocol::new(PROTOCOL), support)],
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
fn answer(request: &[u8], jobs: &SyncSender<Submission>, metrics: &Metrics) -> RelayReply {
    match RelayRequest::from_bytes(request) {
        Ok(request) => ask(jobs, metrics, request, "p2p"),
        Err(error) => {
            metrics.refused("p2p", Reason::Invalid);
            Refusal::new(Reason::Invalid, error.to_string()).reply()
        }
    }
}

/// Sends `request` to the relay `peer` at `addr`, as `libp2p_module` does, and returns its
/// answer. For tools and tests; the Accounts app goes through `libp2p_module` itself.
pub fn submit(peer: PeerId, addr: Multiaddr, request: &RelayRequest) -> Result<RelayReply, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?
        .block_on(async {
            let key = Keypair::from(secp256k1::Keypair::generate());
            let mut swarm = swarm(key, ProtocolSupport::Outbound)?;
            swarm.behaviour_mut().relay.send_request_with_addresses(
                &peer,
                request.to_bytes(),
                vec![addr],
            );
            loop {
                match swarm.select_next_some().await {
                    SwarmEvent::Behaviour(BehaviourEvent::Relay(
                        request_response::Event::Message {
                            message: request_response::Message::Response { response, .. },
                            ..
                        },
                    )) => {
                        return serde_json::from_slice(&response).map_err(|error| {
                            format!("the relay answered something else: {error}")
                        });
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Relay(
                        request_response::Event::OutboundFailure { error, .. },
                    )) => return Err(error.to_string()),
                    _ => {}
                }
            }
        })
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
