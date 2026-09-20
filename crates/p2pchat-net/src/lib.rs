//! QUIC endpoints, public node, private node, sessions — `architecture.md` §3.
//!
//! M3 is the transport: certificates, endpoints, the channel binding, and M2's
//! frames carried over real streams. M4 adds [`handshake`], which carries
//! `architecture.md` §6 over it. The AEAD is M5.

#![forbid(unsafe_code)]

mod accept_any_server_cert;
pub mod handshake;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use quinn::{Connection, Endpoint, RecvStream, SendStream};
use rustls::crypto::CryptoProvider;
use thiserror::Error;

use p2pchat_core::frame::{decode, encode, frame_len, LENGTH_PREFIX};
use p2pchat_core::wire::WireType;

/// `architecture.md` §3: the label the 32 channel-binding bytes are exported
/// under. Both sides must use the same one or the M4 handshake never agrees.
pub const CHANNEL_BINDING_LABEL: &[u8] = b"p2pchat-v1-channel-binding";

/// Length of the channel binding, fixed by §6's transcript.
pub const CHANNEL_BINDING_LEN: usize = 32;

/// Which of the two endpoints this is — `architecture.md` §3.
///
/// The ALPN and the port travel together on purpose: they are the pair that
/// must not get crossed, and a misdirected connection should fail at the ALPN
/// rather than arrive somewhere confusing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NodeKind {
    /// Profile and connection requests. No authentication.
    Public,
    /// The conversation. Mutually authenticated by §6.
    Private,
}

impl NodeKind {
    pub const fn alpn(self) -> &'static [u8] {
        match self {
            Self::Public => b"p2pchat-pub/1",
            Self::Private => b"p2pchat-priv/1",
        }
    }

    pub const fn default_port(self) -> u16 {
        match self {
            Self::Public => 47100,
            Self::Private => 47101,
        }
    }

    /// The environment variable that overrides the port — `techstack.md`.
    /// Not a convenience: two nodes on one machine is how the integration
    /// tests work from here on.
    pub const fn port_env(self) -> &'static str {
        match self {
            Self::Public => "P2PCHAT_PUBLIC_PORT",
            Self::Private => "P2PCHAT_PRIVATE_PORT",
        }
    }

    /// The port to listen on: the override if it parses, the default
    /// otherwise. An unparseable override is reported and ignored rather than
    /// being a startup failure.
    pub fn port(self) -> u16 {
        match std::env::var(self.port_env()) {
            Ok(value) => value.parse().unwrap_or_else(|_| {
                tracing::warn!(env = self.port_env(), "port override is not a port number");
                self.default_port()
            }),
            Err(_) => self.default_port(),
        }
    }

    /// Every interface, on [`NodeKind::port`].
    pub fn listen_addr(self) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, self.port()))
    }
}

#[derive(Debug, Error)]
pub enum NetError {
    #[error("connection closed")]
    ConnectionClosed,

    /// `architecture.md` §6: the exchange did not finish inside
    /// [`handshake::HANDSHAKE_TIMEOUT`].
    #[error("handshake timed out")]
    HandshakeTimeout,

    /// `architecture.md` §3. Only reachable if the connection negotiated no
    /// TLS exporter at all, which QUIC does not permit.
    #[error("the connection exported no channel binding")]
    NoChannelBinding,

    #[error("generating the transport certificate: {0}")]
    Certificate(#[from] rcgen::Error),

    #[error("TLS configuration: {0}")]
    Tls(#[from] rustls::Error),

    /// `quinn` refuses a TLS config whose cipher suites cannot carry QUIC.
    #[error("TLS configuration is not usable for QUIC: {0}")]
    NotQuicCapable(#[from] quinn::crypto::rustls::NoInitialCipherSuite),

    #[error("opening connection: {0}")]
    Connect(#[from] quinn::ConnectError),

    #[error("connection: {0}")]
    Connection(#[from] quinn::ConnectionError),

    #[error("writing to stream: {0}")]
    Write(#[from] quinn::WriteError),

    #[error("reading from stream: {0}")]
    Read(#[from] quinn::ReadExactError),

    #[error("binding endpoint: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Crypto(#[from] p2pchat_crypto::CryptoError),

    #[error(transparent)]
    Core(#[from] p2pchat_core::CoreError),
}

/// `ring`, named in code rather than left to `rustls`'s default.
///
/// `rustls` 0.23 defaults to `aws-lc-rs`, which wants `cmake` and `nasm` and is
/// the worse half of the choice on the GNU toolchain. `techstack.md` says
/// `ring`; this function is what makes that true regardless of which features
/// a future dependency turns on. Every config in this crate is built from it,
/// so there is no process-wide default to install and nothing to race.
pub fn crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A listening endpoint with a fresh self-signed certificate.
///
/// The certificate is generated per run and carries no identity meaning
/// whatsoever — `architecture.md` §3, agent.md §3 invariant 11. Pass port 0 to
/// let the OS choose, which is what the tests do.
pub fn server_endpoint(addr: SocketAddr, kind: NodeKind) -> Result<Endpoint, NetError> {
    let certified = rcgen::generate_simple_self_signed(vec!["p2pchat".to_owned()])?;
    let cert = certified.cert.der().clone();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der());

    let mut crypto = rustls::ServerConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())?;
    crypto.alpn_protocols = vec![kind.alpn().to_vec()];

    let config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?,
    ));
    let endpoint = Endpoint::server(config, addr)?;
    tracing::info!(?kind, addr = %endpoint.local_addr()?, "listening");
    Ok(endpoint)
}

/// An endpoint that only dials, on an ephemeral port.
pub fn client_endpoint(kind: NodeKind) -> Result<Endpoint, NetError> {
    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
    endpoint.set_default_client_config(accept_any_server_cert::client_config(kind.alpn())?);
    Ok(endpoint)
}

/// Required by TLS and meaningless here: the certificate is not checked
/// against it, and identity comes from §6.
const SERVER_NAME: &str = "p2pchat";

/// Dial `addr`, offering the endpoint's ALPN.
pub async fn connect(endpoint: &Endpoint, addr: SocketAddr) -> Result<Connection, NetError> {
    Ok(endpoint.connect(addr, SERVER_NAME)?.await?)
}

/// The 32 bytes both sides mix into the §6 transcript.
///
/// Identical on the two ends of one connection, different on every other
/// connection. That second half is what makes it a relay defence: an attacker
/// who terminates one QUIC connection and opens another to the real peer holds
/// two different bindings and cannot produce a signature that verifies on both.
pub fn channel_binding(connection: &Connection) -> Result<[u8; CHANNEL_BINDING_LEN], NetError> {
    let mut binding = [0u8; CHANNEL_BINDING_LEN];
    connection
        .export_keying_material(&mut binding, CHANNEL_BINDING_LABEL, &[])
        .map_err(|_| NetError::NoChannelBinding)?;
    Ok(binding)
}

/// Writes one length-delimited frame — `architecture.md` §5.
pub async fn send_frame<T: WireType>(stream: &mut SendStream, value: &T) -> Result<(), NetError> {
    let mut buf = Vec::new();
    encode(value, &mut buf)?;
    stream.write_all(&buf).await?;
    Ok(())
}

/// Reads one length-delimited frame.
///
/// QUIC delivers a stream, not messages: a frame can arrive split across any
/// number of reads, and two frames can arrive in one. The length prefix is
/// what recovers the boundaries, and it is checked against `MAX_FRAME_SIZE`
/// *before* the body buffer is allocated — a peer announcing four gigabytes
/// gets an error, not an allocation.
pub async fn recv_frame<T: WireType>(stream: &mut RecvStream) -> Result<T, NetError> {
    let mut prefix = [0u8; LENGTH_PREFIX];
    stream.read_exact(&mut prefix).await?;
    let mut body = vec![0u8; frame_len(prefix)?];
    stream.read_exact(&mut body).await?;
    Ok(decode(&body)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_endpoints_do_not_share_an_alpn_or_a_port() {
        assert_eq!(NodeKind::Public.alpn(), b"p2pchat-pub/1");
        assert_eq!(NodeKind::Private.alpn(), b"p2pchat-priv/1");
        assert_eq!(NodeKind::Public.default_port(), 47100);
        assert_eq!(NodeKind::Private.default_port(), 47101);
    }
}
