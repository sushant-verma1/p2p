//! STUN (RFC 5389) binding requests and NAT mapping classification — M13,
//! `plan-v0.2.md`.
//!
//! Read-only. This module learns the node's reflexive address and how its NAT
//! maps outbound sessions, and reports both. Nothing here is wired into
//! dialling, invites, or address advertisement — that is M17 and M18.
//!
//! On a node it runs over the QUIC endpoint's own socket, through
//! [`crate::socket::StunChannel`] — M13a. The mapping it reports is then the
//! one quinn's traffic actually gets, which is the only one worth knowing.
//!
//! **Every byte [`parse_response`] touches arrives from a UDP socket with no
//! transport-level authentication under it.** That makes it attacker-controlled
//! in the same sense `architecture.md` §12 means it: bound every length before
//! using it, never allocate from a length field alone, reject unknown
//! comprehension-required attributes, never panic. A later refactor that
//! relaxes any of that quietly reopens the thing this module exists to close —
//! hold it to the same discipline as `p2pchat_core::frame`, not to a looser one
//! because the format is smaller.
//!
//! The transaction ID is the whole defence against an off-path spoofed reply:
//! see [`query`]. `techstack.md` records why this is hand-rolled rather than a
//! crate.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use rand::RngCore;
use thiserror::Error;
use tokio::net::UdpSocket;

// ---------------------------------------------------------------------------
// Wire format — RFC 5389 §6, §15
// ---------------------------------------------------------------------------

const MAGIC_COOKIE: u32 = 0x2112_A442;
const HEADER_LEN: usize = 20;

/// 96 bits, RFC 5389 §6.
pub const TRANSACTION_ID_LEN: usize = 12;

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const BINDING_ERROR: u16 = 0x0111;

const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

const FAMILY_IPV4: u8 = 0x01;
const FAMILY_IPV6: u8 = 0x02;

/// Comfortably larger than any STUN binding response a compliant server
/// sends. Bounds the receive buffer to a fixed stack array, so a hostile
/// datagram controls how much of it gets looked at, never how much gets
/// allocated.
const MAX_RESPONSE: usize = 1500;

#[derive(Debug, Error)]
pub enum StunError {
    #[error("sending or receiving: {0}")]
    Io(#[from] std::io::Error),
    /// No matching response before the deadline — `query`'s caller decides
    /// whether that is fatal. M13's own rule is that it never is: a server
    /// that times out is skipped, not fatal to the overall classification.
    #[error("no response within the timeout")]
    Timeout,
    #[error("malformed STUN response")]
    Malformed,
    /// RFC 5389 §7.3.3: an unrecognized attribute in the range that demands
    /// comprehension. The whole message is untrustworthy, not just the one
    /// attribute — this is the mutation-tested rejection path.
    #[error("comprehension-required attribute {0:#06x} was not understood")]
    UnknownAttribute(u16),
    #[error("the server returned a binding error")]
    ServerError,
    #[error("no mapped address in an otherwise well-formed response")]
    NoMappedAddress,
}

/// Builds a Binding Request with no attributes: header only, 20 bytes.
fn encode_request(transaction_id: [u8; TRANSACTION_ID_LEN]) -> [u8; HEADER_LEN] {
    let mut buf = [0u8; HEADER_LEN];
    buf[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    buf[2..4].copy_from_slice(&0u16.to_be_bytes());
    buf[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    buf[8..20].copy_from_slice(&transaction_id);
    buf
}

/// The transaction ID a datagram claims, or `None` if it is too short or does
/// not carry the magic cookie to even have one. Used to decide, before any
/// other parsing, whether a datagram is worth parsing at all.
fn claimed_transaction_id(datagram: &[u8]) -> Option<[u8; TRANSACTION_ID_LEN]> {
    let header = datagram.get(..HEADER_LEN)?;
    let cookie = u32::from_be_bytes(header[4..8].try_into().ok()?);
    if cookie != MAGIC_COOKIE {
        return None;
    }
    let mut id = [0u8; TRANSACTION_ID_LEN];
    id.copy_from_slice(&header[8..20]);
    Some(id)
}

/// Whether a datagram arriving on a socket shared with QUIC is STUN's — M13a,
/// [`crate::socket`]. The first two bits are zero in every STUN message and
/// set to `01` in every QUIC packet quinn will accept, so this cannot claim a
/// QUIC packet; the cookie narrows it further to what [`query`] could use.
pub(crate) fn is_stun(datagram: &[u8]) -> bool {
    datagram.first().is_some_and(|first| first & 0xC0 == 0)
        && claimed_transaction_id(datagram).is_some()
}

/// Parses a Binding Success Response already known to carry `expected`'s
/// transaction ID, returning the mapped address.
///
/// Every slice below comes from [`slice::get`], never indexing: a length that
/// runs past the end of `datagram` is an error, not a panic.
fn parse_response(
    datagram: &[u8],
    expected: [u8; TRANSACTION_ID_LEN],
) -> Result<SocketAddr, StunError> {
    let header = datagram.get(..HEADER_LEN).ok_or(StunError::Malformed)?;

    // RFC 5389 §6: the top two bits of the type are always zero.
    if header[0] & 0xC0 != 0 {
        return Err(StunError::Malformed);
    }
    let msg_type = u16::from_be_bytes([header[0], header[1]]);
    let msg_len = u16::from_be_bytes([header[2], header[3]]) as usize;

    if header[8..20] != expected {
        // Not reachable from `query`, which filters on this first — kept as
        // a second, independent check so this function is safe to call on
        // its own from a test or a future caller.
        return Err(StunError::Malformed);
    }

    match msg_type {
        BINDING_SUCCESS => {}
        BINDING_ERROR => return Err(StunError::ServerError),
        _ => return Err(StunError::Malformed),
    }

    // The declared attribute length is bounded against what actually arrived
    // before it is used for anything — the frame.rs discipline applied here.
    let body = datagram
        .get(HEADER_LEN..)
        .and_then(|body| body.get(..msg_len))
        .ok_or(StunError::Malformed)?;

    parse_attributes(body, expected)
}

fn parse_attributes(
    mut body: &[u8],
    transaction_id: [u8; TRANSACTION_ID_LEN],
) -> Result<SocketAddr, StunError> {
    let mut mapped = None;
    let mut xor_mapped = None;

    while !body.is_empty() {
        let header = body.get(..4).ok_or(StunError::Malformed)?;
        let attr_type = u16::from_be_bytes([header[0], header[1]]);
        let attr_len = u16::from_be_bytes([header[2], header[3]]) as usize;
        // Attributes are padded to a 4-byte boundary; the padding itself
        // carries no meaning and is skipped rather than validated.
        let padded_len = attr_len.div_ceil(4) * 4;

        let value = body.get(4..4 + attr_len).ok_or(StunError::Malformed)?;
        let rest = body.get(4 + padded_len..).ok_or(StunError::Malformed)?;

        match attr_type {
            ATTR_MAPPED_ADDRESS => mapped = Some(decode_address(value, None)?),
            ATTR_XOR_MAPPED_ADDRESS => {
                xor_mapped = Some(decode_address(value, Some(transaction_id))?)
            }
            // RFC 5389 §15: 0x0000-0x7FFF is comprehension-required. An
            // attribute in that range this parser does not understand means
            // the message may mean something this code cannot see, so the
            // whole response is rejected rather than the one attribute
            // skipped. 0x8000-0xFFFF is comprehension-optional and safe to
            // ignore. This is the boundary the "decode without the XOR"
            // mutation cannot touch, and the boundary M13's gate 4 mutation
            // ("only one server queried") does not exercise either — see
            // the module tests for why that gap is covered elsewhere.
            other if other & 0x8000 == 0 => return Err(StunError::UnknownAttribute(other)),
            _ => {}
        }

        body = rest;
    }

    xor_mapped.or(mapped).ok_or(StunError::NoMappedAddress)
}

/// Decodes a MAPPED-ADDRESS or XOR-MAPPED-ADDRESS value. `xor` is `Some` for
/// the latter — RFC 5389 §15.2 XORs the port against the top 16 bits of the
/// magic cookie and the address against the cookie (IPv4) or the cookie
/// followed by the transaction ID (IPv6).
fn decode_address(
    value: &[u8],
    xor: Option<[u8; TRANSACTION_ID_LEN]>,
) -> Result<SocketAddr, StunError> {
    let family = *value.get(1).ok_or(StunError::Malformed)?;
    let port_bytes = value.get(2..4).ok_or(StunError::Malformed)?;
    let mut port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
    if xor.is_some() {
        port ^= (MAGIC_COOKIE >> 16) as u16;
    }

    match family {
        FAMILY_IPV4 => {
            let raw = value.get(4..8).ok_or(StunError::Malformed)?;
            let mut octets = [raw[0], raw[1], raw[2], raw[3]];
            if xor.is_some() {
                let cookie = MAGIC_COOKIE.to_be_bytes();
                for (byte, mask) in octets.iter_mut().zip(cookie) {
                    *byte ^= mask;
                }
            }
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        FAMILY_IPV6 => {
            let raw = value.get(4..20).ok_or(StunError::Malformed)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(raw);
            if let Some(transaction_id) = xor {
                let cookie = MAGIC_COOKIE.to_be_bytes();
                for (byte, mask) in octets[..4].iter_mut().zip(cookie) {
                    *byte ^= mask;
                }
                for (byte, mask) in octets[4..].iter_mut().zip(transaction_id) {
                    *byte ^= mask;
                }
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => Err(StunError::Malformed),
    }
}

// ---------------------------------------------------------------------------
// Querying a server
// ---------------------------------------------------------------------------

/// What [`query`] needs from a socket: a plain `tokio` `UdpSocket`, or a
/// node's QUIC socket through [`crate::socket::StunChannel`].
pub trait Datagrams: Sync {
    fn send_to(
        &self,
        datagram: &[u8],
        to: SocketAddr,
    ) -> impl Future<Output = io::Result<()>> + Send;
    fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> impl Future<Output = io::Result<(usize, SocketAddr)>> + Send;
}

impl Datagrams for UdpSocket {
    async fn send_to(&self, datagram: &[u8], to: SocketAddr) -> io::Result<()> {
        UdpSocket::send_to(self, datagram, to).await.map(drop)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        UdpSocket::recv_from(self, buf).await
    }
}

/// Sends one Binding Request to `server` on `socket` and returns the mapped
/// address, or the reason none arrived.
///
/// The transaction ID is 96 bits from `OsRng`, generated fresh for this call.
/// A datagram whose claimed transaction ID does not match — including every
/// datagram that is not shaped like a STUN header at all — is discarded and
/// **not** treated as an answer; `query` keeps listening until a matching one
/// arrives or `request_timeout` elapses. This is the only check standing
/// between this node and an off-path attacker who spoofs a reply: treat it
/// with the same weight `agent.md` §3 gives the handshake's transcript check.
pub async fn query(
    socket: &impl Datagrams,
    server: SocketAddr,
    request_timeout: Duration,
) -> Result<SocketAddr, StunError> {
    let mut transaction_id = [0u8; TRANSACTION_ID_LEN];
    rand::rngs::OsRng.fill_bytes(&mut transaction_id);

    socket
        .send_to(&encode_request(transaction_id), server)
        .await?;

    let deadline = tokio::time::Instant::now() + request_timeout;
    let mut buf = [0u8; MAX_RESPONSE];
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(StunError::Timeout);
        }
        let (received, _from) =
            match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
                Ok(result) => result?,
                Err(_) => return Err(StunError::Timeout),
            };
        let datagram = &buf[..received];

        // Discarded, not treated as an answer: this is the whole defence
        // against an off-path spoofed reply, so it happens before anything
        // else about the datagram is trusted, including whether it parses.
        if claimed_transaction_id(datagram) != Some(transaction_id) {
            continue;
        }
        return parse_response(datagram, transaction_id);
    }
}

// ---------------------------------------------------------------------------
// Mapping classification
// ---------------------------------------------------------------------------

/// How this NAT (if any) assigns the external port for outbound UDP —
/// `plan-v0.2.md` M13, the property that decides whether M18's hole punching
/// can ever work on this connection.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mapping {
    /// The same reflexive address for every destination. Punching can work.
    EndpointIndependent,
    /// The reflexive address changed with the destination — address-dependent
    /// or address-and-port-dependent NAT, commonly called symmetric. No relay
    /// means punching never works here, and nothing downstream may treat this
    /// as a maybe.
    AddressOrPortDependent,
    /// Fewer than two independent servers answered, so there is no second
    /// observation to compare against the first. Reported instead of a guess.
    Unknown,
}

impl Mapping {
    /// Plain answer to the question this whole milestone exists to ask.
    pub fn punchable(self) -> bool {
        matches!(self, Self::EndpointIndependent)
    }
}

/// Classifies the mapping from the reflexive addresses independent servers
/// returned, in query order.
///
/// Never call this with the result of one server: a single answer cannot
/// distinguish "this NAT is endpoint-independent" from "this NAT is symmetric
/// and I got lucky." That is why the function's only inputs are the addresses
/// that *succeeded* — a caller that skips failed servers rather than padding
/// the list is what keeps this correct.
pub fn classify(reflexive: &[SocketAddr]) -> Mapping {
    match reflexive {
        [] | [_] => Mapping::Unknown,
        [first, rest @ ..] => {
            if rest.iter().all(|addr| addr == first) {
                Mapping::EndpointIndependent
            } else {
                Mapping::AddressOrPortDependent
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Multi-server discovery
// ---------------------------------------------------------------------------

/// Independent public STUN servers queried by default.
///
/// Three different organisations, not three addresses of one — classification
/// leans on that independence (`plan-v0.2.md` M13), and a single operator's
/// outage or misbehaviour must not be able to produce a classification by
/// itself. This is still a centralisation point worth naming plainly: these
/// three answer a large share of all STUN traffic on the internet, Google's
/// most of all, and nothing here changes that. It only refuses to lean on any
/// one of them *alone*.
pub const DEFAULT_SERVERS: &[(&str, &str)] = &[
    ("google", "stun.l.google.com:19302"),
    ("cloudflare", "stun.cloudflare.com:3478"),
    ("twilio", "global.stun.twilio.com:3478"),
];

/// Per-server budget. STUN is one UDP round trip; a server that has not
/// answered inside a few seconds is not going to.
pub const SERVER_TIMEOUT: Duration = Duration::from_secs(3);

/// One server's outcome, kept even on failure so the caller can report which
/// servers answered and which did not — a server that times out is skipped,
/// never fatal to the overall result.
pub struct Probe {
    pub label: &'static str,
    pub server: SocketAddr,
    pub result: Result<SocketAddr, StunError>,
}

/// Queries every server in turn, on the same socket, and returns every
/// outcome.
///
/// Sequential and not concurrent: `recv_from` on a shared socket has no way
/// to route an inbound datagram to "the task that is waiting for this one" —
/// two outstanding queries on the same socket would race for each other's
/// replies. STUN is a handful of round trips; there is nothing here worth
/// that risk to save.
pub async fn probe(
    socket: &impl Datagrams,
    servers: &[(&'static str, SocketAddr)],
    request_timeout: Duration,
) -> Vec<Probe> {
    let mut probes = Vec::with_capacity(servers.len());
    for &(label, server) in servers {
        let result = query(socket, server, request_timeout).await;
        probes.push(Probe {
            label,
            server,
            result,
        });
    }
    probes
}

/// The IP this host would use to reach `probe_target`, learned without
/// sending a packet: a UDP `connect` only consults the routing table to pick
/// a source address, it transmits nothing.
///
/// `None` if that lookup itself fails, which happens on a host with no route
/// at all — folded into "unknown" by [`discover`], never into a NAT guess.
pub fn local_outbound_ip(probe_target: SocketAddr) -> Option<IpAddr> {
    let bind: SocketAddr = match probe_target {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = std::net::UdpSocket::bind(bind).ok()?;
    socket.connect(probe_target).ok()?;
    socket.local_addr().ok().map(|addr| addr.ip())
}

/// Every server's outcome plus what they add up to.
pub struct Report {
    pub probes: Vec<Probe>,
    pub mapping: Mapping,
    /// `Some(true)`: the reflexive address equals a local address, so there
    /// is no NAT on this path at all. `Some(false)`: there is a NAT and it
    /// is endpoint-independent. `None`: the mapping is not
    /// `EndpointIndependent` — comparing addresses is moot once the servers
    /// already disagree — or the local address could not be determined.
    pub no_nat: Option<bool>,
}

/// Runs [`probe`] against `servers` and folds the results into a [`Report`]:
/// the classification from [`classify`], plus the no-NAT check requirement 3
/// asks for.
pub async fn discover(
    socket: &impl Datagrams,
    servers: &[(&'static str, SocketAddr)],
    request_timeout: Duration,
) -> Report {
    let probes = probe(socket, servers, request_timeout).await;
    let reflexive: Vec<SocketAddr> = probes
        .iter()
        .filter_map(|p| p.result.as_ref().ok().copied())
        .collect();
    let mapping = classify(&reflexive);

    let no_nat = match (mapping, reflexive.first()) {
        (Mapping::EndpointIndependent, Some(seen)) => servers
            .first()
            .and_then(|&(_, server)| local_outbound_ip(server))
            .map(|local| local == seen.ip()),
        _ => None,
    };

    Report {
        probes,
        mapping,
        no_nat,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::from(ip), port))
    }

    // -----------------------------------------------------------------------
    // Wire format
    // -----------------------------------------------------------------------

    /// Builds a Binding Success Response carrying one XOR-MAPPED-ADDRESS
    /// attribute for `mapped`, as a real server would send it: the value on
    /// the wire is XORed, not the value this test expects back.
    fn success_response(transaction_id: [u8; TRANSACTION_ID_LEN], mapped: SocketAddr) -> Vec<u8> {
        let SocketAddr::V4(mapped) = mapped else {
            panic!("test helper handles IPv4 only");
        };
        let cookie = MAGIC_COOKIE.to_be_bytes();
        let xor_port = mapped.port() ^ (MAGIC_COOKIE >> 16) as u16;
        let mut xor_addr = mapped.ip().octets();
        for (byte, mask) in xor_addr.iter_mut().zip(cookie) {
            *byte ^= mask;
        }

        let mut attr_value = vec![0u8, FAMILY_IPV4];
        attr_value.extend_from_slice(&xor_port.to_be_bytes());
        attr_value.extend_from_slice(&xor_addr);

        let mut msg = Vec::new();
        msg.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        // 4-byte attribute header + 8-byte value = 12.
        msg.extend_from_slice(&(12u16).to_be_bytes());
        msg.extend_from_slice(&cookie);
        msg.extend_from_slice(&transaction_id);
        msg.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        msg.extend_from_slice(&(attr_value.len() as u16).to_be_bytes());
        msg.extend_from_slice(&attr_value);
        msg
    }

    #[test]
    fn a_well_formed_response_decodes_to_the_address_it_carries() {
        let id = [7u8; TRANSACTION_ID_LEN];
        let expected = addr([203, 0, 113, 9], 47100);
        let response = success_response(id, expected);
        assert_eq!(parse_response(&response, id).unwrap(), expected);
    }

    /// Gate 1's mutation: decoding XOR-MAPPED-ADDRESS without applying the
    /// XOR must produce the wrong address, not the right one — otherwise the
    /// XOR step is untested. This computes what that mutant would return and
    /// checks it disagrees with the correct decode.
    #[test]
    fn skipping_the_xor_would_give_a_different_address_than_applying_it() {
        let id = [3u8; TRANSACTION_ID_LEN];
        let expected = addr([198, 51, 100, 4], 12345);
        let response = success_response(id, expected);

        let correct = parse_response(&response, id).unwrap();
        assert_eq!(correct, expected);

        // The un-XORed bytes, read directly off the wire the way a mutant
        // that forgot the XOR step would read them.
        let raw_port = u16::from_be_bytes([response[24], response[25]]);
        let raw_ip = Ipv4Addr::new(response[26], response[27], response[28], response[29]);
        let un_xored = SocketAddr::from((raw_ip, raw_port));
        assert_ne!(
            un_xored, correct,
            "the un-XORed and XORed readings must differ for this test to mean anything"
        );
    }

    /// Gate 5's mutation target, at the parser level: a response whose
    /// transaction ID does not match is rejected before anything else about
    /// it is trusted. [`query`]'s own test covers the "keep listening"
    /// behaviour end to end.
    #[test]
    fn a_mismatched_transaction_id_is_rejected() {
        let sent = [1u8; TRANSACTION_ID_LEN];
        let received = [2u8; TRANSACTION_ID_LEN];
        let response = success_response(received, addr([1, 2, 3, 4], 1));
        assert!(matches!(
            parse_response(&response, sent),
            Err(StunError::Malformed)
        ));
    }

    #[test]
    fn a_binding_error_response_is_reported_as_a_server_error() {
        let id = [9u8; TRANSACTION_ID_LEN];
        let mut msg = Vec::new();
        msg.extend_from_slice(&BINDING_ERROR.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(&id);
        assert!(matches!(
            parse_response(&msg, id),
            Err(StunError::ServerError)
        ));
    }

    #[test]
    fn an_unknown_comprehension_required_attribute_rejects_the_whole_message() {
        let id = [4u8; TRANSACTION_ID_LEN];
        let mut msg = Vec::new();
        msg.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        msg.extend_from_slice(&(8u16).to_be_bytes());
        msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(&id);
        // 0x0099 is unassigned and below 0x8000: comprehension-required.
        msg.extend_from_slice(&0x0099u16.to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes());
        msg.extend_from_slice(&[0u8; 4]);
        assert!(matches!(
            parse_response(&msg, id),
            Err(StunError::UnknownAttribute(0x0099))
        ));
    }

    #[test]
    fn an_unknown_comprehension_optional_attribute_is_ignored() {
        let id = [5u8; TRANSACTION_ID_LEN];
        let expected = addr([203, 0, 113, 9], 47100);
        let mut msg = success_response(id, expected);
        // Splice in a comprehension-optional attribute (top bit set) ahead of
        // the real one, and grow the declared message length to match.
        let extra_type = 0x8099u16.to_be_bytes();
        let extra_len = 4u16.to_be_bytes();
        let extra = [extra_type.as_slice(), &extra_len, &[0u8; 4]].concat();
        msg.splice(HEADER_LEN..HEADER_LEN, extra.iter().copied());
        let new_len = (msg.len() - HEADER_LEN) as u16;
        msg[2..4].copy_from_slice(&new_len.to_be_bytes());

        assert_eq!(parse_response(&msg, id).unwrap(), expected);
    }

    /// Gate 6: a length field is never trusted on its own. This attribute
    /// claims 65535 bytes of value and supplies none.
    #[test]
    fn an_attribute_length_with_nothing_behind_it_is_rejected_not_panicked() {
        let id = [6u8; TRANSACTION_ID_LEN];
        let mut msg = Vec::new();
        msg.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes());
        msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(&id);
        msg.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        msg.extend_from_slice(&0xFFFFu16.to_be_bytes());
        assert!(matches!(
            parse_response(&msg, id),
            Err(StunError::Malformed)
        ));
    }

    #[test]
    fn a_truncated_header_is_rejected_not_panicked() {
        for len in 0..HEADER_LEN {
            assert!(
                matches!(
                    parse_response(&vec![0u8; len], [0u8; TRANSACTION_ID_LEN]),
                    Err(StunError::Malformed)
                ),
                "{len} bytes was accepted as a header"
            );
        }
    }

    #[test]
    fn a_response_with_no_mapped_address_attribute_is_reported_as_such() {
        let id = [8u8; TRANSACTION_ID_LEN];
        let mut msg = Vec::new();
        msg.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(&id);
        assert!(matches!(
            parse_response(&msg, id),
            Err(StunError::NoMappedAddress)
        ));
    }

    // -----------------------------------------------------------------------
    // Classification
    // -----------------------------------------------------------------------

    #[test]
    fn zero_or_one_observation_is_unknown_never_a_guess() {
        assert_eq!(classify(&[]), Mapping::Unknown);
        assert_eq!(classify(&[addr([1, 2, 3, 4], 1)]), Mapping::Unknown);
    }

    #[test]
    fn agreeing_servers_are_endpoint_independent_and_punchable() {
        let same = addr([203, 0, 113, 9], 47100);
        let mapping = classify(&[same, same, same]);
        assert_eq!(mapping, Mapping::EndpointIndependent);
        assert!(mapping.punchable());
    }

    #[test]
    fn disagreeing_servers_are_address_or_port_dependent_and_never_punchable() {
        let mapping = classify(&[addr([203, 0, 113, 9], 47100), addr([203, 0, 113, 9], 47101)]);
        assert_eq!(mapping, Mapping::AddressOrPortDependent);
        assert!(!mapping.punchable());
    }

    #[test]
    fn one_disagreement_among_several_is_still_address_or_port_dependent() {
        let same = addr([203, 0, 113, 9], 47100);
        let mapping = classify(&[same, same, addr([203, 0, 113, 9], 47101)]);
        assert_eq!(mapping, Mapping::AddressOrPortDependent);
    }

    #[test]
    fn unknown_is_never_punchable_either() {
        assert!(!Mapping::Unknown.punchable());
    }

    // -----------------------------------------------------------------------
    // Gate 6: the parser must not panic on hostile input, not just the
    // malformed shapes picked by hand above.
    // -----------------------------------------------------------------------

    use proptest::prelude::*;

    proptest! {
        /// Coverage caveat, named rather than assumed away: a correct magic
        /// cookie is 1 in 2^32 and a matching transaction ID is 1 in 2^96, so
        /// this essentially never gets past the header check into the
        /// attribute loop. Kept anyway as the unstructured baseline; the
        /// generators below are what actually reach the loop, by construction
        /// rather than by luck.
        #[test]
        fn parse_response_never_panics_on_arbitrary_bytes(
            bytes in prop::collection::vec(any::<u8>(), 0..2048),
            expected in prop::array::uniform12(any::<u8>()),
        ) {
            let _ = parse_response(&bytes, expected);
        }

        /// Unlike the header, `parse_attributes` has no equivalent gate: any
        /// 4 bytes read as a length rejects immediately if it overruns
        /// `body`, and a uniform u16 over a 0..2048 buffer overruns it most
        /// of the time. This one reaches the interesting bound check often,
        /// though still by chance — the generators below make it certain.
        #[test]
        fn parse_attributes_never_panics_on_arbitrary_bytes(
            body in prop::collection::vec(any::<u8>(), 0..2048),
            transaction_id in prop::array::uniform12(any::<u8>()),
        ) {
            let _ = parse_attributes(&body, transaction_id);
        }
    }

    /// Wraps `body` (the attribute area) in an otherwise-correct Binding
    /// Success header, with the outer length field set honestly to
    /// `body.len()` — so every generator below is hostile only in the inner,
    /// attribute-level length it declares, which is the field `agent.md` §7
    /// warns a blind test can look like it covers without ever exercising.
    fn wrap_header(transaction_id: [u8; TRANSACTION_ID_LEN], body: &[u8]) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        msg.extend_from_slice(&(body.len() as u16).to_be_bytes());
        msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(transaction_id.as_slice());
        msg.extend_from_slice(body);
        msg
    }

    fn mapped_address_attribute(mapped: SocketAddr) -> Vec<u8> {
        let SocketAddr::V4(mapped) = mapped else {
            panic!("test helper handles IPv4 only");
        };
        let mut value = vec![0u8, FAMILY_IPV4];
        value.extend_from_slice(&mapped.port().to_be_bytes());
        value.extend_from_slice(&mapped.ip().octets());
        let mut attr = Vec::new();
        attr.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
        attr.extend_from_slice(&(value.len() as u16).to_be_bytes());
        attr.extend_from_slice(&value);
        attr
    }

    // -----------------------------------------------------------------------
    // Gate 6, structured: each generator below builds a header that always
    // passes the outer checks, so every single case it produces reaches
    // `parse_attributes` and lands on the specific hostile shape named in
    // its title — proven by construction, not by sampling luck the way the
    // arbitrary-bytes tests above are. This is the coverage check `agent.md`
    // §7 asks for: a fuzz test that never reaches the code it claims to test
    // is the `netem/tail.py` failure in a new place.
    // -----------------------------------------------------------------------

    proptest! {
        /// Overlong: the declared length is always strictly greater than the
        /// bytes actually supplied, by construction.
        #[test]
        fn an_overlong_declared_attribute_length_is_always_rejected(
            transaction_id in prop::array::uniform12(any::<u8>()),
            attr_type in prop_oneof![
                Just(ATTR_MAPPED_ADDRESS),
                Just(ATTR_XOR_MAPPED_ADDRESS),
                Just(0x8099u16),
            ],
            supplied in prop::collection::vec(any::<u8>(), 0..16),
            overshoot in 1u16..=2000,
        ) {
            let declared_len = supplied.len() as u16 + overshoot;
            let mut body = Vec::new();
            body.extend_from_slice(&attr_type.to_be_bytes());
            body.extend_from_slice(&declared_len.to_be_bytes());
            body.extend_from_slice(&supplied);

            let msg = wrap_header(transaction_id, &body);
            prop_assert!(matches!(
                parse_response(&msg, transaction_id),
                Err(StunError::Malformed)
            ));
        }

        /// Zero: an empty value for every attribute type this parser acts
        /// on, which must be handled as "too short to decode", never as an
        /// out-of-bounds read.
        #[test]
        fn a_zero_length_attribute_never_panics(
            transaction_id in prop::array::uniform12(any::<u8>()),
            attr_type in prop_oneof![
                Just(ATTR_MAPPED_ADDRESS),
                Just(ATTR_XOR_MAPPED_ADDRESS),
                Just(0x8099u16),
            ],
        ) {
            let mut body = Vec::new();
            body.extend_from_slice(&attr_type.to_be_bytes());
            body.extend_from_slice(&0u16.to_be_bytes());
            let msg = wrap_header(transaction_id, &body);
            let _ = parse_response(&msg, transaction_id);
        }

        /// Truncated: 1 to 3 bytes remain where a 4-byte attribute header is
        /// expected next — always too short to be one.
        #[test]
        fn a_truncated_attribute_header_is_always_rejected(
            transaction_id in prop::array::uniform12(any::<u8>()),
            leftover in prop::collection::vec(any::<u8>(), 1..4),
        ) {
            let msg = wrap_header(transaction_id, &leftover);
            prop_assert!(matches!(
                parse_response(&msg, transaction_id),
                Err(StunError::Malformed)
            ));
        }

        /// Overlapping: a first attribute whose length is not a multiple of
        /// 4 is followed by padding bytes crafted to resemble a plausible
        /// attribute header. A parser that advanced the cursor by the raw
        /// declared length instead of the padded length would read those
        /// padding bytes as the start of the next attribute and either
        /// misdecode or reject the real one that follows; this asserts the
        /// real, second attribute is always the one actually recovered.
        #[test]
        fn padding_crafted_to_look_like_a_header_never_derails_the_next_attribute(
            transaction_id in prop::array::uniform12(any::<u8>()),
            stub_len in 1u16..=3,
            padding in prop::array::uniform3(any::<u8>()),
            mapped_ip in prop::array::uniform4(any::<u8>()),
            mapped_port in any::<u16>(),
        ) {
            let mapped = addr(mapped_ip, mapped_port);

            let mut body = Vec::new();
            // Comprehension-optional and unknown, so it is ignored rather
            // than rejected — the only thing under test is where the cursor
            // lands afterward.
            body.extend_from_slice(&0x8099u16.to_be_bytes());
            body.extend_from_slice(&stub_len.to_be_bytes());
            body.extend_from_slice(&vec![0u8; stub_len as usize]);
            let padded = (stub_len as usize).div_ceil(4) * 4;
            body.extend_from_slice(&padding[..padded - stub_len as usize]);

            body.extend_from_slice(&mapped_address_attribute(mapped));

            let msg = wrap_header(transaction_id, &body);
            prop_assert_eq!(parse_response(&msg, transaction_id).unwrap(), mapped);
        }
    }
}
