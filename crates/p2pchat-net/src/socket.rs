//! The node's UDP sockets: bound by the node, shared by QUIC and STUN — M13a,
//! `architecture.md` §3.
//!
//! A NAT's mapping belongs to one socket. STUN asked from any other socket
//! learns *that* socket's mapping, which says nothing about quinn's; a hole
//! punched from any other socket opens a port nothing listens on. So the node
//! binds the socket itself, quinn runs over it through [`Demux`], and STUN goes
//! out on it through [`StunChannel`].
//!
//! Inbound datagrams go one way or the other, never both. STUN is a datagram
//! whose first two bits are zero and which carries the magic cookie —
//! [`stun::is_stun`]. Every QUIC packet sets the fixed bit (0x40) of its first
//! byte, so none can pass that test — *provided* no peer is allowed to clear
//! it. RFC 9287 greasing does exactly that, and quinn offers it by default;
//! [`crate::node_endpoint`] turns it off, and with it off quinn also drops any
//! packet that arrives with the bit clear. Re-enabling it makes this demux
//! guess.

use std::future::poll_fn;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Runtime, UdpPoller};
use tokio::sync::{mpsc, Mutex};

use crate::stun;

/// STUN datagrams set aside and not yet read. Beyond this they are dropped:
/// STUN is lossy anyway, and a flood of cookie-bearing datagrams must not turn
/// into memory.
const STUN_QUEUE: usize = 32;

/// Binds `addr` once and returns quinn's side and STUN's side of that socket.
pub(crate) fn bind(addr: SocketAddr) -> io::Result<(Arc<dyn AsyncUdpSocket>, StunChannel)> {
    let socket = quinn::TokioRuntime.wrap_udp_socket(std::net::UdpSocket::bind(addr)?)?;
    let (stun, inbound) = mpsc::channel(STUN_QUEUE);
    let demux = Demux {
        socket: Arc::clone(&socket),
        stun,
    };
    let channel = StunChannel {
        socket,
        inbound: Mutex::new(inbound),
    };
    Ok((Arc::new(demux), channel))
}

/// quinn's view of the socket: everything but STUN.
#[derive(Debug)]
struct Demux {
    socket: Arc<dyn AsyncUdpSocket>,
    stun: mpsc::Sender<(Vec<u8>, SocketAddr)>,
}

impl AsyncUdpSocket for Demux {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Arc::clone(&self.socket).create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.socket.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let received = ready!(self.socket.poll_recv(cx, bufs, meta))?;
        for (buf, meta) in bufs.iter_mut().zip(meta.iter_mut()).take(received) {
            let from = meta.addr;
            // A `len` of zero is an entry quinn skips, so an all-STUN entry
            // needs no special case.
            meta.len = divert(&mut buf[..meta.len], meta.stride, |datagram| {
                // Full or closed: dropped. Never handed to quinn instead.
                let _ = self.stun.try_send((datagram.to_vec(), from));
            });
        }
        Poll::Ready(Ok(received))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    // The three below default to values that are wrong for the real socket
    // underneath — `max_receive_segments` most of all, since quinn sizes its
    // receive buffer from it and GRO fills that buffer.
    fn max_transmit_segments(&self) -> usize {
        self.socket.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.socket.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.socket.may_fragment()
    }
}

/// Hands every STUN datagram in `buf` to `to_stun` and packs the rest to the
/// front, returning how many bytes quinn still has.
///
/// `buf` holds several datagrams, `stride` bytes apart, when the OS coalesced
/// them (GRO). Each is judged on its own, and order is kept, so only the last
/// of what remains can be short — the shape quinn expects.
fn divert(buf: &mut [u8], stride: usize, mut to_stun: impl FnMut(&[u8])) -> usize {
    let mut kept = 0;
    let mut at = 0;
    while at < buf.len() {
        let end = (at + stride).min(buf.len());
        if stun::is_stun(&buf[at..end]) {
            to_stun(&buf[at..end]);
        } else {
            buf.copy_within(at..end, kept);
            kept += end - at;
        }
        at = end;
    }
    kept
}

/// STUN's view of the socket: sends on it, and reads what [`Demux`] set aside.
pub struct StunChannel {
    socket: Arc<dyn AsyncUdpSocket>,
    inbound: Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
}

impl stun::Datagrams for StunChannel {
    async fn send_to(&self, datagram: &[u8], to: SocketAddr) -> io::Result<()> {
        let transmit = Transmit {
            destination: to,
            ecn: None,
            contents: datagram,
            segment_size: None,
            src_ip: None,
        };
        let mut poller = Arc::clone(&self.socket).create_io_poller();
        poll_fn(|cx| loop {
            match self.socket.try_send(&transmit) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    ready!(poller.as_mut().poll_writable(cx))?;
                }
                sent => return Poll::Ready(sent),
            }
        })
        .await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        // `None` once the endpoint, and with it `Demux`, is gone.
        let (datagram, from) = self
            .inbound
            .lock()
            .await
            .recv()
            .await
            .ok_or(io::ErrorKind::NotConnected)?;
        let len = datagram.len().min(buf.len());
        buf[..len].copy_from_slice(&datagram[..len]);
        Ok((len, from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Binding Success header: first byte 0x01, magic cookie at 4..8.
    fn stun_datagram(fill: u8) -> Vec<u8> {
        let mut datagram = vec![0x01, 0x01, 0, 0, 0x21, 0x12, 0xA4, 0x42];
        datagram.extend_from_slice(&[fill; 12]);
        datagram
    }

    /// A QUIC short header (fixed bit set) that otherwise mimics STUN as
    /// closely as it can, cookie included. It must still go to quinn.
    fn quic_datagram(fill: u8) -> Vec<u8> {
        let mut datagram = stun_datagram(fill);
        datagram[0] = 0x41;
        datagram
    }

    /// Gate 2, at the boundary quinn reads from: in a GRO batch mixing the
    /// two, quinn's bytes are exactly the QUIC datagrams and STUN's are
    /// exactly the STUN ones.
    #[test]
    fn a_mixed_batch_splits_exactly() {
        let mut buf = [
            quic_datagram(1),
            stun_datagram(2),
            quic_datagram(3),
            stun_datagram(4),
        ]
        .concat();

        let mut diverted = Vec::new();
        let kept = divert(&mut buf, 20, |d| diverted.push(d.to_vec()));

        assert_eq!(&buf[..kept], [quic_datagram(1), quic_datagram(3)].concat());
        assert_eq!(diverted, vec![stun_datagram(2), stun_datagram(4)]);
    }

    /// The short last segment survives compaction still last.
    #[test]
    fn a_short_quic_tail_stays_the_tail() {
        let mut tail = quic_datagram(9);
        tail.truncate(12);
        let mut buf = [stun_datagram(1), quic_datagram(2), tail.clone()].concat();

        let kept = divert(&mut buf, 20, |_| {});

        assert_eq!(&buf[..kept], [quic_datagram(2), tail].concat());
    }

    #[test]
    fn a_datagram_too_short_for_a_stun_header_goes_to_quinn() {
        let mut buf = stun_datagram(0)[..19].to_vec();
        let mut diverted = 0;
        assert_eq!(divert(&mut buf, 19, |_| diverted += 1), 19);
        assert_eq!(diverted, 0);
    }
}
