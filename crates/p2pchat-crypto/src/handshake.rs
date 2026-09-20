//! The three-message mutually-authenticated handshake — `architecture.md` §6.
//!
//! No I/O here. Each side is a small state machine that takes the peer's
//! message and hands back the next one, which is what makes every failure in
//! §6 reachable from a unit test without a socket. `p2pchat-net::handshake`
//! carries the messages and owns the 10-second deadline.
//!
//! Two things this module exists to get right:
//!
//! - **The transcript covers the channel binding.** Without it, an attacker who
//!   terminates one QUIC connection and opens another to the real peer relays
//!   three messages and ends up inside the session. With it, the two sides sign
//!   over different bytes and the signature fails. This is defect 1's fix and
//!   the reason `p2pchat-net` exports keying material at all.
//! - **Nothing tells the peer *why* it was rejected.** Every path out is
//!   [`CryptoError::Handshake`]. The detail goes to the local log, keyed by
//!   fingerprint, because a peer that learns which check failed has an oracle.

use ed25519_dalek::VerifyingKey;
use p2pchat_core::wire::{
    self, HelloConfirm, HelloInit, HelloResp, HelloRespUnsigned, Signature, WireType, NONCE_LEN,
    PROTOCOL_VERSION,
};
use p2pchat_core::UserId;
use rand::RngCore;
use subtle::ConstantTimeEq;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

use crate::identity::{derive_user_id, Identity};
use crate::CryptoError;

/// Domain separator the transcript opens with — `architecture.md` §6.
pub const HANDSHAKE_DOMAIN: &[u8] = b"p2pchat-v1-handshake";

/// Which side of the handshake this was.
///
/// §7 names its two keys `k_i2r` and `k_r2i`, so every send and receive has to
/// know which end it is. That answer is fixed the moment the handshake
/// finishes and is carried here, rather than passed as a `bool` by whoever
/// happens to call [`crate::SessionCipher::derive`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Initiator,
    Responder,
}

/// Everything M4 produces. [`crate::SessionCipher::derive`] turns it into the
/// two directional keys and consumes it, which is what zeroizes the shared
/// secret once HKDF has read it.
pub struct Session {
    shared_secret: Zeroizing<[u8; 32]>,
    transcript_hash: [u8; 32],
    peer_user_id: UserId,
    peer_identity_pk: [u8; 32],
    role: Role,
}

impl Session {
    /// The X25519 output. HKDF's IKM, and nothing else.
    pub fn shared_secret(&self) -> &Zeroizing<[u8; 32]> {
        &self.shared_secret
    }

    /// The transcript hash at the point `sig_i` is computed over: after
    /// `sig_r`, before `sig_i`. Both sides reach the same 32 bytes, which is
    /// what makes it usable as HKDF's salt.
    pub fn transcript_hash(&self) -> &[u8; 32] {
        &self.transcript_hash
    }

    /// Verified: it binds to [`Session::peer_identity_pk`] by check 2, and
    /// matched the expected peer by check 3 where there was one.
    pub fn peer_user_id(&self) -> UserId {
        self.peer_user_id
    }

    pub fn peer_identity_pk(&self) -> [u8; 32] {
        self.peer_identity_pk
    }

    /// Which end we were. Decides which derived key sends and which receives.
    pub fn role(&self) -> Role {
        self.role
    }
}

/// The peer's fingerprint and nothing else. No derive: one of these fields is
/// a key, and the other two are things a log line has no business carrying.
impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Session(peer {})", self.peer_user_id)
    }
}

// ---------------------------------------------------------------------------
// Initiator
// ---------------------------------------------------------------------------

/// The initiator between sending `HELLO_INIT` and receiving `HELLO_RESP`.
pub struct Initiator<'a> {
    identity: &'a Identity,
    transcript: Transcript,
    eph_sk: EphemeralSecret,
    expected_peer: Option<UserId>,
}

impl<'a> Initiator<'a> {
    /// `HELLO_INIT`, and the state needed to finish.
    ///
    /// `expected_peer` is the user ID from the invite blob when this is an
    /// outbound connection to someone known. `None` means "whoever answers",
    /// which disables check 3 — see the warning on [`Initiator::finish`].
    pub fn start(
        identity: &'a Identity,
        channel_binding: &[u8; 32],
        expected_peer: Option<UserId>,
    ) -> Result<(Self, HelloInit), CryptoError> {
        let eph_sk = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let hello = HelloInit {
            version: PROTOCOL_VERSION,
            user_id_i: identity.user_id(),
            identity_pk_i: identity.identity_pk(),
            eph_pk_i: PublicKey::from(&eph_sk).to_bytes(),
            nonce_i: nonce(),
        };

        let mut transcript = Transcript::new(channel_binding);
        transcript.absorb(&hello)?;

        Ok((
            Self {
                identity,
                transcript,
                eph_sk,
                expected_peer,
            },
            hello,
        ))
    }

    /// Checks 1 to 5 against `HELLO_RESP`, then the DH and `HELLO_CONFIRM`.
    ///
    /// Check 3 — `user_id_r` is the peer that was expected — is the one that
    /// makes the invite blob mean anything. Skipping it on an outbound
    /// connection means authenticating *somebody*, which is not authentication.
    pub fn finish(self, resp: &HelloResp) -> Result<(Session, HelloConfirm), CryptoError> {
        let unsigned = &resp.unsigned;
        let peer = Peer::check(
            unsigned.version,
            unsigned.user_id_r,
            &unsigned.identity_pk_r,
        )?;

        // Check 3.
        if let Some(expected) = self.expected_peer {
            if !ct_eq(&peer.user_id, &expected) {
                return Err(reject("peer is not the expected user", &peer.user_id));
            }
        }

        let mut transcript = self.transcript;
        transcript.absorb(unsigned)?;

        // Check 4: `sig_r` covers everything up to and including `HELLO_RESP`'s
        // unsigned fields — and therefore the channel binding.
        if !verify(&peer.key, &transcript.hash(), &resp.sig_r) {
            return Err(reject("HELLO_RESP signature", &peer.user_id));
        }

        // Check 5.
        let shared_secret = dh(self.eph_sk, &unsigned.eph_pk_r, &peer.user_id)?;

        transcript.absorb_signature(&resp.sig_r);
        let transcript_hash = transcript.hash();
        let confirm = HelloConfirm {
            sig_i: self.identity.sign(&transcript_hash),
        };

        Ok((
            Session {
                shared_secret,
                transcript_hash,
                peer_user_id: peer.user_id,
                peer_identity_pk: unsigned.identity_pk_r,
                role: Role::Initiator,
            },
            confirm,
        ))
    }
}

// ---------------------------------------------------------------------------
// Responder
// ---------------------------------------------------------------------------

/// The responder between sending `HELLO_RESP` and receiving `HELLO_CONFIRM`.
///
/// The DH has already happened by this point — it is check 5 on the
/// initiator's ephemeral key, and doing it on receipt is what lets a
/// small-order key be refused before anything is sent back. The shared secret
/// is held here and discarded with the state if `HELLO_CONFIRM` fails.
pub struct Responder {
    shared_secret: Zeroizing<[u8; 32]>,
    transcript_hash: [u8; 32],
    peer: Peer,
}

impl Responder {
    /// Checks 1, 2 and 5 against `HELLO_INIT`, then `HELLO_RESP`.
    ///
    /// Check 3 does not apply: an inbound connection has no expected peer by
    /// definition. Check 4 does not either — `HELLO_INIT` carries no signature,
    /// because there is nothing to sign over until the responder has
    /// contributed its half of the transcript.
    pub fn respond(
        identity: &Identity,
        channel_binding: &[u8; 32],
        hello: &HelloInit,
    ) -> Result<(Self, HelloResp), CryptoError> {
        let peer = Peer::check(hello.version, hello.user_id_i, &hello.identity_pk_i)?;

        let eph_sk = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let unsigned = HelloRespUnsigned {
            version: PROTOCOL_VERSION,
            user_id_r: identity.user_id(),
            identity_pk_r: identity.identity_pk(),
            eph_pk_r: PublicKey::from(&eph_sk).to_bytes(),
            nonce_r: nonce(),
        };

        // Check 5.
        let shared_secret = dh(eph_sk, &hello.eph_pk_i, &peer.user_id)?;

        let mut transcript = Transcript::new(channel_binding);
        transcript.absorb(hello)?;
        transcript.absorb(&unsigned)?;
        let sig_r = identity.sign(&transcript.hash());

        transcript.absorb_signature(&sig_r);

        Ok((
            Self {
                shared_secret,
                transcript_hash: transcript.hash(),
                peer,
            },
            HelloResp { unsigned, sig_r },
        ))
    }

    /// Check 4 on `sig_i`.
    ///
    /// The hash it covers includes this connection's channel binding, both
    /// nonces and both ephemeral keys, so a `HELLO_CONFIRM` captured anywhere
    /// else verifies against different bytes and fails here.
    pub fn finish(self, confirm: &HelloConfirm) -> Result<Session, CryptoError> {
        if !verify(&self.peer.key, &self.transcript_hash, &confirm.sig_i) {
            return Err(reject("HELLO_CONFIRM signature", &self.peer.user_id));
        }

        Ok(Session {
            shared_secret: self.shared_secret,
            transcript_hash: self.transcript_hash,
            peer_user_id: self.peer.user_id,
            peer_identity_pk: self.peer.key.to_bytes(),
            role: Role::Responder,
        })
    }
}

// ---------------------------------------------------------------------------
// The parts both sides share
// ---------------------------------------------------------------------------

/// The running BLAKE3 hash of `architecture.md` §6.
struct Transcript(blake3::Hasher);

impl Transcript {
    /// `h ← BLAKE3(domain ‖ cb)`.
    ///
    /// The channel binding goes in before any message does. Dropping it leaves
    /// a handshake that is still perfectly sound against everything except the
    /// one attack it was built for — which is why F-10 has a test of its own.
    fn new(channel_binding: &[u8; 32]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(HANDSHAKE_DOMAIN);
        hasher.update(channel_binding);
        Self(hasher)
    }

    fn absorb<T: WireType>(&mut self, value: &T) -> Result<(), CryptoError> {
        self.0.update(&wire::to_bytes(value)?);
        Ok(())
    }

    fn absorb_signature(&mut self, signature: &Signature) {
        self.0.update(signature.as_bytes());
    }

    fn hash(&self) -> [u8; 32] {
        *self.0.finalize().as_bytes()
    }
}

/// A peer that has passed checks 1 and 2.
struct Peer {
    user_id: UserId,
    key: VerifyingKey,
}

impl Peer {
    /// Check 1 (`version == 1`) and check 2 (the ID binds to the key), in that
    /// order.
    fn check(version: u8, user_id: UserId, identity_pk: &[u8; 32]) -> Result<Self, CryptoError> {
        if version != PROTOCOL_VERSION {
            return Err(reject("protocol version", &user_id));
        }

        // Check 2. Without it a peer claims any ID it likes, and check 3 —
        // which compares IDs, not keys — becomes decorative.
        if !ct_eq(&derive_user_id(identity_pk), &user_id) {
            return Err(reject("user_id does not bind to identity_pk", &user_id));
        }

        let key = VerifyingKey::from_bytes(identity_pk)
            .map_err(|_| reject("identity_pk is not a point", &user_id))?;

        Ok(Self { user_id, key })
    }
}

/// Check 5, and the DH it is part of.
///
/// `eph_sk` is taken by value: `diffie_hellman` consumes it and the secret is
/// zeroized on the drop at the end of this function, which is the "immediately
/// after the DH" §6 asks for. `SharedSecret` zeroizes on the same terms.
fn dh(
    eph_sk: EphemeralSecret,
    peer_eph_pk: &[u8; 32],
    peer: &UserId,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let shared = eph_sk.diffie_hellman(&PublicKey::from(*peer_eph_pk));

    // All-zero and every other small-order point land here: the output has no
    // contribution from our secret, so the "shared" secret is one the peer
    // knew in advance.
    if !shared.was_contributory() {
        return Err(reject("ephemeral key is small-order", peer));
    }

    Ok(Zeroizing::new(shared.to_bytes()))
}

/// Ed25519 verification, the one place it happens.
///
/// `verify_strict` rather than `verify`: it refuses small-order public keys and
/// pins down the malleability that plain Ed25519 verification leaves open.
fn verify(key: &VerifyingKey, message: &[u8; 32], signature: &Signature) -> bool {
    let signature = ed25519_dalek::Signature::from_bytes(signature.as_bytes());
    key.verify_strict(message, &signature).is_ok()
}

/// Constant-time, because these are compared against attacker-supplied bytes
/// and the timing of an early-exit `==` leaks a prefix length.
pub(crate) fn ct_eq(a: &UserId, b: &UserId) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// One error to the peer, the detail to the log.
///
/// `UserId` renders as a fingerprint in both `Display` and `Debug`, so the log
/// line cannot carry a full ID however this is called — agent.md §2.
fn reject(detail: &'static str, peer: &UserId) -> CryptoError {
    tracing::warn!(%peer, detail, "handshake rejected");
    CryptoError::Handshake
}

fn nonce() -> [u8; NONCE_LEN] {
    let mut out = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The copy of the DH output that outlives the handshake.
    ///
    /// `EphemeralSecret` and `SharedSecret` are not asserted here because
    /// x25519-dalek 2 wipes them with zeroize's `#[zeroize(drop)]`, which
    /// writes a `Drop` impl without the `ZeroizeOnDrop` marker — there is no
    /// trait bound left to assert against. Their wiping is the crate's
    /// business; this one is ours.
    #[test]
    fn the_shared_secret_zeroizes() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<Zeroizing<[u8; 32]>>();
    }

    /// The whole exchange, with the transport replaced by two `let`s.
    fn exchange(
        initiator: &Identity,
        responder: &Identity,
        cb_i: &[u8; 32],
        cb_r: &[u8; 32],
        expected_peer: Option<UserId>,
    ) -> Result<(Session, Session), CryptoError> {
        let (state_i, hello) = Initiator::start(initiator, cb_i, expected_peer)?;
        let (state_r, resp) = Responder::respond(responder, cb_r, &hello)?;
        let (session_i, confirm) = state_i.finish(&resp)?;
        let session_r = state_r.finish(&confirm)?;
        Ok((session_i, session_r))
    }

    #[test]
    fn both_sides_agree_on_the_secret_and_the_transcript() {
        let (i, r) = (Identity::generate(), Identity::generate());
        let cb = [7u8; 32];
        let (session_i, session_r) = exchange(&i, &r, &cb, &cb, Some(r.user_id())).unwrap();

        assert_eq!(
            session_i.shared_secret().as_slice(),
            session_r.shared_secret().as_slice()
        );
        assert_eq!(session_i.transcript_hash(), session_r.transcript_hash());
        assert_eq!(session_i.peer_user_id(), r.user_id());
        assert_eq!(session_r.peer_user_id(), i.user_id());
    }

    /// Same two identities, second connection: nothing is reused. Without this
    /// the replay tests in `p2pchat-net` would be checking a coincidence.
    #[test]
    fn two_handshakes_share_nothing() {
        let (i, r) = (Identity::generate(), Identity::generate());
        let cb = [7u8; 32];
        let first = exchange(&i, &r, &cb, &cb, None).unwrap().0;
        let second = exchange(&i, &r, &cb, &cb, None).unwrap().0;

        assert_ne!(
            first.shared_secret().as_slice(),
            second.shared_secret().as_slice()
        );
        assert_ne!(first.transcript_hash(), second.transcript_hash());
    }

    /// The transcript covers `nonce_r`: altering it between R signing and I
    /// verifying must break `sig_r`. Belt and braces against the ephemeral
    /// keys, and the only thing that fails if a nonce quietly stops being
    /// hashed — which is why this is a test and not a comment.
    #[test]
    fn nonce_r_altered_in_flight_breaks_the_transcript() {
        let (i, r) = (Identity::generate(), Identity::generate());
        let cb = [7u8; 32];
        let (state_i, hello) = Initiator::start(&i, &cb, None).unwrap();
        let (_state_r, mut resp) = Responder::respond(&r, &cb, &hello).unwrap();

        resp.unsigned.nonce_r[0] ^= 1;
        assert!(matches!(state_i.finish(&resp), Err(CryptoError::Handshake)));
    }

    /// The same for `nonce_i`, one message earlier: R hashes what it received,
    /// I hashes what it sent, and `sig_r` is where the two disagree.
    #[test]
    fn nonce_i_altered_in_flight_breaks_the_transcript() {
        let (i, r) = (Identity::generate(), Identity::generate());
        let cb = [7u8; 32];
        let (state_i, hello) = Initiator::start(&i, &cb, None).unwrap();

        let mut received = hello;
        received.nonce_i[0] ^= 1;
        let (_state_r, resp) = Responder::respond(&r, &cb, &received).unwrap();
        assert!(matches!(state_i.finish(&resp), Err(CryptoError::Handshake)));
    }

    /// F-10 in miniature: the two sides of a relayed connection hold different
    /// channel bindings, so `sig_r` verifies against the wrong transcript.
    /// `p2pchat-net`'s proxy test is the same failure with a real attacker.
    #[test]
    fn a_different_channel_binding_on_each_side_fails() {
        let (i, r) = (Identity::generate(), Identity::generate());
        let result = exchange(&i, &r, &[1u8; 32], &[2u8; 32], None);
        assert!(matches!(result, Err(CryptoError::Handshake)));
    }
}
