//! Session keys and the record layer — `architecture.md` §7.
//!
//! One handshake output becomes two keys, and each side sends under one of
//! them and receives under the other. Getting that backwards is the failure
//! this module is shaped to prevent: a [`SessionCipher`] resolves the roles
//! once, at derivation, and then only offers `seal` and `open`. No call site
//! names a key, so no call site can name the wrong one.
//!
//! The nonce is the frame counter, not a random number — §7 and agent.md §2.
//! Encryption here draws from no RNG at all; [`SessionCipher::seal`] is a pure
//! function of the key, the counter and the message.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use p2pchat_core::id::FrameSeq;
use p2pchat_core::wire::{MessageFrame, MessageHeader, WireType};
use p2pchat_core::UserId;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::handshake::{ct_eq, Role, Session};
use crate::CryptoError;

/// HKDF's `info` — `architecture.md` §7.
pub const SESSION_INFO: &[u8] = b"p2pchat-v1-session";

/// `k_i2r ‖ k_r2i ‖ session_id`: two ChaCha20-Poly1305 keys and the public
/// name of the pair, in that order. HKDF-Expand's output is a prefix, so
/// lengthening it left both keys exactly as they were.
const OKM_LEN: usize = 96;

/// Where the two keys end and [`SessionCipher::session_id`] begins.
const KEY_LEN: usize = 32;

/// The two directional keys, each with its own counter, already resolved by
/// role.
///
/// Created by [`SessionCipher::derive`] from a finished handshake and kept in
/// memory for the life of the connection. Nothing here is persisted: a session
/// that ends takes its keys with it, which is what F-11 asks for.
pub struct SessionCipher {
    send: Direction,
    recv: Direction,
    /// The peer authenticated in §6. Receiver rule 3 compares against this.
    peer: UserId,
    session_id: [u8; 32],
}

impl SessionCipher {
    /// `HKDF-SHA256(ikm = shared_secret, salt = transcript_hash, info =
    /// "p2pchat-v1-session")`, 64 bytes, split in two.
    ///
    /// Takes the [`Session`] by value. The shared secret is zeroized when it
    /// drops at the end of this function, so there is no window in which both
    /// it and the keys derived from it are alive.
    ///
    /// The salt is the transcript hash, which covers both ephemeral keys, so
    /// two connections between the same pair of identities derive unrelated
    /// keys even though the identity keys never change — F-11.
    pub fn derive(session: Session) -> Result<Self, CryptoError> {
        let okm = expand(session.shared_secret(), session.transcript_hash())?;
        let (keys, id) = okm.split_at(2 * KEY_LEN);
        let (k_i2r, k_r2i) = keys.split_at(KEY_LEN);
        let mut session_id = [0u8; 32];
        session_id.copy_from_slice(id);

        // The one place a direction is chosen.
        let (send, recv) = match session.role() {
            Role::Initiator => (k_i2r, k_r2i),
            Role::Responder => (k_r2i, k_i2r),
        };

        Ok(Self {
            send: Direction::new(send),
            recv: Direction::new(recv),
            peer: session.peer_user_id(),
            session_id,
        })
    }

    /// Encrypt one frame under the send key, at the next send counter.
    ///
    /// The header travels in the clear and is the associated data, so a peer
    /// that edits any of its fields in flight fails the tag.
    pub fn seal(
        &mut self,
        header: &MessageHeader,
        plaintext: &[u8],
    ) -> Result<MessageFrame, CryptoError> {
        let nonce = self.send.step()?;
        let ciphertext = self.send.cipher.encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &header.aad()?,
            },
        )?;

        let frame = MessageFrame {
            header: *header,
            ciphertext,
        };
        // Bounds the body at MAX_BODY on the way out, the same check the
        // receiver applies on the way in.
        frame.validate()?;
        Ok(frame)
    }

    /// Receiver rules 1 to 3 of §7, in that order.
    ///
    /// Rule 4 — drop a `message_id` already stored — is the store's, at M7. It
    /// is deduplication, not authentication, and this layer has no database.
    ///
    /// A failure here means the session is over: §7 says close the connection,
    /// and the counters make that unambiguous, since the next frame would
    /// decrypt under a nonce the peer never used.
    pub fn open(&mut self, frame: &MessageFrame) -> Result<Vec<u8>, CryptoError> {
        frame.validate()?;

        // Rule 1: the nonce is our own counter. Nothing on the wire selects
        // it, so a replayed or reordered frame is decrypted under the nonce
        // the *next* frame should have used, and rule 2 rejects it.
        let nonce = self.recv.step()?;

        // Rule 2.
        let plaintext = self.recv.cipher.decrypt(
            &nonce,
            Payload {
                msg: &frame.ciphertext,
                aad: &frame.header.aad()?,
            },
        )?;

        // Rule 3: the sender is the peer we authenticated. The AEAD proves the
        // frame came from the holder of the key; this proves the header agrees
        // about whose it is.
        if !ct_eq(&frame.header.sender_id, &self.peer) {
            tracing::warn!(peer = %self.peer, "frame sender_id is not the authenticated peer");
            return Err(CryptoError::SenderMismatch);
        }

        Ok(plaintext)
    }

    /// Frames sealed so far. The counter itself never crosses the wire.
    pub fn frames_sent(&self) -> u64 {
        self.send.seq.get()
    }

    /// Frames opened so far.
    pub fn frames_received(&self) -> u64 {
        self.recv.seq.get()
    }

    pub fn peer(&self) -> UserId {
        self.peer
    }

    /// A public name for this session's keys — §10's "every reconnection is a
    /// completely new session".
    ///
    /// The last 32 bytes of the same HKDF output the keys come from, so it
    /// changes exactly when they do: a fresh handshake gives a fresh one, and
    /// a session that reused a key — resumption, which V0.1 does not do —
    /// would repeat it. Safe to log and to compare; it is one-way from the
    /// keys and reveals nothing about them.
    pub fn session_id(&self) -> [u8; 32] {
        self.session_id
    }
}

/// The peer's fingerprint and nothing else — two of these fields are keys.
impl std::fmt::Debug for SessionCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SessionCipher(peer {}, sent {}, received {})",
            self.peer,
            self.frames_sent(),
            self.frames_received()
        )
    }
}

/// One key and the counter that belongs to it. They are never apart: a counter
/// paired with the wrong key is a reused nonce.
struct Direction {
    cipher: ChaCha20Poly1305,
    seq: FrameSeq,
}

impl Direction {
    fn new(key: &[u8]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
            seq: FrameSeq::ZERO,
        }
    }

    /// The nonce for the next frame, consuming that counter value.
    ///
    /// `[0u8; 4] ‖ frame_seq.to_be_bytes()` — §7. The counter stops at
    /// [`FrameSeq::LIMIT`] and returns an error rather than wrapping: a wrapped
    /// nonce reuses a keystream, which loses the plaintext of both frames.
    fn step(&mut self) -> Result<Nonce, CryptoError> {
        let used = self.seq;
        self.seq = used.checked_next().ok_or(CryptoError::SequenceExhausted)?;

        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&used.get().to_be_bytes());
        Ok(Nonce::from(nonce))
    }
}

/// HKDF-SHA256 to [`OKM_LEN`] bytes. Separate from [`SessionCipher::derive`] so the
/// halves can be compared in a test — a `ChaCha20Poly1305` will not show them.
fn expand(
    shared_secret: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> Result<Zeroizing<[u8; OKM_LEN]>, CryptoError> {
    let mut okm = Zeroizing::new([0u8; OKM_LEN]);
    Hkdf::<Sha256>::new(Some(transcript_hash), shared_secret)
        .expand(SESSION_INFO, okm.as_mut_slice())
        .map_err(|_| CryptoError::Kdf)?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use p2pchat_core::id::{ConversationId, MessageId, MsgSeq};
    use p2pchat_core::wire::{MsgType, MAX_BODY, PROTOCOL_VERSION};

    use super::*;
    use crate::handshake::{Initiator, Responder};
    use crate::Identity;

    /// A handshake and the two ciphers that come out of it.
    fn connect(i: &Identity, r: &Identity) -> (SessionCipher, SessionCipher) {
        let cb = [9u8; 32];
        let (state_i, hello) = Initiator::start(i, &cb, None).unwrap();
        let (state_r, resp) = Responder::respond(r, &cb, &hello).unwrap();
        let (session_i, confirm) = state_i.finish(&resp).unwrap();
        let session_r = state_r.finish(&confirm).unwrap();
        (
            SessionCipher::derive(session_i).unwrap(),
            SessionCipher::derive(session_r).unwrap(),
        )
    }

    fn header(sender: UserId, seq: u64) -> MessageHeader {
        MessageHeader {
            version: PROTOCOL_VERSION,
            msg_type: MsgType::Text,
            message_id: MessageId::now_v7(),
            conversation_id: ConversationId::from_bytes([3u8; 32]),
            sender_id: sender,
            msg_seq: MsgSeq::new(seq),
            created_at: 1_700_000_000,
        }
    }

    /// Gate 1.
    #[test]
    fn a_frame_round_trips_in_both_directions() {
        let (i, r) = (Identity::generate(), Identity::generate());
        let (mut side_i, mut side_r) = connect(&i, &r);

        let out = side_i
            .seal(&header(i.user_id(), 0), b"from the initiator")
            .unwrap();
        assert_eq!(side_r.open(&out).unwrap(), b"from the initiator");

        let back = side_r
            .seal(&header(r.user_id(), 0), b"from the responder")
            .unwrap();
        assert_eq!(side_i.open(&back).unwrap(), b"from the responder");
    }

    /// Gate 2. The two halves of the OKM are what the directions are built
    /// from, so comparing them is comparing the keys.
    #[test]
    fn the_two_directional_keys_differ() {
        let okm = expand(&[1u8; 32], &[2u8; 32]).unwrap();
        let (k_i2r, k_r2i) = okm[..2 * KEY_LEN].split_at(KEY_LEN);
        assert_ne!(k_i2r, k_r2i);
    }

    /// M10 gate 4, at this layer: two handshakes between the same two
    /// identities name themselves differently, because §10 makes every
    /// reconnection a new session rather than a resumed one. The node-level
    /// gate asserts the same thing across a real reconnect.
    #[test]
    fn two_sessions_between_the_same_identities_have_different_ids() {
        let (i, r) = (Identity::generate(), Identity::generate());
        let (first, _) = connect(&i, &r);
        let (second, _) = connect(&i, &r);
        assert_ne!(
            first.session_id(),
            second.session_id(),
            "two handshakes produced one session id, so the keys were reused"
        );
    }

    /// Both ends of one session agree on its name — otherwise it names a
    /// direction rather than a session.
    #[test]
    fn both_sides_of_one_session_share_its_id() {
        let (i, r) = (Identity::generate(), Identity::generate());
        let (side_i, side_r) = connect(&i, &r);
        assert_eq!(side_i.session_id(), side_r.session_id());
    }

    /// The salt has to be *read*. Every gate test above still passes with a
    /// constant salt, because the IKM — a fresh DH output — is already unique
    /// per connection; F-11 cannot tell the difference. What a constant salt
    /// loses is the binding between the keys and the transcript, and with it
    /// the channel binding, the two identities and the two nonces §6 signed
    /// over. Same secret, different transcript, different keys: that is the
    /// property, and this is the only test that sees it.
    #[test]
    fn the_transcript_hash_is_what_salts_the_keys() {
        let shared_secret = [1u8; 32];
        assert_ne!(
            expand(&shared_secret, &[2u8; 32]).unwrap().as_slice(),
            expand(&shared_secret, &[3u8; 32]).unwrap().as_slice()
        );
    }

    /// Gate 2, the half that matters at the call site: a frame the initiator
    /// sealed cannot be opened by the initiator, only by the responder. A
    /// session that used one key for both directions would pass gate 1 and
    /// fail here.
    #[test]
    fn a_side_cannot_open_its_own_frame() {
        let i = Identity::generate();
        let (mut side_i, _side_r) = connect(&i, &Identity::generate());

        let frame = side_i.seal(&header(i.user_id(), 0), b"mine").unwrap();
        // Counter reset, so this fails on the key rather than the nonce.
        side_i.recv.seq = FrameSeq::ZERO;
        assert!(matches!(side_i.open(&frame), Err(CryptoError::Decrypt)));
    }

    /// Gate 3: no RNG in the encrypt path. One cipher rewound to the counter
    /// it started at, given the same input, produces the same bytes.
    #[test]
    fn sealing_the_same_frame_twice_gives_the_same_bytes() {
        let i = Identity::generate();
        let (mut side_i, _) = connect(&i, &Identity::generate());
        let head = header(i.user_id(), 0);

        let a = side_i.seal(&head, b"deterministic").unwrap();
        side_i.send.seq = FrameSeq::ZERO;
        let b = side_i.seal(&head, b"deterministic").unwrap();

        assert_eq!(a.ciphertext, b.ciphertext);
    }

    /// Gate 4.
    #[test]
    fn a_flipped_ciphertext_bit_fails_the_tag() {
        let i = Identity::generate();
        let (mut side_i, mut side_r) = connect(&i, &Identity::generate());

        let mut frame = side_i.seal(&header(i.user_id(), 0), b"intact").unwrap();
        frame.ciphertext[0] ^= 1;
        assert!(matches!(side_r.open(&frame), Err(CryptoError::Decrypt)));
    }

    /// Gate 5. `msg_seq` is a header field the AAD covers; altering it is how
    /// a peer would reorder a conversation without touching the ciphertext.
    #[test]
    fn a_flipped_aad_field_fails_the_tag() {
        let i = Identity::generate();
        let (mut side_i, mut side_r) = connect(&i, &Identity::generate());

        let mut frame = side_i.seal(&header(i.user_id(), 7), b"intact").unwrap();
        frame.header.msg_seq = MsgSeq::new(8);
        assert!(matches!(side_r.open(&frame), Err(CryptoError::Decrypt)));
    }

    /// Gate 5, every field: each one is in the AAD, not just the one that was
    /// convenient to mutate.
    #[test]
    fn every_header_field_is_covered_by_the_aad() {
        let i = Identity::generate();
        let head = header(i.user_id(), 7);

        /// One edit to a header field, named so a failure says which.
        type Edit = (&'static str, fn(&mut MessageHeader));

        let edits: [Edit; 6] = [
            ("version", |h| h.version = 2),
            ("msg_type", |h| h.msg_type = MsgType::Ack),
            ("message_id", |h| h.message_id = MessageId::now_v7()),
            ("conversation_id", |h| {
                h.conversation_id = ConversationId::from_bytes([4u8; 32])
            }),
            ("msg_seq", |h| h.msg_seq = MsgSeq::new(8)),
            ("created_at", |h| h.created_at += 1),
        ];

        for (field, edit) in edits {
            let (mut side_i, mut side_r) = connect(&i, &Identity::generate());
            let mut frame = side_i.seal(&head, b"intact").unwrap();
            edit(&mut frame.header);
            assert!(
                matches!(side_r.open(&frame), Err(CryptoError::Decrypt)),
                "{field} is not covered by the AAD"
            );
        }
    }

    /// Rule 3. `sender_id` is in the AAD too, so an edited one fails the tag
    /// first; this is the case the tag cannot catch — a frame sealed with the
    /// peer's own key claiming someone else sent it.
    #[test]
    fn a_frame_claiming_another_sender_is_rejected() {
        let i = Identity::generate();
        let (mut side_i, mut side_r) = connect(&i, &Identity::generate());

        let frame = side_i
            .seal(&header(Identity::generate().user_id(), 0), b"not mine")
            .unwrap();
        assert!(matches!(
            side_r.open(&frame),
            Err(CryptoError::SenderMismatch)
        ));
    }

    /// Gate 6.
    #[test]
    fn a_replayed_frame_is_rejected() {
        let i = Identity::generate();
        let (mut side_i, mut side_r) = connect(&i, &Identity::generate());

        let first = side_i.seal(&header(i.user_id(), 0), b"one").unwrap();
        side_r.open(&first).unwrap();

        assert!(matches!(side_r.open(&first), Err(CryptoError::Decrypt)));
    }

    /// Gate 7, F-11: same two identities, second connection, different keys.
    #[test]
    fn two_sessions_between_the_same_identities_derive_different_keys() {
        let (i, r) = (Identity::generate(), Identity::generate());
        let (mut first, _) = connect(&i, &r);
        let (_, mut second) = connect(&i, &r);

        // A frame from the first session, offered to the second.
        let frame = first
            .seal(&header(i.user_id(), 0), b"first session")
            .unwrap();
        assert!(matches!(second.open(&frame), Err(CryptoError::Decrypt)));
    }

    /// Gate 8: the ceiling is an error, not a wrap and not a panic.
    #[test]
    fn the_frame_counter_stops_at_its_limit() {
        let i = Identity::generate();
        let (mut side_i, _) = connect(&i, &Identity::generate());
        let head = header(i.user_id(), 0);

        side_i.send.seq = FrameSeq::new(FrameSeq::LIMIT - 1);
        side_i.seal(&head, b"the last one").unwrap();

        assert!(matches!(
            side_i.seal(&head, b"one too many"),
            Err(CryptoError::SequenceExhausted)
        ));
    }

    /// The same ceiling on the receive side, which a sender-only check misses.
    #[test]
    fn the_receive_counter_stops_at_its_limit() {
        let i = Identity::generate();
        let (mut side_i, mut side_r) = connect(&i, &Identity::generate());
        let frame = side_i.seal(&header(i.user_id(), 0), b"hello").unwrap();

        side_r.recv.seq = FrameSeq::new(FrameSeq::LIMIT);
        assert!(matches!(
            side_r.open(&frame),
            Err(CryptoError::SequenceExhausted)
        ));
    }

    /// F-13's 4 KiB, enforced on the way out as well as the way in.
    #[test]
    fn a_body_over_the_maximum_is_refused() {
        let i = Identity::generate();
        let (mut side_i, _) = connect(&i, &Identity::generate());

        let body = vec![b'a'; MAX_BODY + 1];
        assert!(side_i.seal(&header(i.user_id(), 0), &body).is_err());
        assert!(side_i
            .seal(&header(i.user_id(), 0), &body[..MAX_BODY])
            .is_ok());
    }
}
