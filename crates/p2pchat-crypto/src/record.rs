//! Signed address records — `plan-v0.2.md` M15.
//!
//! The value the DHT will store under a user ID: where that user can be
//! dialled, signed by their identity key. Self-certifying, so the nodes that
//! store and hand it out are never trusted for it — the argument
//! `architecture.md` §3 makes for the public node's profile answer.
//!
//! **Order of checks is the security property, as it is for invites.** Bounds,
//! then the user ID binding, then the signature, and only then the timestamp
//! and `seq`. A timestamp or a counter nobody has authenticated is not worth
//! acting on: checked first, "expired" becomes an answer an attacker can
//! produce by editing a number, and a forged high `seq` could push a real
//! record out. `a_tampered_and_expired_record_reports_the_signature` is the
//! test that can see the order.
//!
//! The signature covers [`DOMAIN`] ‖ `postcard(AddressRecordBody)`. The same
//! key signs invites, whose bytes are unprefixed, and §6 transcripts; the
//! domain means no signature made for one of those verifies as a record.

use std::net::SocketAddr;

use ed25519_dalek::VerifyingKey;
use p2pchat_core::wire::{AddressRecord, AddressRecordBody, PROTOCOL_VERSION};
use p2pchat_core::{decode, CoreError};

use crate::handshake::ct_eq;
use crate::identity::{derive_user_id, Identity};
use crate::invite::SKEW;
use crate::CryptoError;

/// Prefixed to the body before signing and verifying.
pub const DOMAIN: &[u8] = b"p2pchat-v1-address-record";

/// How long a record is valid: `expires_at = published_at + LIFETIME`.
///
/// OD-6, M17: three minutes. A peer that goes offline has to be reported not
/// found before `architecture.md` §10's reconnect loop gives up on it (ten
/// minutes). Its record stops verifying `LIFETIME` after its last
/// publish, and the loop sees that at its next attempt: at most a 36 s wait
/// (the 30 s backoff cap and 20% jitter), then 20 s of silent dial per
/// address, which is how long a stale address takes to fail (the dial
/// deadline, M12c), and a record carries up to two. So `LIFETIME + 36 + 40 <=
/// 600`, and `LIFETIME <= 524`. Address changes are not what this
/// tracks: a node republishes on the change itself (`architecture.md` §3,
/// "Publish and lookup").
pub const LIFETIME: u64 = 3 * 60;

/// How often an owner republishes: half the lifetime, so one lost republish
/// does not let the record lapse — OD-6, M17. A publish is a lookup and
/// `replication` stores; `plan-v0.2.md` M17 has what they took under netem,
/// against this.
pub const REPUBLISH: u64 = LIFETIME / 2;

/// A record for this identity at `addrs`, valid for [`LIFETIME`] from
/// `published_at`. `seq` is the caller's to keep increasing — M17.
///
/// No addresses, or an unspecified one, is refused here for the reason
/// `invite::create` gives: a record nobody can dial is not worth publishing.
pub fn create(
    identity: &Identity,
    addrs: Vec<SocketAddr>,
    seq: u64,
    published_at: u64,
) -> Result<AddressRecord, CryptoError> {
    if addrs.is_empty() || addrs.iter().any(|addr| addr.ip().is_unspecified()) {
        return Err(CryptoError::RecordMalformed);
    }
    let body = AddressRecordBody {
        version: PROTOCOL_VERSION,
        user_id: identity.user_id(),
        identity_pk: identity.identity_pk(),
        addrs,
        seq,
        published_at,
        expires_at: published_at.saturating_add(LIFETIME),
    };
    let sig = identity.sign(&signed_message(&body)?);
    Ok(AddressRecord { body, sig })
}

/// `DOMAIN ‖ postcard(body)`. `to_bytes` validates, so a body past the bounds
/// is never signed or verified.
fn signed_message(body: &AddressRecordBody) -> Result<Vec<u8>, CryptoError> {
    let mut message = DOMAIN.to_vec();
    message.extend(p2pchat_core::wire::to_bytes(body)?);
    Ok(message)
}

/// Decodes a record from bytes a storage node handed over, and verifies it.
///
/// `now` is seconds since the epoch, passed in so that every expiry case is
/// reachable from a test.
pub fn open(bytes: &[u8], now: u64) -> Result<AddressRecord, CryptoError> {
    // `decode` applies `wire`'s bounds before anything holds the record.
    let record = decode(bytes).map_err(|_| CryptoError::RecordMalformed)?;
    verify(&record, now)?;
    Ok(record)
}

/// The checks, in order, on a decoded record.
pub fn verify(record: &AddressRecord, now: u64) -> Result<(), CryptoError> {
    let body = &record.body;

    if body.version != PROTOCOL_VERSION {
        return Err(CoreError::UnsupportedVersion.into());
    }
    if body.addrs.is_empty() {
        return Err(CryptoError::RecordMalformed);
    }

    if !ct_eq(&derive_user_id(&body.identity_pk), &body.user_id) {
        return Err(CryptoError::RecordUserId);
    }

    let key =
        VerifyingKey::from_bytes(&body.identity_pk).map_err(|_| CryptoError::RecordSignature)?;
    let message = signed_message(body).map_err(|_| CryptoError::RecordMalformed)?;
    let sig = ed25519_dalek::Signature::from_bytes(record.sig.as_bytes());
    // `verify_strict`, as for invites and the handshake.
    key.verify_strict(&message, &sig)
        .map_err(|_| CryptoError::RecordSignature)?;

    // Only now are timestamps worth reading. Skew admits a publisher whose
    // clock runs ahead; it never extends a record's validity.
    if body.published_at > now.saturating_add(SKEW) {
        return Err(CryptoError::RecordFuture);
    }
    if now > body.expires_at {
        return Err(CryptoError::RecordExpired);
    }

    Ok(())
}

/// Verifies `record` and checks that it supersedes `held`, the record already
/// held for the same user, if any.
///
/// A lower `seq` is a rollback: somebody replaying what the owner has since
/// replaced, to send peers to an address the owner has left. The same `seq`
/// with different contents is refused as well, since the owner signs one
/// record per `seq` and a second one is not theirs to prefer. The same record
/// again is fine — republished, or fetched twice.
///
/// Nothing about `record` is compared until it has passed [`verify`], so a
/// forged `seq` never outranks a real one.
pub fn supersedes(
    record: &AddressRecord,
    held: Option<&AddressRecord>,
    now: u64,
) -> Result<(), CryptoError> {
    verify(record, now)?;
    if let Some(held) = held {
        let (got, held_seq) = (record.body.seq, held.body.seq);
        if got < held_seq || (got == held_seq && record != held) {
            return Err(CryptoError::RecordRolledBack {
                held: held_seq,
                got,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2pchat_core::UserId;

    const EPOCH: u64 = 1_700_000_000;

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn sample(identity: &Identity, seq: u64) -> AddressRecord {
        create(identity, vec![addr("203.0.113.7:47101")], seq, EPOCH).unwrap()
    }

    fn bytes(record: &AddressRecord) -> Vec<u8> {
        // Straight to postcard: an attacker is not bound by our outbound
        // validation, and some tests below need what validation would refuse.
        postcard::to_stdvec(record).unwrap()
    }

    /// Signs `body` as `identity` would, domain and all: a record that is
    /// internally consistent under whichever key signed it.
    fn resign(identity: &Identity, body: AddressRecordBody) -> AddressRecord {
        let mut message = DOMAIN.to_vec();
        message.extend(postcard::to_stdvec(&body).unwrap());
        AddressRecord {
            sig: identity.sign(&message),
            body,
        }
    }

    #[test]
    fn a_record_round_trips() {
        let identity = Identity::generate();
        let record = sample(&identity, 1);
        assert_eq!(open(&bytes(&record), EPOCH).unwrap(), record);
        assert_eq!(record.body.expires_at, EPOCH + LIFETIME);
    }

    /// Gate 1: a record for the victim, built by someone without the victim's
    /// key. Both shapes: the victim's key with the attacker's signature, and
    /// a signature that is noise.
    #[test]
    fn gate_1_a_forged_record_is_rejected() {
        let victim = Identity::generate();
        let attacker = Identity::generate();

        let mut body = sample(&victim, 9).body;
        body.addrs = vec![addr("198.51.100.66:47101")];
        let forged = AddressRecord {
            sig: resign(&attacker, body.clone()).sig,
            body: body.clone(),
        };
        let err = open(&bytes(&forged), EPOCH).unwrap_err();
        assert!(matches!(err, CryptoError::RecordSignature), "{err:?}");

        let noise = AddressRecord {
            body,
            sig: p2pchat_core::wire::Signature::from_bytes([0x5A; 64]),
        };
        let err = open(&bytes(&noise), EPOCH).unwrap_err();
        assert!(matches!(err, CryptoError::RecordSignature), "{err:?}");
    }

    /// Gate 2: the user ID has to bind to the key, whoever signed. The
    /// owner re-signing a changed ID, and an attacker signing properly under
    /// the victim's ID with their own key.
    #[test]
    fn gate_2_a_user_id_that_does_not_bind_is_rejected() {
        let owner = Identity::generate();
        let mut body = sample(&owner, 1).body;
        body.user_id = UserId::from_bytes([9; 32]);
        let err = open(&bytes(&resign(&owner, body)), EPOCH).unwrap_err();
        assert!(matches!(err, CryptoError::RecordUserId), "{err:?}");

        let victim = Identity::generate();
        let attacker = Identity::generate();
        let mut body = sample(&attacker, 1).body;
        body.user_id = victim.user_id();
        let err = open(&bytes(&resign(&attacker, body)), EPOCH).unwrap_err();
        assert!(matches!(err, CryptoError::RecordUserId), "{err:?}");
    }

    /// Gate 3: expired and malformed are different answers. Expired means
    /// look again later; malformed means this storage node sent rubbish.
    #[test]
    fn gate_3_expired_and_malformed_are_distinct_errors() {
        let identity = Identity::generate();
        let record = sample(&identity, 1);

        assert!(open(&bytes(&record), EPOCH + LIFETIME).is_ok());
        let err = open(&bytes(&record), EPOCH + LIFETIME + 1).unwrap_err();
        assert!(matches!(err, CryptoError::RecordExpired), "{err:?}");

        let future = sample(&identity, 2);
        let err = open(&bytes(&future), EPOCH.saturating_sub(SKEW + 1)).unwrap_err();
        assert!(matches!(err, CryptoError::RecordFuture), "{err:?}");

        let mut too_many = record.body.clone();
        too_many.addrs = vec![addr("203.0.113.7:47101"); p2pchat_core::wire::MAX_ADDRS + 1];
        let mut none = record.body.clone();
        none.addrs.clear();

        let mut truncated = bytes(&record);
        truncated.pop();
        for (what, malformed) in [
            ("empty", Vec::new()),
            ("garbage", vec![0xFF; 40]),
            ("truncated", truncated),
            ("too many addresses", bytes(&resign(&identity, too_many))),
            ("no addresses", bytes(&resign(&identity, none))),
        ] {
            let err = open(&malformed, EPOCH).unwrap_err();
            assert!(
                matches!(err, CryptoError::RecordMalformed),
                "{what} gave {err:?}"
            );
        }
    }

    /// Gate 4: a node holding seq 5 refuses seq 4, and a different record
    /// claiming seq 5; it takes seq 6, and seq 5 again unchanged.
    #[test]
    fn gate_4_a_rolled_back_seq_is_rejected() {
        let identity = Identity::generate();
        let held = sample(&identity, 5);

        let err = supersedes(&sample(&identity, 4), Some(&held), EPOCH).unwrap_err();
        assert!(
            matches!(err, CryptoError::RecordRolledBack { held: 5, got: 4 }),
            "{err:?}"
        );

        let rival = create(&identity, vec![addr("198.51.100.2:47101")], 5, EPOCH).unwrap();
        let err = supersedes(&rival, Some(&held), EPOCH).unwrap_err();
        assert!(
            matches!(err, CryptoError::RecordRolledBack { held: 5, got: 5 }),
            "{err:?}"
        );

        assert!(supersedes(&sample(&identity, 6), Some(&held), EPOCH).is_ok());
        assert!(supersedes(&held, Some(&held), EPOCH).is_ok());
        assert!(supersedes(&sample(&identity, 0), None, EPOCH).is_ok());
    }

    /// A forged record never outranks a real one, however high its seq.
    #[test]
    fn a_forged_high_seq_does_not_supersede() {
        let victim = Identity::generate();
        let attacker = Identity::generate();
        let held = sample(&victim, 5);

        let mut body = held.body.clone();
        body.seq = u64::MAX;
        body.addrs = vec![addr("198.51.100.66:47101")];
        let forged = AddressRecord {
            sig: resign(&attacker, body.clone()).sig,
            body,
        };
        let err = supersedes(&forged, Some(&held), EPOCH).unwrap_err();
        assert!(matches!(err, CryptoError::RecordSignature), "{err:?}");
    }

    /// Gate 5: the address changed after signing. The binding is untouched,
    /// so the signature is the only check that can see it.
    #[test]
    fn gate_5_a_tampered_address_fails_the_signature() {
        let mut record = sample(&Identity::generate(), 1);
        record.body.addrs[0] = addr("198.51.100.66:47101");
        let err = open(&bytes(&record), EPOCH).unwrap_err();
        assert!(matches!(err, CryptoError::RecordSignature), "{err:?}");
    }

    /// And every other byte, one bit at a time.
    #[test]
    fn no_single_altered_byte_survives() {
        let mut encoded = bytes(&sample(&Identity::generate(), 1));
        for index in 0..encoded.len() {
            encoded[index] ^= 0x01;
            assert!(
                open(&encoded, EPOCH).is_err(),
                "byte {index} could be flipped unnoticed"
            );
            encoded[index] ^= 0x01;
        }
    }

    /// Gate 6: expiry is read only after the signature. Two tampered records,
    /// each of which would be reported expired by a check made in the wrong
    /// order: an address changed, looked at after expiry; and `expires_at`
    /// itself pulled back to a plausible time already past. Both must report
    /// the signature.
    #[test]
    fn gate_6_a_tampered_and_expired_record_reports_the_signature() {
        let identity = Identity::generate();

        let mut moved = sample(&identity, 1);
        moved.body.addrs[0] = addr("198.51.100.66:47101");
        let err = open(&bytes(&moved), EPOCH + LIFETIME + SKEW + 1).unwrap_err();
        assert!(matches!(err, CryptoError::RecordSignature), "{err:?}");

        let mut aged = sample(&identity, 1);
        aged.body.expires_at = EPOCH + 60;
        let err = open(&bytes(&aged), EPOCH + 60 + SKEW + 1).unwrap_err();
        assert!(matches!(err, CryptoError::RecordSignature), "{err:?}");
    }

    /// The domain is part of what is signed: a signature over the bare body,
    /// which is how an invite is signed, is not a record signature.
    #[test]
    fn a_signature_without_the_domain_does_not_verify() {
        let identity = Identity::generate();
        let body = sample(&identity, 1).body;
        let bare = AddressRecord {
            sig: identity.sign(&postcard::to_stdvec(&body).unwrap()),
            body,
        };
        let err = open(&bytes(&bare), EPOCH).unwrap_err();
        assert!(matches!(err, CryptoError::RecordSignature), "{err:?}");
    }

    #[test]
    fn nothing_undialable_is_signed() {
        let identity = Identity::generate();
        for addrs in [vec![], vec![addr("0.0.0.0:47101")], vec![addr("[::]:1")]] {
            let err = create(&identity, addrs.clone(), 1, EPOCH).unwrap_err();
            assert!(matches!(err, CryptoError::RecordMalformed), "{addrs:?}");
        }
    }
}
