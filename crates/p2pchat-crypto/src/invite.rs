//! The invite blob — `architecture.md` §9.
//!
//! ```text
//! p2pchat:v1:<base64url(postcard(Invite))>
//! ```
//!
//! Self-signed, so it proves internal consistency and nothing about who sent
//! it. An attacker who controls the channel carrying the invite substitutes
//! their own wholesale; the fingerprint comparison in §4 is the only defence
//! and it is manual. F-05 requires the UI to show the fingerprint before
//! connecting for exactly that reason.
//!
//! **Order of checks is the security property here.** Signature first, expiry
//! last. An expired invite and a forged one are both rejected either way, but
//! reversing them means the "ask your peer for a fresh invite" that §9 promises
//! could be produced by a timestamp nobody signed. The only observable
//! difference is an invite that fails *both* checks, which is what
//! `an_expired_and_tampered_invite_reports_the_signature` pins down.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use p2pchat_core::wire::{Invite, InviteBody, PROTOCOL_VERSION};
use p2pchat_core::{decode, CoreError};

use crate::handshake::ct_eq;
use crate::identity::{derive_user_id, Identity};
use crate::CryptoError;

/// The scheme and version prefix every invite starts with — §9.
pub const SCHEME: &str = "p2pchat:v1:";

/// `expires_at = created_at + 24h` — OD-3.
pub const LIFETIME: u64 = 24 * 60 * 60;

/// Clock skew allowed on the expiry check, §9: enough that a fast clock does
/// not reject an invite that was just generated.
pub const SKEW: u64 = 5 * 60;

/// Seconds since the Unix epoch, which is the unit of every timestamp that
/// crosses the wire unencrypted: `Invite::created_at`, `Invite::expires_at`,
/// `ConnectionRequest::created_at`. (`messages.created_at` is milliseconds and
/// is a different clock in a different place — §8.)
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// What to tell whoever asked for an invite that would advertise nothing
/// dialable. One string, because M9d requires the same instruction from both
/// places that can produce the situation: generating an invite, and accepting
/// a connection request — which needs an advertised private address to send
/// back, derived from this same `--addr` (§10).
pub const NO_ADDR: &str = "no address to advertise: pass --addr with an address peers can dial, \
     or set `addr` in config.toml";

/// A signed invite for this identity, valid for [`LIFETIME`] from `created_at`.
///
/// `display_name` and `addrs` are bounded by `wire`'s limits; anything longer
/// is refused here rather than emitted and refused by the peer.
///
/// An invite with no address at all, or with an unspecified one — `0.0.0.0` or
/// `[::]` — is refused outright, F-04 and M9d. The unspecified address is what
/// a node *binds* to and names no host; no address at all names nothing either.
/// Either way the blob is one nobody can act on, and by the time that is
/// noticed it has been pasted into someone's chat. This is the one place both
/// the `invite` subcommand and the public node's profile answer pass through,
/// so the check is here rather than at either call site. Loopback is allowed: a
/// node reached over loopback is a node on the same machine, which is how the
/// tests run.
pub fn create(
    identity: &Identity,
    display_name: &str,
    addrs: Vec<SocketAddr>,
    created_at: u64,
) -> Result<Invite, CryptoError> {
    if addrs.is_empty() {
        return Err(CryptoError::InviteNoAddr);
    }
    if let Some(addr) = addrs.iter().find(|addr| addr.ip().is_unspecified()) {
        return Err(CryptoError::InviteUnspecifiedAddr(*addr));
    }

    let body = InviteBody {
        version: PROTOCOL_VERSION,
        user_id: identity.user_id(),
        identity_pk: identity.identity_pk(),
        display_name: display_name.to_owned(),
        addrs,
        created_at,
        expires_at: Some(created_at.saturating_add(LIFETIME)),
    };

    let sig = identity.sign(&p2pchat_core::wire::to_bytes(&body)?);
    Ok(Invite { body, sig })
}

/// `p2pchat:v1:<base64url(postcard(Invite))>` — one line, no padding.
pub fn encode(invite: &Invite) -> Result<String, CryptoError> {
    let bytes = p2pchat_core::wire::to_bytes(invite)?;
    Ok(format!("{SCHEME}{}", URL_SAFE_NO_PAD.encode(bytes)))
}

/// Decodes and fully verifies an invite blob — F-05.
///
/// `now` is seconds since the epoch, passed in rather than read here so that
/// every expiry case is reachable from a test without touching the clock.
pub fn parse(text: &str, now: u64) -> Result<Invite, CryptoError> {
    let invite = split(text)?;
    verify(&invite, now)?;
    Ok(invite)
}

/// The checks, in order, on an already-decoded invite.
///
/// Public because the profile answer from a public node arrives as an `Invite`
/// rather than as a blob (`architecture.md` §3), and it is exactly as untrusted
/// as a pasted one.
pub fn verify(invite: &Invite, now: u64) -> Result<(), CryptoError> {
    let body = &invite.body;

    if body.version != PROTOCOL_VERSION {
        return Err(CoreError::UnsupportedVersion.into());
    }

    // Same check as §6's check 2, for the same reason: without it the ID is
    // whatever the blob says, and comparing fingerprints compares nothing.
    if !ct_eq(&derive_user_id(&body.identity_pk), &body.user_id) {
        return Err(CryptoError::InviteUserId);
    }

    let key =
        VerifyingKey::from_bytes(&body.identity_pk).map_err(|_| CryptoError::InviteSignature)?;
    let signed = p2pchat_core::wire::to_bytes(body)?;
    let sig = ed25519_dalek::Signature::from_bytes(invite.sig.as_bytes());
    // `verify_strict`, as in the handshake: it refuses small-order public keys
    // and pins down Ed25519's malleability.
    key.verify_strict(&signed, &sig)
        .map_err(|_| CryptoError::InviteSignature)?;

    // Only now is the timestamp worth reading: it is signed, by a key that
    // the user ID binds to.
    if let Some(expires_at) = body.expires_at {
        if now > expires_at.saturating_add(SKEW) {
            return Err(CryptoError::InviteExpired);
        }
    }

    Ok(())
}

/// Scheme, base64, postcard, and `wire`'s length bounds. No signature.
///
/// Private: an invite that has been decoded but not verified is a structure an
/// attacker chose every field of, and there is no call site that wants one.
fn split(text: &str) -> Result<Invite, CryptoError> {
    let encoded = text
        .trim()
        .strip_prefix(SCHEME)
        .ok_or(CryptoError::InviteMalformed)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| CryptoError::InviteMalformed)?;
    // `decode` runs `WireType::validate`, so `display_name` and `addrs` are
    // bounded before anything holds them — MAX_DISPLAY_NAME, MAX_ADDRS.
    decode(&bytes).map_err(|_| CryptoError::InviteMalformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPOCH: u64 = 1_700_000_000;

    fn identity() -> Identity {
        Identity::generate()
    }

    fn sample(identity: &Identity) -> Invite {
        create(
            identity,
            "alice",
            vec!["203.0.113.7:47100".parse().unwrap()],
            EPOCH,
        )
        .unwrap()
    }

    /// Re-signs a body that has been changed, so the invite is internally
    /// consistent under a *different* key: what an attacker who substitutes an
    /// invite wholesale produces.
    ///
    /// Straight to `postcard`, skipping `wire::to_bytes`: an attacker is not
    /// bound by our outbound validation, and one of the tests below needs a
    /// body that validation would have refused to emit.
    fn resign(identity: &Identity, body: InviteBody) -> Invite {
        let sig = identity.sign(&postcard::to_stdvec(&body).unwrap());
        Invite { body, sig }
    }

    /// M7 gate 1.
    #[test]
    fn an_invite_round_trips() {
        let identity = identity();
        let invite = sample(&identity);
        let text = encode(&invite).unwrap();

        assert!(text.starts_with(SCHEME));
        assert_eq!(text.lines().count(), 1);
        assert_eq!(parse(&text, EPOCH).unwrap(), invite);
        assert_eq!(invite.body.user_id, identity.user_id());
        assert_eq!(invite.body.expires_at, Some(EPOCH + LIFETIME));
    }

    /// F-04: a single line under 300 characters.
    #[test]
    fn a_typical_invite_fits_in_a_line() {
        let text = encode(&sample(&identity())).unwrap();
        assert!(text.len() < 300, "{} chars: {text}", text.len());
    }

    /// M7 gate 2. The tamper is to `display_name`, which leaves the ID binding
    /// intact, so the signature is the only check that can catch it.
    #[test]
    fn a_tampered_invite_is_rejected_by_the_signature() {
        let mut invite = sample(&identity());
        invite.body.display_name = "mallory".to_owned();

        let err = parse(&encode(&invite).unwrap(), EPOCH).unwrap_err();
        assert!(matches!(err, CryptoError::InviteSignature), "{err:?}");
    }

    /// The same, one bit at a time, in the encoded form rather than the struct:
    /// covers the signature bytes themselves and the fields a typed tamper
    /// would not reach.
    #[test]
    fn no_single_altered_byte_survives() {
        let invite = sample(&identity());
        let mut bytes = p2pchat_core::wire::to_bytes(&invite).unwrap();

        for index in 0..bytes.len() {
            bytes[index] ^= 0x01;
            let text = format!("{SCHEME}{}", URL_SAFE_NO_PAD.encode(&bytes));
            assert!(
                parse(&text, EPOCH).is_err(),
                "byte {index} could be flipped unnoticed"
            );
            bytes[index] ^= 0x01;
        }
    }

    /// M7 gate 3: the ID must bind to the key, whoever signed.
    #[test]
    fn an_invite_whose_user_id_does_not_bind_is_rejected() {
        let identity = identity();
        let mut body = sample(&identity).body;
        body.user_id = p2pchat_core::UserId::from_bytes([9; 32]);

        let invite = resign(&identity, body);
        let err = parse(&encode(&invite).unwrap(), EPOCH).unwrap_err();
        assert!(matches!(err, CryptoError::InviteUserId), "{err:?}");
    }

    /// The attacker's version of the same thing: their key, their signature,
    /// the victim's user ID. Signing it properly does not help.
    #[test]
    fn a_substituted_key_under_a_borrowed_user_id_is_rejected() {
        let victim = identity();
        let attacker = identity();

        let mut body = sample(&attacker).body;
        body.user_id = victim.user_id();

        let invite = resign(&attacker, body);
        let err = parse(&encode(&invite).unwrap(), EPOCH).unwrap_err();
        assert!(matches!(err, CryptoError::InviteUserId), "{err:?}");
    }

    /// M7 gate 4: expired and malformed are different answers, because the
    /// user's next move differs — §9.
    #[test]
    fn expired_and_malformed_are_distinct_errors() {
        let invite = sample(&identity());
        let text = encode(&invite).unwrap();

        let expired = parse(&text, EPOCH + LIFETIME + SKEW + 1).unwrap_err();
        assert!(matches!(expired, CryptoError::InviteExpired), "{expired:?}");

        for malformed in [
            String::new(),
            "not an invite".to_owned(),
            text.replace(SCHEME, "p2pchat:v2:"),
            format!("{SCHEME}!!!not base64!!!"),
            format!("{SCHEME}{}", URL_SAFE_NO_PAD.encode([0u8; 8])),
        ] {
            let err = parse(&malformed, EPOCH).unwrap_err();
            assert!(
                matches!(err, CryptoError::InviteMalformed),
                "{malformed:?} gave {err:?}"
            );
        }
    }

    /// M7 gate 5, both halves.
    #[test]
    fn five_minutes_ahead_is_accepted_and_twenty_five_hours_is_not() {
        let invite = sample(&identity());
        let text = encode(&invite).unwrap();

        // Generated five minutes in the future by a peer whose clock runs fast.
        assert!(parse(&text, EPOCH - SKEW).is_ok());
        // Fresh.
        assert!(parse(&text, EPOCH).is_ok());
        // One second before it lapses, and one second after the skew allowance.
        assert!(parse(&text, EPOCH + LIFETIME - 1).is_ok());
        assert!(parse(&text, EPOCH + LIFETIME + SKEW).is_ok());

        let old = parse(&text, EPOCH + 25 * 60 * 60).unwrap_err();
        assert!(matches!(old, CryptoError::InviteExpired), "{old:?}");
    }

    /// The order of the two checks, and the only case that can observe it: an
    /// invite that fails both. Checking expiry first would answer `Expired`
    /// here — acting on, and reporting, a timestamp that nothing authenticates.
    /// "Ask your peer for a fresh invite" is then advice an attacker wrote.
    #[test]
    fn an_expired_and_tampered_invite_reports_the_signature() {
        let mut invite = sample(&identity());
        invite.body.display_name = "mallory".to_owned();
        let text = encode(&invite).unwrap();

        let err = parse(&text, EPOCH + LIFETIME + SKEW + 1).unwrap_err();
        assert!(matches!(err, CryptoError::InviteSignature), "{err:?}");
    }

    /// Garbage that happens to decode must never reach the expiry branch
    /// either: `InviteExpired` is reachable only through a valid signature.
    #[test]
    fn a_forged_invite_never_reports_expiry() {
        let attacker = identity();
        let mut body = sample(&attacker).body;
        body.expires_at = Some(0);
        body.user_id = p2pchat_core::UserId::from_bytes([0xAA; 32]);

        let invite = resign(&attacker, body);
        let err = parse(&encode(&invite).unwrap(), EPOCH).unwrap_err();
        assert!(!matches!(err, CryptoError::InviteExpired), "{err:?}");
    }

    /// An invite with no expiry never lapses. `expires_at` is an `Option` in
    /// §9 and this is what the `None` means.
    #[test]
    fn an_invite_without_an_expiry_does_not_expire() {
        let identity = identity();
        let mut body = sample(&identity).body;
        body.expires_at = None;

        let invite = resign(&identity, body);
        let text = encode(&invite).unwrap();
        assert!(parse(&text, EPOCH + 10 * LIFETIME).is_ok());
    }

    /// M9c gate 3: an invite never advertises an address that names no host.
    /// Both families, and the port is irrelevant to the answer.
    #[test]
    fn an_unspecified_address_is_never_advertised() {
        let identity = identity();

        for addr in ["0.0.0.0:47100", "[::]:47100", "0.0.0.0:0"] {
            let err = create(&identity, "ada", vec![addr.parse().unwrap()], EPOCH).unwrap_err();
            assert!(
                matches!(err, CryptoError::InviteUnspecifiedAddr(_)),
                "{addr} gave {err:?}"
            );
            // The message has to tell the user what to do about it.
            assert!(err.to_string().contains("--addr"), "{err}");
        }

        // One bad address in a list of good ones is still refused.
        let err = create(
            &identity,
            "ada",
            vec![
                "203.0.113.7:47100".parse().unwrap(),
                "0.0.0.0:47100".parse().unwrap(),
            ],
            EPOCH,
        )
        .unwrap_err();
        assert!(
            matches!(err, CryptoError::InviteUnspecifiedAddr(_)),
            "{err:?}"
        );

        // Loopback is not unspecified: it names this host, and the tests use it.
        assert!(create(
            &identity,
            "ada",
            vec!["127.0.0.1:47100".parse().unwrap()],
            EPOCH
        )
        .is_ok());
        // No address at all is a different thing from an unusable one, and
        // since M9d it is refused too — an invite nobody can act on is not
        // worth printing. Same instruction, because the fix is the same.
        let err = create(&identity, "ada", Vec::new(), EPOCH).unwrap_err();
        assert!(matches!(err, CryptoError::InviteNoAddr), "{err:?}");
        assert!(err.to_string().contains("--addr"), "{err}");
    }

    /// Bounds come from `wire::validate`, on the way in as well as out —
    /// M2's limits, restated here because base64 is a new way to reach them.
    #[test]
    fn an_oversize_field_is_malformed_not_accepted() {
        let identity = identity();
        let mut body = sample(&identity).body;
        body.display_name = "x".repeat(p2pchat_core::wire::MAX_DISPLAY_NAME + 1);

        let invite = resign(&identity, body);
        // It cannot even be encoded, which is the point of validating on the
        // way out; and hand-encoding the same bytes is refused on the way in.
        assert!(encode(&invite).is_err());

        let bytes = postcard::to_stdvec(&invite).unwrap();
        let text = format!("{SCHEME}{}", URL_SAFE_NO_PAD.encode(bytes));
        let err = parse(&text, EPOCH).unwrap_err();
        assert!(matches!(err, CryptoError::InviteMalformed), "{err:?}");
    }
}
