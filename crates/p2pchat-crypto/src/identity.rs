//! Long-term Ed25519 identity and the user ID derived from it —
//! `architecture.md` §4.

use ed25519_dalek::{Signer, SigningKey};
use p2pchat_core::wire::Signature;
use p2pchat_core::{ConversationId, UserId};
use zeroize::Zeroizing;

/// Domain separator for user ID derivation. Changing this changes every user
/// ID in existence.
pub const USER_ID_DOMAIN: &[u8] = b"p2pchat-v1-userid";

/// The Ed25519 seed as stored on disk.
pub const SEED_LEN: usize = 32;

/// Domain separator for conversation ID derivation — `architecture.md` §8.
pub const CONVERSATION_ID_DOMAIN: &[u8] = b"p2pchat-v1-conv";

/// `BLAKE3(b"p2pchat-v1-userid" || identity_pk)`.
///
/// Also used by the handshake (`architecture.md` §6 check 2) to verify that a
/// peer's claimed ID actually binds to the public key it presented.
pub fn derive_user_id(identity_pk: &[u8; 32]) -> UserId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(USER_ID_DOMAIN);
    hasher.update(identity_pk);
    UserId::from_bytes(*hasher.finalize().as_bytes())
}

/// `BLAKE3(b"p2pchat-v1-conv" || min(a, b) || max(a, b))` — `architecture.md` §8.
///
/// Never negotiated: both peers compute it from the pair of user IDs alone, so
/// the ordering has to come from the IDs themselves rather than from who dialled
/// whom. Hashing them in argument order instead would give the two sides
/// different conversation IDs, and nothing would fail until the first restart
/// failed to find the history.
pub fn derive_conversation_id(a: &UserId, b: &UserId) -> ConversationId {
    let (low, high) = if a <= b { (a, b) } else { (b, a) };

    let mut hasher = blake3::Hasher::new();
    hasher.update(CONVERSATION_ID_DOMAIN);
    hasher.update(low.as_bytes());
    hasher.update(high.as_bytes());
    ConversationId::from_bytes(*hasher.finalize().as_bytes())
}

/// A local identity: the signing key and the ID it implies.
///
/// The secret never leaves this type. `SigningKey` cannot be put in
/// `Zeroizing` — it does not implement `Zeroize` — but under dalek's `zeroize`
/// feature it is `ZeroizeOnDrop`, which is the same guarantee applied by the
/// type itself instead of by a wrapper. Every raw copy of the seed *is*
/// `Zeroizing`; see `seed` and `from_seed`.
pub struct Identity {
    signing: SigningKey,
    user_id: UserId,
}

impl Identity {
    /// Fresh keypair from the operating system RNG.
    pub fn generate() -> Self {
        Self::from_signing_key(SigningKey::generate(&mut rand::rngs::OsRng))
    }

    pub fn from_seed(seed: &Zeroizing<[u8; SEED_LEN]>) -> Self {
        Self::from_signing_key(SigningKey::from_bytes(seed))
    }

    fn from_signing_key(signing: SigningKey) -> Self {
        let user_id = derive_user_id(&signing.verifying_key().to_bytes());
        Self { signing, user_id }
    }

    pub fn user_id(&self) -> UserId {
        self.user_id
    }

    pub fn identity_pk(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Ed25519 over `message`. The handshake signs a transcript hash with it
    /// at the two points `architecture.md` §6 specifies, and nothing else in
    /// the project signs anything the peer chose the bytes of.
    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature::from_bytes(self.signing.sign(message).to_bytes())
    }

    /// The seed, for writing to the keystore. Zeroized when the caller drops it.
    pub(crate) fn seed(&self) -> Zeroizing<[u8; SEED_LEN]> {
        Zeroizing::new(self.signing.to_bytes())
    }
}

/// No `Debug` derive anywhere near the secret; this prints the fingerprint.
impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Identity({})", self.user_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fails to compile if secret material ever stops being self-zeroizing —
    /// the cheapest available check on F-01's `Zeroizing` criterion.
    #[test]
    fn secret_key_material_zeroizes() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SigningKey>();
        assert_zeroize_on_drop::<Zeroizing<[u8; SEED_LEN]>>();

        let identity = Identity::generate();
        let _: &SigningKey = &identity.signing;
        let _: Zeroizing<[u8; SEED_LEN]> = identity.seed();
    }

    #[test]
    fn user_id_binds_to_the_public_key() {
        let identity = Identity::generate();
        let mut expected = blake3::Hasher::new();
        expected.update(b"p2pchat-v1-userid");
        expected.update(&identity.identity_pk());
        assert_eq!(
            identity.user_id().as_bytes(),
            expected.finalize().as_bytes()
        );
    }

    #[test]
    fn same_seed_gives_the_same_user_id() {
        let identity = Identity::generate();
        let reloaded = Identity::from_seed(&identity.seed());
        assert_eq!(identity.user_id(), reloaded.user_id());
        assert_eq!(identity.identity_pk(), reloaded.identity_pk());
    }

    #[test]
    fn distinct_identities_get_distinct_ids() {
        assert_ne!(
            Identity::generate().user_id(),
            Identity::generate().user_id()
        );
    }

    /// F-01: generation completes in under 100 ms.
    #[test]
    fn generation_is_fast() {
        let start = std::time::Instant::now();
        let identity = Identity::generate();
        let elapsed = start.elapsed();
        assert_eq!(identity.user_id().fingerprint().len(), 19);
        eprintln!("keygen took {elapsed:?}");
        assert!(elapsed.as_millis() < 100, "keygen took {elapsed:?}");
    }

    /// M6 gate 6. `min`/`max` is the whole mechanism: derive from the pair in
    /// argument order and each side gets a different ID for the same
    /// conversation.
    #[test]
    fn conversation_id_derivation_is_order_independent() {
        let a = Identity::generate().user_id();
        let b = Identity::generate().user_id();
        assert_ne!(a, b);
        assert_eq!(
            derive_conversation_id(&a, &b),
            derive_conversation_id(&b, &a)
        );
    }

    /// The property above holds trivially for a function that ignores its
    /// arguments, so pin the value to the specification as well.
    #[test]
    fn conversation_id_is_the_documented_hash() {
        let low = UserId::from_bytes([0x11; 32]);
        let high = UserId::from_bytes([0x99; 32]);

        let mut expected = blake3::Hasher::new();
        expected.update(b"p2pchat-v1-conv");
        expected.update(&[0x11; 32]);
        expected.update(&[0x99; 32]);

        assert_eq!(
            derive_conversation_id(&high, &low).as_bytes(),
            expected.finalize().as_bytes()
        );
    }

    #[test]
    fn different_pairs_get_different_conversations() {
        let a = Identity::generate().user_id();
        let b = Identity::generate().user_id();
        let c = Identity::generate().user_id();
        assert_ne!(
            derive_conversation_id(&a, &b),
            derive_conversation_id(&a, &c)
        );
    }

    #[test]
    fn debug_does_not_print_the_full_id() {
        let identity = Identity::generate();
        let rendered = format!("{identity:?}");
        assert!(!rendered.contains(&identity.user_id().to_hex()));
    }
}
