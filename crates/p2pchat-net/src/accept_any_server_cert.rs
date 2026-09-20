//! The permissive server-certificate verifier — `architecture.md` §3.
//!
//! It accepts **any** certificate the server presents. That is sound here and
//! only here: the QUIC certificate is transport, never identity (agent.md §3
//! invariant 11). The peer is authenticated by the inner handshake in §6,
//! which signs a transcript covering this connection's channel binding, so a
//! certificate that anyone could have minted proves nothing and is asked to
//! prove nothing.
//!
//! The verifier type is private to this module and the module is private to
//! the crate. The only thing that escapes is [`client_config`], which returns
//! a config with the ALPN already set — so the verifier cannot be lifted out
//! and bolted onto a general-purpose `rustls::ClientConfig` somewhere else.
//! If this file ever grows a `pub` on the struct, that property is gone.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

use crate::{crypto_provider, NetError};

/// A `quinn::ClientConfig` that accepts any server certificate, speaks TLS 1.3
/// only, and offers exactly `alpn`.
pub(crate) fn client_config(alpn: &[u8]) -> Result<quinn::ClientConfig, NetError> {
    let provider = crypto_provider();
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert { provider }))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![alpn.to_vec()];

    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?;
    Ok(quinn::ClientConfig::new(Arc::new(quic)))
}

#[derive(Debug)]
struct AcceptAnyServerCert {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for AcceptAnyServerCert {
    /// The whole point of the module: no chain, no name, no expiry.
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    /// The handshake signatures *are* checked. They say nothing about who the
    /// peer is — the certificate is unvetted — but an unchecked signature here
    /// would break the TLS key exchange itself, and there is no reason to
    /// accept a broken tunnel around a good handshake.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
