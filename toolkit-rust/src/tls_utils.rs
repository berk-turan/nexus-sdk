use {
    anyhow::{Context, Result},
    futures_util::TryStreamExt,
    pkcs8::{EncodePrivateKey, EncodePublicKey},
    rustls::{
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        crypto::ring::sign::any_supported_type,
        pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
        server::{AlwaysResolvesServerRawPublicKeys, ServerConfig as RustlsServerConfig},
        DigitallySignedStruct,
        Error as RustlsError,
        SignatureScheme,
    },
    sha2::{Digest, Sha256},
    std::{fs, net::SocketAddr, path::Path, sync::Arc},
    subtle::ConstantTimeEq,
    tokio::net::TcpListener,
    tokio_rustls::TlsAcceptor,
    tokio_stream::wrappers::TcpListenerStream,
    warp::Filter,
};

/// Build a [`rustls::ServerConfig`] that serves only raw‑public‑key TLS 1.3.
pub fn server_cfg<P: AsRef<Path>>(key_path: P) -> Result<RustlsServerConfig> {
    // 1. Read private key
    let key_bytes = fs::read(&key_path)
        .with_context(|| format!("reading key file {}", key_path.as_ref().display()))?;
    let key_der = PrivateKeyDer::Pkcs8(key_bytes.clone().into());

    // 2. Turn it into a signer
    let signer = any_supported_type(&key_der)
        .context("unsupported key type - expecting Ed25519 or ECDSA PKCS#8")?;

    // 3. Extract SPKI so we can advertise it in the handshake
    // Extract public key from the signer and create SPKI
    let public_key_der = signer.public_key().expect("signer should have public key");
    let spki: CertificateDer<'static> = public_key_der.as_ref().to_vec().into();

    // 4. Bundle into a CertifiedKey for rustls
    let certified_key = rustls::sign::CertifiedKey {
        cert: vec![spki],
        key: signer,
        ocsp: None,
    };

    let resolver = AlwaysResolvesServerRawPublicKeys::new(Arc::new(certified_key));

    Ok(RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver)))
}

/// Certificate verifier that pins specific public key hashes
#[derive(Debug)]
pub struct Pinned(pub Vec<[u8; 32]>);

impl ServerCertVerifier for Pinned {
    fn requires_raw_public_keys(&self) -> bool {
        true // we expect RFC 7250
    }

    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>, // SNI ignored – we rely purely on pinning
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let digest = spki_sha256(end_entity);
        for pin in &self.0 {
            if pin.ct_eq(&digest).into() {
                return Ok(ServerCertVerified::assertion());
            }
        }
        Err(RustlsError::General("public key pin mismatch".to_string()))
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }
}

/// Build a [`reqwest::Client`] that pins `sha256(spki)` (hex‑encoded).
pub fn reqwest_with_pin(hash_hex: &str) -> Result<reqwest::Client> {
    let bytes = hex::decode(hash_hex).context("hash must be hex")?;
    let pin: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .context("hash must be 32 bytes (SHA‑256)")?;

    let tls_cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned(vec![pin])))
        .with_no_client_auth();

    reqwest::Client::builder()
        .use_preconfigured_tls(tls_cfg)
        .build()
        .context("building reqwest client")
}

/// Generate a fresh Ed25519 keypair, save it to `out`, and return
/// `sha256(spki)` for on‑chain registration.
pub fn generate_key_and_hash<P: AsRef<Path>>(out: P) -> Result<[u8; 32]> {
    use ed25519_dalek::SigningKey;

    let sk = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let der_bytes = sk.to_pkcs8_der()?;
    fs::write(&out, der_bytes.as_bytes())?;

    let public_key_der = sk.verifying_key().to_public_key_der()?;
    Ok(Sha256::digest(public_key_der.as_bytes()).into())
}

/// Convenience alias for backward compatibility - generates a key and returns hash as hex string
pub fn generate_key<P: AsRef<Path>>(out: P) -> std::io::Result<String> {
    match generate_key_and_hash(&out) {
        Ok(hash) => Ok(hex::encode(hash)),
        Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
    }
}

/// Convenience helper shared by client and verifier.
#[inline]
pub fn spki_sha256(spki: &CertificateDer<'_>) -> [u8; 32] {
    Sha256::digest(spki.as_ref()).into()
}

/// Spawn a Warp server that speaks raw-public-key TLS on `addr`.
pub async fn spawn_tls_server<F>(
    routes: F,
    addr: SocketAddr,
    acceptor: TlsAcceptor,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    F: Filter + Clone + Send + Sync + 'static,
    F::Extract: warp::reply::Reply + Send + 'static,
{
    // 1. Bind plain TCP
    let listener = TcpListener::bind(addr).await?;

    // 2. Wrap in a TryStream and upgrade each socket with Rustls
    let incoming_tls = TcpListenerStream::new(listener).and_then(move |tcp| {
        let acc = acceptor.clone();
        async move {
            match acc.accept(tcp).await {
                Ok(tls_stream) => Ok(tls_stream),
                Err(e) => {
                    // Log TLS handshake failures but don't kill the server
                    eprintln!("TLS handshake failed: {}", e);
                    Err(std::io::Error::new(std::io::ErrorKind::Other, e))
                }
            }
        }
    });

    // 3. Hand the TLS stream to Warp
    // It will do simple HTTP so not sure if the best option.
    warp::serve(routes).run_incoming(incoming_tls).await;

    Ok(())
}
