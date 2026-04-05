use std::sync::Once;

static INSTALL_RUSTLS_PROVIDER: Once = Once::new();

pub fn ensure_rustls_crypto_provider() {
    INSTALL_RUSTLS_PROVIDER.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}
