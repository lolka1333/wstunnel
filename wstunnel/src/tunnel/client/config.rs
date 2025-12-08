use crate::protocols::dns::DnsResolver;
use crate::somark::SoMark;
use crate::tunnel::transport::TransportAddr;
use crate::tunnel::transport::adversarial_ml::AdversarialConfig;
use crate::tunnel::transport::dpi_bypass::DpiBypassConfig;
use crate::tunnel::transport::pcap_learning::TrafficProfile;
use crate::tunnel::transport::utls::{BrowserFingerprint, UtlsConfig};
use hyper::header::{HeaderName, HeaderValue};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::{DnsName, ServerName};
use url::{Host, Url};

#[derive(Clone, Debug)]
pub struct WsClientConfig {
    pub remote_addr: TransportAddr,
    pub socket_so_mark: SoMark,
    pub http_upgrade_path_prefix: String,
    pub http_upgrade_credentials: Option<HeaderValue>,
    pub http_headers: HashMap<HeaderName, HeaderValue>,
    pub http_headers_file: Option<PathBuf>,
    pub http_header_host: HeaderValue,
    pub timeout_connect: Duration,
    pub websocket_ping_frequency: Option<Duration>,
    pub websocket_mask_frame: bool,
    pub http_proxy: Option<Url>,
    pub dns_resolver: DnsResolver,
    pub traffic_profile: Option<Arc<TrafficProfile>>,
    pub adversarial_config: Option<AdversarialConfig>,
    /// DPI bypass configuration for Russian TSPU evasion
    pub dpi_bypass_config: Option<DpiBypassConfig>,
    /// uTLS configuration for browser fingerprint mimicry
    pub utls_config: Option<UtlsClientConfig>,
}

/// uTLS configuration for browser TLS fingerprint mimicry
/// 
/// This enables the client to mimic real browser TLS fingerprints
/// to evade DPI detection based on JA3/JA4 fingerprinting.
/// 
/// ## Supported Browsers
/// - Chrome 120+ (Windows/macOS/Linux)
/// - Firefox 121+ (Windows/macOS/Linux)
/// - Safari 17+ (macOS/iOS)
/// - Edge 120+ (Windows)
/// 
/// ## Example
/// ```rust,ignore
/// let utls_config = UtlsClientConfig {
///     enabled: true,
///     fingerprint: BrowserFingerprint::Chrome120Windows,
///     enable_grease: true,
///     enable_session_resumption: true,
/// };
/// ```
#[derive(Clone, Debug)]
pub struct UtlsClientConfig {
    /// Enable uTLS browser fingerprint mimicry
    pub enabled: bool,
    
    /// Browser fingerprint to mimic
    pub fingerprint: BrowserFingerprint,
    
    /// Enable GREASE injection (RFC 8701)
    /// Critical for Chrome fingerprint authenticity
    pub enable_grease: bool,
    
    /// Enable TLS session resumption
    /// Browsers cache sessions for performance
    pub enable_session_resumption: bool,
    
    /// Enable 0-RTT early data for faster connections
    pub enable_early_data: bool,
}

impl Default for UtlsClientConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            fingerprint: BrowserFingerprint::Chrome120Windows,
            enable_grease: true,
            enable_session_resumption: true,
            enable_early_data: true,
        }
    }
}

impl UtlsClientConfig {
    /// Create configuration optimized for Russian DPI evasion
    pub fn russia_optimized() -> Self {
        Self {
            enabled: true,
            fingerprint: BrowserFingerprint::Chrome120Windows,
            enable_grease: true,
            enable_session_resumption: true,
            enable_early_data: true,
        }
    }
    
    /// Create configuration with random browser fingerprint
    pub fn randomized() -> Self {
        Self {
            enabled: true,
            fingerprint: BrowserFingerprint::Randomized,
            enable_grease: true,
            enable_session_resumption: true,
            enable_early_data: true,
        }
    }
    
    /// Convert to internal UtlsConfig
    pub fn to_utls_config(&self, verify_certificate: bool) -> UtlsConfig {
        UtlsConfig {
            fingerprint: self.fingerprint,
            custom_profile: None,
            enable_grease: self.enable_grease,
            enable_session_resumption: self.enable_session_resumption,
            enable_early_data: self.enable_early_data,
            verify_certificate,
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            timeout: std::time::Duration::from_secs(30),
        }
    }
}

impl WsClientConfig {
    pub fn tls_server_name(&self) -> ServerName<'static> {
        static INVALID_DNS_NAME: LazyLock<DnsName> =
            LazyLock::new(|| DnsName::try_from("dns-name-invalid.com").unwrap());

        self.remote_addr
            .tls()
            .and_then(|tls| tls.tls_sni_override.as_ref())
            .map_or_else(
                || match &self.remote_addr.host() {
                    Host::Domain(domain) => ServerName::DnsName(
                        DnsName::try_from(domain.clone()).unwrap_or_else(|_| INVALID_DNS_NAME.clone()),
                    ),
                    Host::Ipv4(ip) => ServerName::IpAddress(IpAddr::V4(*ip).into()),
                    Host::Ipv6(ip) => ServerName::IpAddress(IpAddr::V6(*ip).into()),
                },
                |sni_override| ServerName::DnsName(sni_override.clone()),
            )
    }
}

#[derive(Clone)]
pub struct TlsClientConfig {
    pub tls_sni_disabled: bool,
    pub tls_sni_override: Option<DnsName<'static>>,
    pub tls_verify_certificate: bool,
    pub tls_connector: Arc<RwLock<TlsConnector>>,
    pub tls_certificate_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
}

impl TlsClientConfig {
    pub fn tls_connector(&self) -> TlsConnector {
        self.tls_connector.read().clone()
    }
}
