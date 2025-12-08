use hyper::header::HOST;
use hyper::http::{HeaderName, HeaderValue};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::str::FromStr;

use tracing::error;

pub mod adversarial_ml;
pub mod alpn_profiles;
pub mod cookies;
pub mod dpi_bypass;
pub mod http2;
pub mod io;
pub mod ip_fragmentation;
mod jwt;
pub mod packet_shaping;
pub mod pcap_learning;
pub mod sni_fragmentation;
pub mod tcp_fragmentation;
pub mod tls_fingerprint;
mod types;
pub mod websocket;
pub mod ws_masking;

// uTLS - Browser fingerprint TLS for DPI evasion
pub mod utls;
pub mod utls_connector;

pub use jwt::JWT_HEADER_PREFIX;
pub use jwt::JwtTunnelConfig;
pub use jwt::jwt_token_to_tunnel;
pub use jwt::tunnel_to_jwt_token;
pub use types::TransportAddr;
pub use types::TransportScheme;

// uTLS re-exports
pub use utls::{BrowserFingerprint, UtlsConfig, UtlsProfile};
pub use utls_connector::{UtlsConnector, UtlsTlsStream};

#[allow(clippy::type_complexity)]
#[inline]
pub fn headers_from_file(path: &Path) -> (Option<(HeaderName, HeaderValue)>, Vec<(HeaderName, HeaderValue)>) {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(err) => {
            error!("Cannot read headers from file: {:?}: {:?}", path, err);
            return (None, vec![]);
        }
    };

    let mut host_header = None;
    let headers = BufReader::new(file)
        .lines()
        .filter_map(|line| {
            let line = line.ok()?;
            let (header, value) = line.split_once(':')?;
            let header = HeaderName::from_str(header.trim()).ok()?;
            let value = HeaderValue::from_str(value.trim()).ok()?;
            if header == HOST {
                host_header = Some((header, value));
                return None;
            }
            Some((header, value))
        })
        .collect();

    (host_header, headers)
}
