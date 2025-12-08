/// uTLS Browser Fingerprint Module
/// 
/// This module provides complete browser TLS fingerprint mimicry for DPI evasion.
/// Unlike rustls, this implementation supports:
/// - Full GREASE injection (RFC 8701)
/// - Exact browser ClientHello reproduction
/// - JA3/JA4 fingerprint matching
/// - Extension order customization
/// - Cipher suite ordering
///
/// ## Supported Browsers
/// - Chrome 120+ (Windows/macOS/Linux)
/// - Firefox 121+ (Windows/macOS/Linux)
/// - Safari 17+ (macOS/iOS)
/// - Edge 120+ (Windows)
/// - Android Chrome
/// - iOS Safari
///
/// ## Why uTLS?
/// Russian DPI (TSPU) uses JA3/JA4 fingerprinting to detect tunnel software.
/// Standard TLS libraries (rustls, OpenSSL) have distinctive fingerprints.
/// uTLS allows mimicking real browser fingerprints to bypass detection.
///
/// ## Implementation
/// Uses BoringSSL (via boring crate) which supports:
/// - Full ClientHello customization
/// - GREASE values
/// - All cipher suites and extensions
/// - Session resumption with browser-like behavior

use std::sync::atomic::{AtomicU64, Ordering};
use rand::Rng;

/// Global state for GREASE value rotation
static GREASE_STATE: AtomicU64 = AtomicU64::new(0xDEADBEEF_CAFEBABE);

/// GREASE values from RFC 8701
/// These reserved values are ignored by servers but used for fingerprinting
pub const GREASE_VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
    0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// TLS cipher suite identifiers
#[allow(dead_code)]
pub mod cipher_suites {
    // TLS 1.3 cipher suites
    pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
    pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
    pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
    
    // TLS 1.2 ECDHE cipher suites
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02b;
    pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02f;
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: u16 = 0xc02c;
    pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: u16 = 0xc030;
    pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xcca9;
    pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xcca8;
    
    // Legacy cipher suites (for compatibility)
    pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: u16 = 0xc013;
    pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: u16 = 0xc014;
    pub const TLS_RSA_WITH_AES_128_GCM_SHA256: u16 = 0x009c;
    pub const TLS_RSA_WITH_AES_256_GCM_SHA384: u16 = 0x009d;
    pub const TLS_RSA_WITH_AES_128_CBC_SHA: u16 = 0x002f;
    pub const TLS_RSA_WITH_AES_256_CBC_SHA: u16 = 0x0035;
}

/// TLS extension identifiers
#[allow(dead_code)]
pub mod extensions {
    pub const SERVER_NAME: u16 = 0x0000;
    pub const STATUS_REQUEST: u16 = 0x0005;
    pub const SUPPORTED_GROUPS: u16 = 0x000a;
    pub const EC_POINT_FORMATS: u16 = 0x000b;
    pub const SIGNATURE_ALGORITHMS: u16 = 0x000d;
    pub const ALPN: u16 = 0x0010;
    pub const SIGNED_CERTIFICATE_TIMESTAMP: u16 = 0x0012;
    pub const PADDING: u16 = 0x0015;
    pub const EXTENDED_MASTER_SECRET: u16 = 0x0017;
    pub const COMPRESS_CERTIFICATE: u16 = 0x001b;
    pub const SESSION_TICKET: u16 = 0x0023;
    pub const SUPPORTED_VERSIONS: u16 = 0x002b;
    pub const PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
    pub const KEY_SHARE: u16 = 0x0033;
    pub const RENEGOTIATION_INFO: u16 = 0xff01;
    pub const ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
    pub const APPLICATION_SETTINGS: u16 = 0x4469; // ALPS
    pub const DELEGATED_CREDENTIALS: u16 = 0x0022;
}

/// Supported groups (elliptic curves)
#[allow(dead_code)]
pub mod groups {
    pub const X25519: u16 = 0x001d;
    pub const SECP256R1: u16 = 0x0017;
    pub const SECP384R1: u16 = 0x0018;
    pub const SECP521R1: u16 = 0x0019;
    pub const X25519_KYBER768: u16 = 0x6399; // Post-quantum hybrid
    pub const FFDHE2048: u16 = 0x0100;
    pub const FFDHE3072: u16 = 0x0101;
}

/// Signature algorithms
#[allow(dead_code)]
pub mod signature_algorithms {
    pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
    pub const ECDSA_SECP384R1_SHA384: u16 = 0x0503;
    pub const ECDSA_SECP521R1_SHA512: u16 = 0x0603;
    pub const RSA_PSS_RSAE_SHA256: u16 = 0x0804;
    pub const RSA_PSS_RSAE_SHA384: u16 = 0x0805;
    pub const RSA_PSS_RSAE_SHA512: u16 = 0x0806;
    pub const RSA_PKCS1_SHA256: u16 = 0x0401;
    pub const RSA_PKCS1_SHA384: u16 = 0x0501;
    pub const RSA_PKCS1_SHA512: u16 = 0x0601;
    pub const ED25519: u16 = 0x0807;
    pub const ED448: u16 = 0x0808;
}

/// Browser fingerprint identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BrowserFingerprint {
    /// Chrome 120 on Windows
    Chrome120Windows,
    /// Chrome 120 on macOS
    Chrome120MacOS,
    /// Chrome 120 on Linux
    Chrome120Linux,
    /// Chrome on Android
    ChromeAndroid,
    /// Firefox 121 on Windows
    Firefox121Windows,
    /// Firefox 121 on macOS
    Firefox121MacOS,
    /// Safari 17 on macOS
    Safari17MacOS,
    /// Safari on iOS 17
    SafariIOS17,
    /// Edge 120 on Windows
    Edge120Windows,
    /// Randomized fingerprint (rotates each connection)
    Randomized,
    /// Custom fingerprint (user-defined)
    Custom,
}

impl std::str::FromStr for BrowserFingerprint {
    type Err = String;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "chrome" | "chrome120" | "chrome_windows" | "chrome120_windows" => Ok(Self::Chrome120Windows),
            "chrome_macos" | "chrome120_macos" => Ok(Self::Chrome120MacOS),
            "chrome_linux" | "chrome120_linux" => Ok(Self::Chrome120Linux),
            "chrome_android" => Ok(Self::ChromeAndroid),
            "firefox" | "firefox121" | "firefox_windows" | "firefox121_windows" => Ok(Self::Firefox121Windows),
            "firefox_macos" | "firefox121_macos" => Ok(Self::Firefox121MacOS),
            "safari" | "safari17" | "safari_macos" | "safari17_macos" => Ok(Self::Safari17MacOS),
            "safari_ios" | "safari_ios17" => Ok(Self::SafariIOS17),
            "edge" | "edge120" | "edge_windows" | "edge120_windows" => Ok(Self::Edge120Windows),
            "random" | "randomized" => Ok(Self::Randomized),
            "custom" => Ok(Self::Custom),
            _ => Err(format!("Unknown browser fingerprint: {}", s)),
        }
    }
}

impl std::fmt::Display for BrowserFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Chrome120Windows => write!(f, "Chrome 120 Windows"),
            Self::Chrome120MacOS => write!(f, "Chrome 120 macOS"),
            Self::Chrome120Linux => write!(f, "Chrome 120 Linux"),
            Self::ChromeAndroid => write!(f, "Chrome Android"),
            Self::Firefox121Windows => write!(f, "Firefox 121 Windows"),
            Self::Firefox121MacOS => write!(f, "Firefox 121 macOS"),
            Self::Safari17MacOS => write!(f, "Safari 17 macOS"),
            Self::SafariIOS17 => write!(f, "Safari iOS 17"),
            Self::Edge120Windows => write!(f, "Edge 120 Windows"),
            Self::Randomized => write!(f, "Randomized"),
            Self::Custom => write!(f, "Custom"),
        }
    }
}

/// Complete browser TLS fingerprint profile
#[derive(Debug, Clone)]
pub struct UtlsProfile {
    /// Profile name
    pub name: String,
    
    /// Browser fingerprint type
    pub fingerprint: BrowserFingerprint,
    
    /// TLS record version (0x0301 = TLS 1.0 in record layer, always used)
    pub record_version: u16,
    
    /// Handshake version (0x0303 = TLS 1.2, actual version in supported_versions ext)
    pub handshake_version: u16,
    
    /// Cipher suites in exact browser order (with GREASE positions)
    pub cipher_suites: Vec<u16>,
    
    /// Cipher suite GREASE positions (indices where GREASE should be inserted)
    pub cipher_grease_positions: Vec<usize>,
    
    /// TLS extensions in exact browser order
    pub extensions: Vec<u16>,
    
    /// Extension GREASE positions
    pub extension_grease_positions: Vec<usize>,
    
    /// Supported groups (elliptic curves)
    pub supported_groups: Vec<u16>,
    
    /// Supported groups GREASE positions
    pub groups_grease_positions: Vec<usize>,
    
    /// EC point formats
    pub ec_point_formats: Vec<u8>,
    
    /// Signature algorithms
    pub signature_algorithms: Vec<u16>,
    
    /// ALPN protocols
    pub alpn_protocols: Vec<String>,
    
    /// Compression methods (0x00 = null compression)
    pub compression_methods: Vec<u8>,
    
    /// Session ticket hint (seconds)
    pub session_ticket_lifetime: u32,
    
    /// PSK key exchange modes
    pub psk_modes: Vec<u8>,
    
    /// Certificate compression algorithms
    pub cert_compression_algs: Vec<u16>,
    
    /// Target ClientHello size for padding
    pub target_client_hello_size: usize,
    
    /// Enable 0-RTT early data
    pub enable_early_data: bool,
    
    /// Enable session resumption
    pub enable_session_resumption: bool,
    
    /// Use post-quantum key exchange (X25519Kyber768)
    pub enable_post_quantum: bool,
    
    /// Minimum TLS version
    pub min_version: u16,
    
    /// Maximum TLS version
    pub max_version: u16,
    
    /// Expected JA3 hash (for validation)
    pub expected_ja3: Option<String>,
    
    /// Expected JA4 fingerprint (for validation)
    pub expected_ja4: Option<String>,
}

impl UtlsProfile {
    /// Chrome 120 on Windows - Most common browser fingerprint
    /// 
    /// JA3: 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0
    pub fn chrome_120_windows() -> Self {
        use cipher_suites::*;
        use extensions::*;
        use groups::*;
        use signature_algorithms::*;
        
        Self {
            name: "Chrome 120 Windows".to_string(),
            fingerprint: BrowserFingerprint::Chrome120Windows,
            record_version: 0x0301, // TLS 1.0 in record layer
            handshake_version: 0x0303, // TLS 1.2 in ClientHello
            cipher_suites: vec![
                // GREASE inserted at position 0
                TLS_AES_128_GCM_SHA256,
                TLS_AES_256_GCM_SHA384,
                TLS_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                TLS_RSA_WITH_AES_128_GCM_SHA256,
                TLS_RSA_WITH_AES_256_GCM_SHA384,
                TLS_RSA_WITH_AES_128_CBC_SHA,
                TLS_RSA_WITH_AES_256_CBC_SHA,
            ],
            cipher_grease_positions: vec![0], // GREASE at start
            extensions: vec![
                // GREASE at position 0
                SERVER_NAME,                    // 0
                EXTENDED_MASTER_SECRET,         // 23
                RENEGOTIATION_INFO,             // 65281
                SUPPORTED_GROUPS,               // 10
                EC_POINT_FORMATS,               // 11
                SESSION_TICKET,                 // 35
                ALPN,                           // 16
                STATUS_REQUEST,                 // 5
                SIGNATURE_ALGORITHMS,           // 13
                SIGNED_CERTIFICATE_TIMESTAMP,   // 18
                KEY_SHARE,                      // 51
                PSK_KEY_EXCHANGE_MODES,         // 45
                SUPPORTED_VERSIONS,             // 43
                COMPRESS_CERTIFICATE,           // 27
                APPLICATION_SETTINGS,           // 17513
                // GREASE before padding
                PADDING,                        // 21
            ],
            extension_grease_positions: vec![0, 15], // GREASE at start and before padding
            supported_groups: vec![
                // GREASE at position 0
                X25519,
                SECP256R1,
                SECP384R1,
            ],
            groups_grease_positions: vec![0],
            ec_point_formats: vec![0x00], // Uncompressed only
            signature_algorithms: vec![
                ECDSA_SECP256R1_SHA256,
                RSA_PSS_RSAE_SHA256,
                RSA_PKCS1_SHA256,
                ECDSA_SECP384R1_SHA384,
                RSA_PSS_RSAE_SHA384,
                RSA_PKCS1_SHA384,
                RSA_PSS_RSAE_SHA512,
                RSA_PKCS1_SHA512,
            ],
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            compression_methods: vec![0x00], // Null compression
            session_ticket_lifetime: 604800, // 7 days
            psk_modes: vec![0x01], // psk_dhe_ke
            cert_compression_algs: vec![0x0002], // brotli
            target_client_hello_size: 517, // Chrome's typical size
            enable_early_data: true,
            enable_session_resumption: true,
            enable_post_quantum: false, // Chrome 120 doesn't enable by default
            min_version: 0x0303, // TLS 1.2
            max_version: 0x0304, // TLS 1.3
            expected_ja3: None,
            expected_ja4: None,
        }
    }
    
    /// Chrome 120 on macOS
    pub fn chrome_120_macos() -> Self {
        let mut profile = Self::chrome_120_windows();
        profile.name = "Chrome 120 macOS".to_string();
        profile.fingerprint = BrowserFingerprint::Chrome120MacOS;
        profile
    }
    
    /// Chrome 120 on Linux
    pub fn chrome_120_linux() -> Self {
        let mut profile = Self::chrome_120_windows();
        profile.name = "Chrome 120 Linux".to_string();
        profile.fingerprint = BrowserFingerprint::Chrome120Linux;
        profile
    }
    
    /// Chrome on Android
    pub fn chrome_android() -> Self {
        use cipher_suites::*;
        use extensions::*;
        use groups::*;
        use signature_algorithms::*;
        
        Self {
            name: "Chrome Android".to_string(),
            fingerprint: BrowserFingerprint::ChromeAndroid,
            record_version: 0x0301,
            handshake_version: 0x0303,
            cipher_suites: vec![
                TLS_AES_128_GCM_SHA256,
                TLS_AES_256_GCM_SHA384,
                TLS_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ],
            cipher_grease_positions: vec![0],
            extensions: vec![
                SERVER_NAME,
                EXTENDED_MASTER_SECRET,
                RENEGOTIATION_INFO,
                SUPPORTED_GROUPS,
                EC_POINT_FORMATS,
                SESSION_TICKET,
                ALPN,
                STATUS_REQUEST,
                SIGNATURE_ALGORITHMS,
                KEY_SHARE,
                PSK_KEY_EXCHANGE_MODES,
                SUPPORTED_VERSIONS,
                COMPRESS_CERTIFICATE,
                PADDING,
            ],
            extension_grease_positions: vec![0, 13],
            supported_groups: vec![X25519, SECP256R1, SECP384R1],
            groups_grease_positions: vec![0],
            ec_point_formats: vec![0x00],
            signature_algorithms: vec![
                ECDSA_SECP256R1_SHA256,
                RSA_PSS_RSAE_SHA256,
                RSA_PKCS1_SHA256,
                ECDSA_SECP384R1_SHA384,
                RSA_PSS_RSAE_SHA384,
                RSA_PKCS1_SHA384,
            ],
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            compression_methods: vec![0x00],
            session_ticket_lifetime: 604800,
            psk_modes: vec![0x01],
            cert_compression_algs: vec![0x0002],
            target_client_hello_size: 480,
            enable_early_data: true,
            enable_session_resumption: true,
            enable_post_quantum: false,
            min_version: 0x0303,
            max_version: 0x0304,
            expected_ja3: None,
            expected_ja4: None,
        }
    }
    
    /// Firefox 121 on Windows
    /// 
    /// Firefox differs from Chrome:
    /// - Different cipher suite order
    /// - Uses GREASE but less frequently
    /// - Different extension order
    pub fn firefox_121_windows() -> Self {
        use cipher_suites::*;
        use extensions::*;
        use groups::*;
        use signature_algorithms::*;
        
        Self {
            name: "Firefox 121 Windows".to_string(),
            fingerprint: BrowserFingerprint::Firefox121Windows,
            record_version: 0x0301,
            handshake_version: 0x0303,
            cipher_suites: vec![
                TLS_AES_128_GCM_SHA256,
                TLS_CHACHA20_POLY1305_SHA256,
                TLS_AES_256_GCM_SHA384,
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                TLS_RSA_WITH_AES_128_GCM_SHA256,
                TLS_RSA_WITH_AES_256_GCM_SHA384,
                TLS_RSA_WITH_AES_128_CBC_SHA,
                TLS_RSA_WITH_AES_256_CBC_SHA,
            ],
            cipher_grease_positions: vec![], // Firefox typically doesn't GREASE cipher suites
            extensions: vec![
                SERVER_NAME,
                EXTENDED_MASTER_SECRET,
                RENEGOTIATION_INFO,
                SUPPORTED_GROUPS,
                EC_POINT_FORMATS,
                SESSION_TICKET,
                ALPN,
                STATUS_REQUEST,
                DELEGATED_CREDENTIALS,
                KEY_SHARE,
                SUPPORTED_VERSIONS,
                SIGNATURE_ALGORITHMS,
                PSK_KEY_EXCHANGE_MODES,
                PADDING,
            ],
            extension_grease_positions: vec![],
            supported_groups: vec![
                X25519,
                SECP256R1,
                SECP384R1,
                SECP521R1,
                FFDHE2048,
                FFDHE3072,
            ],
            groups_grease_positions: vec![],
            ec_point_formats: vec![0x00],
            signature_algorithms: vec![
                ECDSA_SECP256R1_SHA256,
                ECDSA_SECP384R1_SHA384,
                ECDSA_SECP521R1_SHA512,
                RSA_PSS_RSAE_SHA256,
                RSA_PSS_RSAE_SHA384,
                RSA_PSS_RSAE_SHA512,
                RSA_PKCS1_SHA256,
                RSA_PKCS1_SHA384,
                RSA_PKCS1_SHA512,
                ED25519,
                ED448,
            ],
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            compression_methods: vec![0x00],
            session_ticket_lifetime: 604800,
            psk_modes: vec![0x01],
            cert_compression_algs: vec![0x0002, 0x0001], // brotli, zlib
            target_client_hello_size: 512,
            enable_early_data: true,
            enable_session_resumption: true,
            enable_post_quantum: false,
            min_version: 0x0303,
            max_version: 0x0304,
            expected_ja3: None,
            expected_ja4: None,
        }
    }
    
    /// Firefox 121 on macOS
    pub fn firefox_121_macos() -> Self {
        let mut profile = Self::firefox_121_windows();
        profile.name = "Firefox 121 macOS".to_string();
        profile.fingerprint = BrowserFingerprint::Firefox121MacOS;
        profile
    }
    
    /// Safari 17 on macOS
    /// 
    /// Safari has distinct fingerprint:
    /// - Prefers ECDSA over RSA
    /// - Different extension set
    /// - No GREASE
    pub fn safari_17_macos() -> Self {
        use cipher_suites::*;
        use extensions::*;
        use groups::*;
        use signature_algorithms::*;
        
        Self {
            name: "Safari 17 macOS".to_string(),
            fingerprint: BrowserFingerprint::Safari17MacOS,
            record_version: 0x0301,
            handshake_version: 0x0303,
            cipher_suites: vec![
                TLS_AES_128_GCM_SHA256,
                TLS_AES_256_GCM_SHA384,
                TLS_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_RSA_WITH_AES_256_GCM_SHA384,
                TLS_RSA_WITH_AES_128_GCM_SHA256,
            ],
            cipher_grease_positions: vec![],
            extensions: vec![
                SERVER_NAME,
                EXTENDED_MASTER_SECRET,
                RENEGOTIATION_INFO,
                SUPPORTED_GROUPS,
                EC_POINT_FORMATS,
                ALPN,
                STATUS_REQUEST,
                SIGNATURE_ALGORITHMS,
                SIGNED_CERTIFICATE_TIMESTAMP,
                KEY_SHARE,
                PSK_KEY_EXCHANGE_MODES,
                SUPPORTED_VERSIONS,
                PADDING,
            ],
            extension_grease_positions: vec![],
            supported_groups: vec![
                X25519,
                SECP256R1,
                SECP384R1,
                SECP521R1,
            ],
            groups_grease_positions: vec![],
            ec_point_formats: vec![0x00],
            signature_algorithms: vec![
                ECDSA_SECP256R1_SHA256,
                ECDSA_SECP384R1_SHA384,
                ECDSA_SECP521R1_SHA512,
                RSA_PSS_RSAE_SHA256,
                RSA_PSS_RSAE_SHA384,
                RSA_PSS_RSAE_SHA512,
                RSA_PKCS1_SHA256,
                RSA_PKCS1_SHA384,
                RSA_PKCS1_SHA512,
            ],
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            compression_methods: vec![0x00],
            session_ticket_lifetime: 604800,
            psk_modes: vec![0x01, 0x00], // psk_dhe_ke, psk_ke
            cert_compression_algs: vec![],
            target_client_hello_size: 0, // Safari doesn't pad
            enable_early_data: true,
            enable_session_resumption: true,
            enable_post_quantum: false,
            min_version: 0x0303,
            max_version: 0x0304,
            expected_ja3: None,
            expected_ja4: None,
        }
    }
    
    /// Safari on iOS 17
    pub fn safari_ios_17() -> Self {
        let mut profile = Self::safari_17_macos();
        profile.name = "Safari iOS 17".to_string();
        profile.fingerprint = BrowserFingerprint::SafariIOS17;
        profile
    }
    
    /// Edge 120 on Windows (based on Chromium, nearly identical to Chrome)
    pub fn edge_120_windows() -> Self {
        let mut profile = Self::chrome_120_windows();
        profile.name = "Edge 120 Windows".to_string();
        profile.fingerprint = BrowserFingerprint::Edge120Windows;
        profile
    }
    
    /// Get profile by fingerprint type
    pub fn from_fingerprint(fp: BrowserFingerprint) -> Self {
        match fp {
            BrowserFingerprint::Chrome120Windows => Self::chrome_120_windows(),
            BrowserFingerprint::Chrome120MacOS => Self::chrome_120_macos(),
            BrowserFingerprint::Chrome120Linux => Self::chrome_120_linux(),
            BrowserFingerprint::ChromeAndroid => Self::chrome_android(),
            BrowserFingerprint::Firefox121Windows => Self::firefox_121_windows(),
            BrowserFingerprint::Firefox121MacOS => Self::firefox_121_macos(),
            BrowserFingerprint::Safari17MacOS => Self::safari_17_macos(),
            BrowserFingerprint::SafariIOS17 => Self::safari_ios_17(),
            BrowserFingerprint::Edge120Windows => Self::edge_120_windows(),
            BrowserFingerprint::Randomized => Self::random(),
            BrowserFingerprint::Custom => Self::chrome_120_windows(), // Default for custom
        }
    }
    
    /// Get a random browser profile
    pub fn random() -> Self {
        let profiles = [
            BrowserFingerprint::Chrome120Windows,
            BrowserFingerprint::Chrome120MacOS,
            BrowserFingerprint::Firefox121Windows,
            BrowserFingerprint::Safari17MacOS,
            BrowserFingerprint::Edge120Windows,
        ];
        
        let idx = rand::rng().random_range(0..profiles.len());
        let mut profile = Self::from_fingerprint(profiles[idx]);
        profile.fingerprint = BrowserFingerprint::Randomized;
        profile
    }
    
    /// Select a GREASE value for this connection
    pub fn select_grease_value(&self) -> u16 {
        let state = GREASE_STATE.fetch_add(1, Ordering::Relaxed);
        GREASE_VALUES[(state as usize) % GREASE_VALUES.len()]
    }
    
    /// Get cipher suites with GREASE values inserted
    pub fn cipher_suites_with_grease(&self) -> Vec<u16> {
        let mut suites = self.cipher_suites.clone();
        
        // Insert GREASE values at specified positions (reverse order to maintain indices)
        for &pos in self.cipher_grease_positions.iter().rev() {
            if pos <= suites.len() {
                suites.insert(pos, self.select_grease_value());
            }
        }
        
        suites
    }
    
    /// Get extensions with GREASE values inserted
    pub fn extensions_with_grease(&self) -> Vec<u16> {
        let mut exts = self.extensions.clone();
        
        for &pos in self.extension_grease_positions.iter().rev() {
            if pos <= exts.len() {
                exts.insert(pos, self.select_grease_value());
            }
        }
        
        exts
    }
    
    /// Get supported groups with GREASE values inserted
    pub fn supported_groups_with_grease(&self) -> Vec<u16> {
        let mut groups = self.supported_groups.clone();
        
        for &pos in self.groups_grease_positions.iter().rev() {
            if pos <= groups.len() {
                groups.insert(pos, self.select_grease_value());
            }
        }
        
        groups
    }
    
    /// Calculate JA3 fingerprint string (before MD5 hashing)
    pub fn calculate_ja3_string(&self) -> String {
        // JA3 = TLSVersion,CipherSuites,Extensions,SupportedGroups,ECPointFormats
        
        let cipher_str: String = self.cipher_suites
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-");
        
        let ext_str: String = self.extensions
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("-");
        
        let groups_str: String = self.supported_groups
            .iter()
            .map(|g| g.to_string())
            .collect::<Vec<_>>()
            .join("-");
        
        let formats_str: String = self.ec_point_formats
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join("-");
        
        format!("{},{},{},{},{}", 
            self.handshake_version as u32, // 771 for TLS 1.2
            cipher_str, 
            ext_str, 
            groups_str, 
            formats_str
        )
    }
}

/// uTLS configuration for connection
#[derive(Debug, Clone)]
pub struct UtlsConfig {
    /// Browser fingerprint to use
    pub fingerprint: BrowserFingerprint,
    
    /// Custom profile (used when fingerprint is Custom)
    pub custom_profile: Option<UtlsProfile>,
    
    /// Enable GREASE injection
    pub enable_grease: bool,
    
    /// Enable session resumption
    pub enable_session_resumption: bool,
    
    /// Enable 0-RTT early data
    pub enable_early_data: bool,
    
    /// Verify server certificate
    pub verify_certificate: bool,
    
    /// ALPN protocols
    pub alpn_protocols: Vec<String>,
    
    /// Connection timeout
    pub timeout: std::time::Duration,
}

impl Default for UtlsConfig {
    fn default() -> Self {
        Self {
            fingerprint: BrowserFingerprint::Chrome120Windows,
            custom_profile: None,
            enable_grease: true,
            enable_session_resumption: true,
            enable_early_data: true,
            verify_certificate: true,
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            timeout: std::time::Duration::from_secs(30),
        }
    }
}

impl UtlsConfig {
    /// Create config optimized for Russian DPI evasion
    pub fn russia_optimized() -> Self {
        Self {
            fingerprint: BrowserFingerprint::Chrome120Windows,
            custom_profile: None,
            enable_grease: true,
            enable_session_resumption: true,
            enable_early_data: true,
            verify_certificate: false, // Many users disable for self-signed certs
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            timeout: std::time::Duration::from_secs(30),
        }
    }
    
    /// Create config for maximum stealth
    pub fn maximum_stealth() -> Self {
        Self {
            fingerprint: BrowserFingerprint::Randomized,
            custom_profile: None,
            enable_grease: true,
            enable_session_resumption: true,
            enable_early_data: true,
            verify_certificate: true,
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            timeout: std::time::Duration::from_secs(30),
        }
    }
    
    /// Get the effective profile
    pub fn get_profile(&self) -> UtlsProfile {
        if let Some(custom) = &self.custom_profile {
            return custom.clone();
        }
        UtlsProfile::from_fingerprint(self.fingerprint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_browser_fingerprint_parsing() {
        assert_eq!(
            "chrome".parse::<BrowserFingerprint>().unwrap(),
            BrowserFingerprint::Chrome120Windows
        );
        assert_eq!(
            "firefox".parse::<BrowserFingerprint>().unwrap(),
            BrowserFingerprint::Firefox121Windows
        );
        assert_eq!(
            "safari".parse::<BrowserFingerprint>().unwrap(),
            BrowserFingerprint::Safari17MacOS
        );
    }
    
    #[test]
    fn test_chrome_profile() {
        let profile = UtlsProfile::chrome_120_windows();
        
        // Chrome should have GREASE positions
        assert!(!profile.cipher_grease_positions.is_empty());
        assert!(!profile.extension_grease_positions.is_empty());
        
        // Chrome should support TLS 1.3
        assert_eq!(profile.max_version, 0x0304);
        
        // Chrome should have ALPN
        assert!(profile.alpn_protocols.contains(&"h2".to_string()));
    }
    
    #[test]
    fn test_grease_insertion() {
        let profile = UtlsProfile::chrome_120_windows();
        
        let suites_with_grease = profile.cipher_suites_with_grease();
        
        // Should have one more entry than original
        assert_eq!(suites_with_grease.len(), profile.cipher_suites.len() + 1);
        
        // First entry should be GREASE
        assert!(GREASE_VALUES.contains(&suites_with_grease[0]));
    }
    
    #[test]
    fn test_firefox_no_cipher_grease() {
        let profile = UtlsProfile::firefox_121_windows();
        
        // Firefox doesn't GREASE cipher suites
        assert!(profile.cipher_grease_positions.is_empty());
        
        let suites_with_grease = profile.cipher_suites_with_grease();
        assert_eq!(suites_with_grease.len(), profile.cipher_suites.len());
    }
    
    #[test]
    fn test_ja3_string() {
        let profile = UtlsProfile::chrome_120_windows();
        let ja3 = profile.calculate_ja3_string();
        
        // Should contain TLS version 771 (0x0303)
        assert!(ja3.starts_with("771,"));
        
        // Should have 5 comma-separated sections
        assert_eq!(ja3.split(',').count(), 5);
    }
    
    #[test]
    fn test_random_profile() {
        let profile1 = UtlsProfile::random();
        let profile2 = UtlsProfile::random();
        
        // Both should be valid profiles
        assert!(!profile1.cipher_suites.is_empty());
        assert!(!profile2.cipher_suites.is_empty());
    }
}
