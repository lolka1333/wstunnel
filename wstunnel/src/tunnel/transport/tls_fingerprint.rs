/// TLS Fingerprint Randomization Module - JA3/JA4 Evasion
///
/// This module implements techniques to randomize TLS fingerprints and evade
/// JA3/JA4-based detection used by Russian DPI systems.
///
/// ## Problem
/// DPI systems create fingerprints from TLS ClientHello:
/// - **JA3**: MD5 hash of (TLS version, Cipher Suites, Extensions, Elliptic Curves, EC Point Formats)
/// - **JA4**: More advanced fingerprint including ALPN, signature algorithms, etc.
///
/// Tunneling software has distinctive fingerprints that DPI can detect.
///
/// ## Solution: Browser Mimicry & Randomization
///
/// This module provides:
///
/// 1. **Browser Profile Mimicry**
///    - Match Chrome, Firefox, Safari TLS fingerprints
///    - Use correct cipher suite order
///    - Include browser-specific extensions
///
/// 2. **GREASE Injection**
///    - Add random GREASE values (RFC 8701)
///    - Chrome uses GREASE to prevent extension ossification
///    - Makes fingerprint match real browsers
///
/// 3. **Extension Shuffling**
///    - Randomize order of TLS extensions
///    - Some DPI relies on extension order
///
/// 4. **Cipher Suite Rotation**
///    - Rotate cipher suite preferences
///    - Changes JA3 hash
///
/// ## Limitations
/// rustls doesn't support full ClientHello customization.
/// This module provides utilities for fingerprint analysis and
/// recommendations for improving fingerprints.
///
/// ## References
/// - JA3 Fingerprinting: https://github.com/salesforce/ja3
/// - JA4+ Fingerprinting: https://github.com/FoxIO-LLC/ja4
/// - RFC 8701 (GREASE)

use std::sync::atomic::{AtomicU64, Ordering};

/// Global state for randomization
static FINGERPRINT_STATE: AtomicU64 = AtomicU64::new(0xFEEDFACE_CAFEBABE);

/// GREASE values from RFC 8701
/// These are used by browsers to prevent extension ossification
pub const GREASE_VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
    0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// Browser profile for TLS fingerprint mimicry
#[derive(Debug, Clone)]
pub struct BrowserProfile {
    /// Browser name
    pub name: String,
    
    /// TLS version (0x0303 = TLS 1.2, 0x0304 = TLS 1.3)
    pub tls_version: u16,
    
    /// Cipher suites in order (as sent by browser)
    pub cipher_suites: Vec<u16>,
    
    /// TLS extensions in order
    pub extensions: Vec<u16>,
    
    /// Supported groups (elliptic curves)
    pub supported_groups: Vec<u16>,
    
    /// EC point formats
    pub ec_point_formats: Vec<u8>,
    
    /// Signature algorithms
    pub signature_algorithms: Vec<u16>,
    
    /// ALPN protocols
    pub alpn_protocols: Vec<String>,
    
    /// Expected JA3 hash (for validation)
    pub expected_ja3: Option<String>,
    
    /// Use GREASE
    pub use_grease: bool,
}

impl BrowserProfile {
    /// Chrome 120+ on Windows profile
    pub fn chrome_windows() -> Self {
        Self {
            name: "Chrome 120 Windows".to_string(),
            tls_version: 0x0303,
            cipher_suites: vec![
                0x1301, 0x1302, 0x1303, // TLS 1.3 suites
                0xc02b, 0xc02f, 0xc02c, 0xc030, // ECDHE suites
                0xcca9, 0xcca8, // ChaCha20
                0xc013, 0xc014, // ECDHE-RSA
                0x009c, 0x009d, // AES-GCM
                0x002f, 0x0035, // AES
            ],
            extensions: vec![
                0x0000, // SNI
                0x0017, // Extended Master Secret
                0x0010, // ALPN
                0x000b, // EC Point Formats
                0x000a, // Supported Groups
                0x0023, // Session Ticket
                0x000d, // Signature Algorithms
                0x002b, // Supported Versions
                0x002d, // PSK Key Exchange Modes
                0x0033, // Key Share
                0x0015, // Padding
                0xfe0d, // Encrypted Client Hello (draft)
            ],
            supported_groups: vec![
                0x001d, // x25519
                0x0017, // secp256r1
                0x0018, // secp384r1
                0x0019, // secp521r1
                0x0100, // ffdhe2048
            ],
            ec_point_formats: vec![0x00], // Uncompressed
            signature_algorithms: vec![
                0x0403, // ecdsa_secp256r1_sha256
                0x0804, // rsa_pss_rsae_sha256
                0x0401, // rsa_pkcs1_sha256
                0x0503, // ecdsa_secp384r1_sha384
                0x0805, // rsa_pss_rsae_sha384
                0x0501, // rsa_pkcs1_sha384
                0x0806, // rsa_pss_rsae_sha512
                0x0601, // rsa_pkcs1_sha512
            ],
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            expected_ja3: None,
            use_grease: true,
        }
    }
    
    /// Firefox 120+ profile
    pub fn firefox_windows() -> Self {
        Self {
            name: "Firefox 120 Windows".to_string(),
            tls_version: 0x0303,
            cipher_suites: vec![
                0x1301, 0x1303, 0x1302, // TLS 1.3 (different order than Chrome)
                0xc02b, 0xc02f, // ECDHE
                0xcca9, 0xcca8, // ChaCha20
                0xc02c, 0xc030, // ECDHE-ECDSA
                0xc00a, 0xc009, // ECDHE-ECDSA-AES
                0xc013, 0xc014, // ECDHE-RSA
            ],
            extensions: vec![
                0x0000, // SNI
                0x0017, // Extended Master Secret
                0x002b, // Supported Versions (earlier than Chrome)
                0x000a, // Supported Groups
                0x000b, // EC Point Formats
                0x000d, // Signature Algorithms
                0x0010, // ALPN
                0x0033, // Key Share
                0x002d, // PSK Key Exchange Modes
                0x0023, // Session Ticket
            ],
            supported_groups: vec![
                0x001d, // x25519
                0x0017, // secp256r1
                0x0018, // secp384r1
            ],
            ec_point_formats: vec![0x00],
            signature_algorithms: vec![
                0x0403, 0x0503, 0x0603,
                0x0804, 0x0805, 0x0806,
                0x0401, 0x0501, 0x0601,
            ],
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            expected_ja3: None,
            use_grease: false, // Firefox doesn't use GREASE by default
        }
    }
    
    /// Safari on macOS profile
    pub fn safari_macos() -> Self {
        Self {
            name: "Safari 17 macOS".to_string(),
            tls_version: 0x0303,
            cipher_suites: vec![
                0x1301, 0x1302, 0x1303,
                0xc02c, 0xc02b, // ECDHE-ECDSA first (Apple prefers)
                0xc030, 0xc02f,
                0xc024, 0xc023,
                0xc00a, 0xc009,
            ],
            extensions: vec![
                0x0000, // SNI
                0x0010, // ALPN
                0x0005, // Status Request
                0x000a, // Supported Groups
                0x000b, // EC Point Formats
                0x000d, // Signature Algorithms
                0x0017, // Extended Master Secret
                0x002b, // Supported Versions
                0x002d, // PSK Key Exchange Modes
                0x0033, // Key Share
            ],
            supported_groups: vec![
                0x001d, 0x0017, 0x0018, 0x0019,
            ],
            ec_point_formats: vec![0x00],
            signature_algorithms: vec![
                0x0403, 0x0503, 0x0603,
                0x0804, 0x0805, 0x0806,
                0x0401, 0x0501, 0x0601,
            ],
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            expected_ja3: None,
            use_grease: false,
        }
    }
    
    /// Telegram Desktop profile (for mimicking Telegram traffic)
    pub fn telegram_desktop() -> Self {
        Self {
            name: "Telegram Desktop".to_string(),
            tls_version: 0x0303,
            cipher_suites: vec![
                0x1301, 0x1302, 0x1303,
                0xc02b, 0xc02f,
                0xcca9, 0xcca8,
                0xc02c, 0xc030,
            ],
            extensions: vec![
                0x0000, // SNI
                0x0017, // Extended Master Secret
                0x000d, // Signature Algorithms
                0x000a, // Supported Groups
                0x000b, // EC Point Formats
                0x002b, // Supported Versions
                0x0033, // Key Share
            ],
            supported_groups: vec![0x001d, 0x0017, 0x0018],
            ec_point_formats: vec![0x00],
            signature_algorithms: vec![
                0x0403, 0x0503, 0x0804, 0x0805,
            ],
            alpn_protocols: vec![],
            expected_ja3: None,
            use_grease: false,
        }
    }
    
    /// Get a random browser profile
    pub fn random() -> Self {
        let state = FINGERPRINT_STATE.fetch_add(1, Ordering::Relaxed);
        match state % 4 {
            0 => Self::chrome_windows(),
            1 => Self::firefox_windows(),
            2 => Self::safari_macos(),
            _ => Self::telegram_desktop(),
        }
    }
}

/// TLS fingerprint configuration
#[derive(Debug, Clone)]
pub struct TlsFingerprintConfig {
    /// Browser profile to mimic
    pub browser_profile: Option<BrowserProfile>,
    
    /// Enable GREASE injection
    pub enable_grease: bool,
    
    /// Randomize extension order
    pub randomize_extensions: bool,
    
    /// Rotate cipher suites
    pub rotate_cipher_suites: bool,
    
    /// Add padding to reach target size
    pub add_padding: bool,
    
    /// Target ClientHello size (for padding)
    pub target_size: usize,
}

impl Default for TlsFingerprintConfig {
    fn default() -> Self {
        Self {
            browser_profile: Some(BrowserProfile::chrome_windows()),
            enable_grease: true,
            randomize_extensions: false, // Can break some servers
            rotate_cipher_suites: true,
            add_padding: true,
            target_size: 517, // Common Chrome ClientHello size
        }
    }
}

impl TlsFingerprintConfig {
    /// Configuration optimized for Russian DPI evasion
    pub fn russia_optimized() -> Self {
        Self {
            browser_profile: Some(BrowserProfile::chrome_windows()),
            enable_grease: true,
            randomize_extensions: false,
            rotate_cipher_suites: true,
            add_padding: true,
            target_size: 517,
        }
    }
}

/// Select a random GREASE value
pub fn select_grease_value() -> u16 {
    let state = FINGERPRINT_STATE.fetch_add(1, Ordering::Relaxed);
    GREASE_VALUES[(state as usize) % GREASE_VALUES.len()]
}

/// Generate GREASE cipher suite for injection into cipher list
pub fn generate_grease_cipher_suite() -> u16 {
    select_grease_value()
}

/// Generate GREASE extension for injection
pub fn generate_grease_extension() -> (u16, Vec<u8>) {
    let ext_type = select_grease_value();
    let state = FINGERPRINT_STATE.fetch_add(1, Ordering::Relaxed);
    
    // GREASE extension data (0-32 bytes)
    let len = (state % 5) as usize;
    let data = vec![0u8; len];
    
    (ext_type, data)
}

/// Generate GREASE supported group
pub fn generate_grease_group() -> u16 {
    select_grease_value()
}

/// Analyze TLS ClientHello and extract fingerprint data
#[derive(Debug, Clone)]
pub struct TlsFingerprint {
    /// TLS version
    pub version: u16,
    
    /// Cipher suites
    pub cipher_suites: Vec<u16>,
    
    /// Extensions
    pub extensions: Vec<u16>,
    
    /// Supported groups
    pub supported_groups: Vec<u16>,
    
    /// EC point formats
    pub ec_point_formats: Vec<u8>,
    
    /// JA3 string (before hashing)
    pub ja3_string: String,
}

impl TlsFingerprint {
    /// Calculate JA3 string from fingerprint components
    pub fn calculate_ja3_string(&self) -> String {
        let cipher_str: String = self.cipher_suites
            .iter()
            .filter(|&&c| !GREASE_VALUES.contains(&c))
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-");
        
        let ext_str: String = self.extensions
            .iter()
            .filter(|&&e| !GREASE_VALUES.contains(&e))
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("-");
        
        let groups_str: String = self.supported_groups
            .iter()
            .filter(|&&g| !GREASE_VALUES.contains(&g))
            .map(|g| g.to_string())
            .collect::<Vec<_>>()
            .join("-");
        
        let formats_str: String = self.ec_point_formats
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join("-");
        
        format!("{},{},{},{},{}", 
            self.version, cipher_str, ext_str, groups_str, formats_str)
    }
}

/// Parse TLS ClientHello and extract fingerprint
pub fn extract_fingerprint(data: &[u8]) -> Option<TlsFingerprint> {
    if data.len() < 43 {
        return None;
    }
    
    // Check TLS record header
    if data[0] != 0x16 {
        return None;
    }
    
    // Get version from ClientHello
    let version = u16::from_be_bytes([data[9], data[10]]);
    
    // Parse to extract cipher suites, extensions, etc.
    let mut pos = 5 + 4 + 2 + 32; // Skip headers, version, random
    
    if pos >= data.len() {
        return None;
    }
    
    // Skip session ID
    let session_id_len = data[pos] as usize;
    pos += 1 + session_id_len;
    
    if pos + 2 > data.len() {
        return None;
    }
    
    // Parse cipher suites
    let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    
    let mut cipher_suites = Vec::new();
    let cipher_end = pos + cipher_suites_len;
    while pos + 2 <= cipher_end && pos + 2 <= data.len() {
        let suite = u16::from_be_bytes([data[pos], data[pos + 1]]);
        cipher_suites.push(suite);
        pos += 2;
    }
    pos = cipher_end;
    
    if pos + 1 > data.len() {
        return None;
    }
    
    // Skip compression methods
    let compression_len = data[pos] as usize;
    pos += 1 + compression_len;
    
    if pos + 2 > data.len() {
        return None;
    }
    
    // Parse extensions
    let extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    
    let mut extensions = Vec::new();
    let mut supported_groups = Vec::new();
    let mut ec_point_formats = Vec::new();
    
    let extensions_end = pos + extensions_len;
    while pos + 4 <= extensions_end && pos + 4 <= data.len() {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        
        extensions.push(ext_type);
        
        // Parse specific extensions
        if ext_type == 0x000a && pos + 4 + 2 <= data.len() {
            // Supported Groups
            let groups_list_len = u16::from_be_bytes([data[pos + 4], data[pos + 5]]) as usize;
            let mut group_pos = pos + 6;
            let groups_end = group_pos + groups_list_len;
            while group_pos + 2 <= groups_end && group_pos + 2 <= data.len() {
                let group = u16::from_be_bytes([data[group_pos], data[group_pos + 1]]);
                supported_groups.push(group);
                group_pos += 2;
            }
        } else if ext_type == 0x000b && pos + 4 + 1 <= data.len() {
            // EC Point Formats
            let formats_len = data[pos + 4] as usize;
            for i in 0..formats_len {
                if pos + 5 + i < data.len() {
                    ec_point_formats.push(data[pos + 5 + i]);
                }
            }
        }
        
        pos += 4 + ext_len;
    }
    
    let fingerprint = TlsFingerprint {
        version,
        cipher_suites,
        extensions,
        supported_groups,
        ec_point_formats,
        ja3_string: String::new(),
    };
    
    let ja3 = fingerprint.calculate_ja3_string();
    
    Some(TlsFingerprint {
        ja3_string: ja3,
        ..fingerprint
    })
}

/// Compare fingerprint similarity to browser profile (0.0 - 1.0)
pub fn fingerprint_similarity(fingerprint: &TlsFingerprint, profile: &BrowserProfile) -> f64 {
    let mut score = 0.0;
    let mut max_score = 0.0;
    
    // Compare cipher suites (weight: 0.3)
    max_score += 0.3;
    let cipher_match = fingerprint.cipher_suites.iter()
        .filter(|c| profile.cipher_suites.contains(c))
        .count() as f64 / profile.cipher_suites.len().max(1) as f64;
    score += cipher_match * 0.3;
    
    // Compare extensions (weight: 0.3)
    max_score += 0.3;
    let ext_match = fingerprint.extensions.iter()
        .filter(|e| profile.extensions.contains(e))
        .count() as f64 / profile.extensions.len().max(1) as f64;
    score += ext_match * 0.3;
    
    // Compare supported groups (weight: 0.2)
    max_score += 0.2;
    let group_match = fingerprint.supported_groups.iter()
        .filter(|g| profile.supported_groups.contains(g))
        .count() as f64 / profile.supported_groups.len().max(1) as f64;
    score += group_match * 0.2;
    
    // Compare version (weight: 0.1)
    max_score += 0.1;
    if fingerprint.version == profile.tls_version {
        score += 0.1;
    }
    
    // Check for GREASE usage (weight: 0.1)
    max_score += 0.1;
    let has_grease = fingerprint.cipher_suites.iter().any(|c| GREASE_VALUES.contains(c))
        || fingerprint.extensions.iter().any(|e| GREASE_VALUES.contains(e));
    if has_grease == profile.use_grease {
        score += 0.1;
    }
    
    score / max_score
}

/// Get recommended cipher suites for mimicking browser
pub fn get_recommended_cipher_suites(profile: &BrowserProfile, enable_grease: bool) -> Vec<u16> {
    let mut suites = Vec::new();
    
    // Optionally add GREASE at the beginning (like Chrome)
    if enable_grease && profile.use_grease {
        suites.push(generate_grease_cipher_suite());
    }
    
    // Add profile cipher suites
    suites.extend(&profile.cipher_suites);
    
    suites
}

/// Get recommended extensions order for mimicking browser
pub fn get_recommended_extensions(profile: &BrowserProfile, enable_grease: bool) -> Vec<u16> {
    let mut exts = Vec::new();
    
    // Add GREASE extension at beginning if Chrome-like
    if enable_grease && profile.use_grease {
        exts.push(select_grease_value());
    }
    
    // Add profile extensions
    exts.extend(&profile.extensions);
    
    // Add GREASE extension before padding if Chrome-like
    if enable_grease && profile.use_grease {
        // Find padding position and insert GREASE before it
        if let Some(padding_pos) = exts.iter().position(|&e| e == 0x0015) {
            exts.insert(padding_pos, select_grease_value());
        }
    }
    
    exts
}

/// Recommendations for improving TLS fingerprint
#[derive(Debug, Clone)]
pub struct FingerprintRecommendations {
    pub issues: Vec<String>,
    pub suggestions: Vec<String>,
    pub similarity_score: f64,
    pub target_profile: String,
}

/// Analyze current fingerprint and provide recommendations
pub fn analyze_fingerprint(fingerprint: &TlsFingerprint) -> FingerprintRecommendations {
    let chrome = BrowserProfile::chrome_windows();
    let similarity = fingerprint_similarity(fingerprint, &chrome);
    
    let mut issues = Vec::new();
    let mut suggestions = Vec::new();
    
    // Check for missing GREASE
    let has_grease = fingerprint.cipher_suites.iter().any(|c| GREASE_VALUES.contains(c));
    if !has_grease {
        issues.push("No GREASE values in cipher suites (Chrome uses GREASE)".to_string());
        suggestions.push("Add GREASE cipher suite at beginning".to_string());
    }
    
    // Check cipher suite order
    if !fingerprint.cipher_suites.is_empty() && !chrome.cipher_suites.is_empty() {
        if fingerprint.cipher_suites[0] != 0x1301 && !GREASE_VALUES.contains(&fingerprint.cipher_suites[0]) {
            issues.push("First cipher suite should be TLS_AES_128_GCM_SHA256 (0x1301)".to_string());
            suggestions.push("Reorder cipher suites to match Chrome".to_string());
        }
    }
    
    // Check extension order
    if fingerprint.extensions.first() != Some(&0x0000) 
        && fingerprint.extensions.first().map(|e| !GREASE_VALUES.contains(e)).unwrap_or(true) {
        issues.push("SNI should be first extension (after GREASE if used)".to_string());
        suggestions.push("Reorder extensions: GREASE (optional), SNI, ...".to_string());
    }
    
    // Check for missing common extensions
    let important_exts = [0x0017, 0x002b, 0x000d, 0x0033]; // Extended Master Secret, Supported Versions, Sig Algs, Key Share
    for &ext in &important_exts {
        if !fingerprint.extensions.contains(&ext) {
            issues.push(format!("Missing important extension 0x{:04x}", ext));
        }
    }
    
    // Check supported groups
    if !fingerprint.supported_groups.contains(&0x001d) {
        issues.push("Missing x25519 (0x001d) in supported groups".to_string());
        suggestions.push("Add x25519 as first supported group".to_string());
    }
    
    if similarity < 0.7 {
        suggestions.push(format!(
            "Similarity to Chrome is only {:.0}%. Consider using Chrome browser profile.",
            similarity * 100.0
        ));
    }
    
    FingerprintRecommendations {
        issues,
        suggestions,
        similarity_score: similarity,
        target_profile: chrome.name.clone(),
    }
}

/// Known DPI-detected fingerprints to avoid
pub fn is_known_bad_fingerprint(fingerprint: &TlsFingerprint) -> bool {
    // List of JA3 hashes known to be blocked by Russian DPI
    // Note: Full JA3 matching would require MD5 hashing (crypto dependency)
    // These patterns are kept for reference but we use heuristic detection instead
    let _bad_ja3_patterns = [
        "473cd7cb9faa642487833865d516e578", // Old OpenSSL
        "6734f37431670b3ab4292b8f60f29984", // Old Go TLS
        "a0e9f5d64349fb13f1325b56d21006cf", // Old Python requests
    ];
    
    // Heuristic pattern matching instead of full JA3 hash comparison
    
    // Pattern 1: No TLS 1.3 cipher suites
    let has_tls13 = fingerprint.cipher_suites.iter()
        .any(|&c| c >= 0x1301 && c <= 0x1305);
    if !has_tls13 {
        return true; // No TLS 1.3 is suspicious
    }
    
    // Pattern 2: Very few extensions
    if fingerprint.extensions.len() < 5 {
        return true; // Browsers have many extensions
    }
    
    // Pattern 3: Missing common extensions
    let common_exts = [0x0000, 0x000a, 0x000b, 0x000d];
    let has_common = common_exts.iter().all(|e| fingerprint.extensions.contains(e));
    if !has_common {
        return true;
    }
    
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_grease_values() {
        // All GREASE values should end in 0x0a
        for &value in &GREASE_VALUES {
            assert_eq!(value & 0x0f0f, 0x0a0a);
        }
    }
    
    #[test]
    fn test_browser_profiles() {
        let chrome = BrowserProfile::chrome_windows();
        assert!(!chrome.cipher_suites.is_empty());
        assert!(!chrome.extensions.is_empty());
        assert!(chrome.use_grease);
        
        let firefox = BrowserProfile::firefox_windows();
        assert!(!firefox.cipher_suites.is_empty());
        assert!(!firefox.use_grease);
    }
    
    #[test]
    fn test_grease_generation() {
        let grease = select_grease_value();
        assert!(GREASE_VALUES.contains(&grease));
        
        let cipher = generate_grease_cipher_suite();
        assert!(GREASE_VALUES.contains(&cipher));
    }
    
    #[test]
    fn test_recommended_cipher_suites() {
        let chrome = BrowserProfile::chrome_windows();
        let suites = get_recommended_cipher_suites(&chrome, true);
        
        // Should have GREASE at beginning
        assert!(GREASE_VALUES.contains(&suites[0]));
        
        // Should contain TLS 1.3 suites
        assert!(suites.contains(&0x1301));
    }
    
    #[test]
    fn test_ja3_string() {
        let fingerprint = TlsFingerprint {
            version: 0x0303,
            cipher_suites: vec![0x1301, 0x1302],
            extensions: vec![0x0000, 0x0017],
            supported_groups: vec![0x001d, 0x0017],
            ec_point_formats: vec![0x00],
            ja3_string: String::new(),
        };
        
        let ja3 = fingerprint.calculate_ja3_string();
        assert!(!ja3.is_empty());
        assert!(ja3.contains("771")); // 0x0303 = 771
    }
    
    #[test]
    fn test_fingerprint_similarity() {
        let chrome = BrowserProfile::chrome_windows();
        
        // Create fingerprint matching Chrome
        let matching = TlsFingerprint {
            version: chrome.tls_version,
            cipher_suites: chrome.cipher_suites.clone(),
            extensions: chrome.extensions.clone(),
            supported_groups: chrome.supported_groups.clone(),
            ec_point_formats: chrome.ec_point_formats.clone(),
            ja3_string: String::new(),
        };
        
        let similarity = fingerprint_similarity(&matching, &chrome);
        assert!(similarity > 0.9); // Should be very high
    }
}
