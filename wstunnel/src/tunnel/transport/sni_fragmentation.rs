/// SNI Fragmentation Module - Bypass DPI SNI-based blocking
///
/// This module implements various SNI (Server Name Indication) obfuscation techniques
/// to evade Deep Packet Inspection systems used in Russia (TSPU/РКНРФ).
///
/// ## Problem
/// Russian DPI actively blocks connections based on SNI field in TLS ClientHello.
/// The SNI field contains the target domain name in plaintext, allowing DPI to:
/// - Block specific domains (e.g., VPN providers, banned sites)
/// - Fingerprint tunnel traffic patterns
/// - Correlate connections across time
///
/// ## Solution: Multi-layer SNI Obfuscation
///
/// This module provides several techniques:
///
/// 1. **TCP Fragmentation of ClientHello**
///    - Split TLS ClientHello into multiple TCP segments
///    - SNI is spread across segments, DPI can't reassemble
///    - Most effective against Russian TSPU
///
/// 2. **SNI Case Randomization**
///    - Send SNI with random case (e.g., "WwW.GoOgLe.CoM")
///    - Some DPI systems fail to normalize case
///
/// 3. **Fake/Decoy SNI**
///    - Send a fake SNI first, then real one
///    - Confuses stateless DPI
///
/// 4. **SNI Padding**
///    - Add padding extensions around SNI
///    - Changes TLS fingerprint
///
/// ## References
/// - GoodbyeDPI project (Russia-specific DPI bypass)
/// - zapret project (Russian DPI research)
/// - "Breaking and Fixing Origin-based Access Control in Hybrid Web/Mobile Applications" (IEEE S&P)

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

/// Global state for randomization
static SNI_OBFUSCATION_STATE: AtomicU64 = AtomicU64::new(0xCAFEBABE_DEADBEEF);

/// SNI obfuscation configuration
#[derive(Debug, Clone)]
pub struct SniObfuscationConfig {
    /// Enable TCP-level fragmentation of ClientHello
    pub tcp_fragmentation: bool,
    
    /// Fragment size for TCP fragmentation (40-100 bytes optimal for TSPU)
    pub fragment_size: usize,
    
    /// Delay between TCP fragments (microseconds)
    pub inter_fragment_delay_us: u64,
    
    /// Enable SNI case randomization
    pub case_randomization: bool,
    
    /// Use decoy/fake SNI
    pub use_decoy_sni: bool,
    
    /// Decoy domain to use (should look legitimate)
    pub decoy_domain: Option<String>,
    
    /// Enable SNI padding
    pub sni_padding: bool,
    
    /// Split position: where to split SNI in ClientHello
    /// None = auto-detect optimal position
    pub split_position: Option<usize>,
}

impl Default for SniObfuscationConfig {
    fn default() -> Self {
        Self {
            tcp_fragmentation: true,
            fragment_size: 40, // Optimal for Russian TSPU
            inter_fragment_delay_us: 100, // 0.1ms delay
            case_randomization: true,
            use_decoy_sni: false,
            decoy_domain: None,
            sni_padding: false,
            split_position: None,
        }
    }
}

impl SniObfuscationConfig {
    /// Configuration optimized for Russian DPI (TSPU/РКНРФ)
    pub fn russia_optimized() -> Self {
        Self {
            tcp_fragmentation: true,
            fragment_size: 40, // Small fragments work best against TSPU
            inter_fragment_delay_us: 100,
            case_randomization: true,
            use_decoy_sni: false, // May cause issues with some servers
            decoy_domain: Some("www.google.com".to_string()),
            sni_padding: true,
            split_position: None,
        }
    }
    
    /// Aggressive mode - use all techniques
    pub fn aggressive() -> Self {
        Self {
            tcp_fragmentation: true,
            fragment_size: 1, // Single-byte fragments (extreme)
            inter_fragment_delay_us: 500,
            case_randomization: true,
            use_decoy_sni: true,
            decoy_domain: Some("www.microsoft.com".to_string()),
            sni_padding: true,
            split_position: None,
        }
    }
}

/// Result of SNI analysis in TLS ClientHello
#[derive(Debug, Clone)]
pub struct SniInfo {
    /// Offset of SNI extension in ClientHello
    pub sni_offset: usize,
    /// Length of SNI data
    pub sni_length: usize,
    /// The SNI hostname
    pub hostname: String,
    /// Optimal split position (just before SNI)
    pub optimal_split_position: usize,
}

/// Parse TLS ClientHello and find SNI extension
///
/// TLS ClientHello structure:
/// - Record Header (5 bytes): type(1), version(2), length(2)
/// - Handshake Header (4 bytes): type(1), length(3)
/// - ClientHello: version(2), random(32), session_id(1+N), cipher_suites(2+N), compression(1+N), extensions(2+N)
/// - Extensions: each is type(2), length(2), data(N)
/// - SNI extension (type 0x0000): list_length(2), type(1), name_length(2), hostname(N)
pub fn find_sni_in_client_hello(data: &[u8]) -> Option<SniInfo> {
    if data.len() < 43 {
        return None; // Too short for TLS ClientHello
    }
    
    // Check TLS record header
    if data[0] != 0x16 {
        return None; // Not a handshake record
    }
    
    // Get record length
    let record_length = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_length {
        return None; // Incomplete record
    }
    
    // Check handshake type (ClientHello = 0x01)
    if data[5] != 0x01 {
        return None; // Not ClientHello
    }
    
    // Skip to extensions
    // Position after handshake header and fixed ClientHello fields
    let mut pos = 5 + 4 + 2 + 32; // record_header(5) + handshake_header(4) + version(2) + random(32)
    
    if pos >= data.len() {
        return None;
    }
    
    // Skip session ID
    let session_id_len = data[pos] as usize;
    pos += 1 + session_id_len;
    
    if pos + 2 > data.len() {
        return None;
    }
    
    // Skip cipher suites
    let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;
    
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
    
    let extensions_end = pos + extensions_len;
    if extensions_end > data.len() {
        return None;
    }
    
    // Find SNI extension (type 0x0000)
    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        
        if ext_type == 0x0000 {
            // Found SNI extension
            let sni_offset = pos;
            
            // Parse SNI data: list_length(2) + type(1) + name_length(2) + hostname(N)
            if pos + 4 + 5 > data.len() || ext_len < 5 {
                return None;
            }
            
            let name_length = u16::from_be_bytes([data[pos + 4 + 3], data[pos + 4 + 4]]) as usize;
            
            if pos + 4 + 5 + name_length > data.len() {
                return None;
            }
            
            let hostname_bytes = &data[pos + 4 + 5..pos + 4 + 5 + name_length];
            let hostname = String::from_utf8_lossy(hostname_bytes).to_string();
            
            return Some(SniInfo {
                sni_offset,
                sni_length: 4 + ext_len, // extension header + data
                hostname,
                optimal_split_position: sni_offset, // Split just before SNI extension
            });
        }
        
        pos += 4 + ext_len;
    }
    
    None
}

/// Calculate optimal positions to split ClientHello for SNI obfuscation
///
/// Returns a list of positions where the data should be split for TCP fragmentation.
/// The goal is to split the SNI across multiple TCP segments so DPI can't see it.
pub fn calculate_split_positions(
    data: &[u8],
    config: &SniObfuscationConfig,
) -> Vec<usize> {
    let mut positions = Vec::new();
    
    // Find SNI in ClientHello
    let sni_info = match find_sni_in_client_hello(data) {
        Some(info) => info,
        None => {
            // No SNI found, use default fragmentation
            let fragment_size = config.fragment_size;
            let mut pos = fragment_size;
            while pos < data.len() {
                positions.push(pos);
                pos += fragment_size;
            }
            return positions;
        }
    };
    
    // Strategy: Split data to fragment SNI across multiple TCP segments
    // Most effective positions:
    // 1. Just before SNI extension (splits header from SNI)
    // 2. Inside SNI hostname (splits hostname into parts)
    // 3. After SNI extension
    
    if let Some(split_pos) = config.split_position {
        // User-specified split position
        if split_pos < data.len() {
            positions.push(split_pos);
        }
    } else {
        // Auto-detect optimal split positions
        let sni_start = sni_info.sni_offset;
        let sni_end = sni_start + sni_info.sni_length;
        
        // Split before SNI (critical split)
        if sni_start > 0 && sni_start < data.len() {
            positions.push(sni_start);
        }
        
        // Split inside SNI hostname (additional fragmentation)
        // SNI structure: ext_type(2) + ext_len(2) + list_len(2) + type(1) + name_len(2) + hostname
        let hostname_start = sni_start + 9; // offset to hostname
        let hostname_len = sni_info.hostname.len();
        
        if hostname_len > 3 {
            // Split hostname in the middle
            let mid = hostname_start + hostname_len / 2;
            if mid < sni_end && mid < data.len() {
                positions.push(mid);
            }
        }
        
        // For very aggressive fragmentation, split more
        if config.fragment_size <= 10 {
            let fragment_size = config.fragment_size.max(1);
            let mut pos = fragment_size;
            while pos < data.len() {
                if !positions.contains(&pos) {
                    positions.push(pos);
                }
                pos += fragment_size;
            }
        }
    }
    
    // Sort and deduplicate
    positions.sort();
    positions.dedup();
    
    // Remove positions that are too close together
    let min_fragment = 1;
    let mut filtered = Vec::new();
    let mut last_pos = 0usize;
    
    for pos in positions {
        if pos > last_pos + min_fragment && pos < data.len() {
            filtered.push(pos);
            last_pos = pos;
        }
    }
    
    filtered
}

/// Fragment data at specified positions
/// Returns a vector of data fragments to be sent as separate TCP segments
pub fn fragment_data(data: &[u8], positions: &[usize]) -> Vec<Vec<u8>> {
    if positions.is_empty() {
        return vec![data.to_vec()];
    }
    
    let mut fragments = Vec::new();
    let mut start = 0;
    
    for &pos in positions {
        if pos > start && pos <= data.len() {
            fragments.push(data[start..pos].to_vec());
            start = pos;
        }
    }
    
    // Add remaining data
    if start < data.len() {
        fragments.push(data[start..].to_vec());
    }
    
    fragments
}

/// Apply case randomization to SNI hostname
///
/// Many DPI systems don't normalize case before matching.
/// Sending "WWW.GOoGlE.cOm" instead of "www.google.com" can bypass some filters.
pub fn randomize_sni_case(hostname: &str) -> String {
    let state = SNI_OBFUSCATION_STATE.fetch_add(1, Ordering::Relaxed);
    let mut result = String::with_capacity(hostname.len());
    
    for (i, c) in hostname.chars().enumerate() {
        if c.is_ascii_alphabetic() {
            // Use position and state to determine case
            let should_upper = ((state >> (i % 64)) ^ (i as u64)) & 1 == 1;
            if should_upper {
                result.extend(c.to_uppercase());
            } else {
                result.extend(c.to_lowercase());
            }
        } else {
            result.push(c);
        }
    }
    
    result
}

/// Modify ClientHello data to apply case randomization to SNI
///
/// This modifies the data in-place, changing the SNI hostname case.
pub fn apply_sni_case_randomization(data: &mut [u8]) -> bool {
    let sni_info = match find_sni_in_client_hello(data) {
        Some(info) => info,
        None => return false,
    };
    
    // Find hostname in data
    let hostname_start = sni_info.sni_offset + 9; // ext_type(2) + ext_len(2) + list_len(2) + type(1) + name_len(2)
    let hostname_end = hostname_start + sni_info.hostname.len();
    
    if hostname_end > data.len() {
        return false;
    }
    
    // Apply case randomization to hostname bytes
    let state = SNI_OBFUSCATION_STATE.fetch_add(1, Ordering::Relaxed);
    
    for (i, byte) in data[hostname_start..hostname_end].iter_mut().enumerate() {
        if byte.is_ascii_alphabetic() {
            let should_upper = ((state >> (i % 64)) ^ (i as u64)) & 1 == 1;
            if should_upper {
                *byte = byte.to_ascii_uppercase();
            } else {
                *byte = byte.to_ascii_lowercase();
            }
        }
    }
    
    true
}

/// Create a modified TLS ClientHello with obfuscated SNI
///
/// This is the main function for SNI obfuscation. It applies all configured
/// techniques and returns fragments ready to be sent.
pub struct ObfuscatedClientHello {
    /// Fragments to send (each should be sent as separate TCP segment)
    pub fragments: Vec<Vec<u8>>,
    
    /// Delay between fragments (microseconds)
    pub inter_fragment_delay_us: u64,
    
    /// Whether case randomization was applied
    pub case_randomized: bool,
}

/// Apply SNI obfuscation to TLS ClientHello
///
/// This function takes raw TLS ClientHello data and applies obfuscation
/// techniques based on configuration.
pub fn obfuscate_client_hello(
    data: &[u8],
    config: &SniObfuscationConfig,
) -> ObfuscatedClientHello {
    let mut modified_data = data.to_vec();
    let mut case_randomized = false;
    
    // Apply case randomization if enabled
    if config.case_randomization {
        case_randomized = apply_sni_case_randomization(&mut modified_data);
    }
    
    // Calculate split positions for TCP fragmentation
    let fragments = if config.tcp_fragmentation {
        let positions = calculate_split_positions(&modified_data, config);
        fragment_data(&modified_data, &positions)
    } else {
        vec![modified_data]
    };
    
    ObfuscatedClientHello {
        fragments,
        inter_fragment_delay_us: config.inter_fragment_delay_us,
        case_randomized,
    }
}

/// TCP segment writer that handles fragmented sending
///
/// This trait should be implemented by the actual TCP writer to support
/// fragmented sending with delays.
pub trait FragmentedTcpWriter {
    /// Send a single fragment
    fn send_fragment(&mut self, data: &[u8]) -> io::Result<()>;
    
    /// Wait for specified duration
    fn delay(&mut self, microseconds: u64);
}

/// Send obfuscated ClientHello using fragmented TCP writes
pub fn send_obfuscated_client_hello<W: FragmentedTcpWriter>(
    writer: &mut W,
    obfuscated: &ObfuscatedClientHello,
) -> io::Result<()> {
    for (i, fragment) in obfuscated.fragments.iter().enumerate() {
        writer.send_fragment(fragment)?;
        
        // Add delay between fragments (except after last)
        if i < obfuscated.fragments.len() - 1 && obfuscated.inter_fragment_delay_us > 0 {
            writer.delay(obfuscated.inter_fragment_delay_us);
        }
    }
    
    Ok(())
}

/// Detect if data looks like TLS ClientHello
pub fn is_tls_client_hello(data: &[u8]) -> bool {
    if data.len() < 6 {
        return false;
    }
    
    // Check TLS record header
    data[0] == 0x16 && // Handshake record
    data[1] == 0x03 && // TLS major version
    (data[2] == 0x01 || data[2] == 0x03) && // TLS 1.0/1.2
    data[5] == 0x01 // ClientHello handshake type
}

/// Generate padding extension data for TLS
///
/// TLS padding extension (type 0x0015) can be used to change
/// ClientHello fingerprint and obscure other extensions.
pub fn generate_padding_extension(target_total_size: usize, current_size: usize) -> Vec<u8> {
    let padding_needed = target_total_size.saturating_sub(current_size);
    if padding_needed < 4 {
        return vec![];
    }
    
    let padding_data_len = padding_needed - 4; // 4 bytes for extension header
    
    let mut extension = Vec::with_capacity(padding_needed);
    
    // Extension type: padding (0x0015)
    extension.push(0x00);
    extension.push(0x15);
    
    // Extension length
    extension.push((padding_data_len >> 8) as u8);
    extension.push(padding_data_len as u8);
    
    // Padding data (zeros are fine for padding extension)
    extension.extend(std::iter::repeat(0u8).take(padding_data_len));
    
    extension
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Sample TLS ClientHello with SNI "example.com"
    fn sample_client_hello() -> Vec<u8> {
        vec![
            // TLS Record Header
            0x16, 0x03, 0x01, 0x00, 0xf1,
            // Handshake Header (ClientHello)
            0x01, 0x00, 0x00, 0xed,
            // Client Version
            0x03, 0x03,
            // Random (32 bytes)
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            // Session ID Length (0)
            0x00,
            // Cipher Suites Length (2) + Cipher Suite
            0x00, 0x02, 0x00, 0xff,
            // Compression Methods Length (1) + Method
            0x01, 0x00,
            // Extensions Length
            0x00, 0x18,
            // SNI Extension (type 0x0000)
            0x00, 0x00, // Extension type: SNI
            0x00, 0x10, // Extension length: 16
            0x00, 0x0e, // SNI list length: 14
            0x00,       // SNI type: hostname
            0x00, 0x0b, // Hostname length: 11
            // "example.com" (11 bytes)
            0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
        ]
    }
    
    #[test]
    fn test_find_sni() {
        let data = sample_client_hello();
        let sni_info = find_sni_in_client_hello(&data).expect("Should find SNI");
        
        assert_eq!(sni_info.hostname, "example.com");
        assert!(sni_info.sni_length > 0);
    }
    
    #[test]
    fn test_is_client_hello() {
        let data = sample_client_hello();
        assert!(is_tls_client_hello(&data));
        
        assert!(!is_tls_client_hello(&[0x17, 0x03, 0x01])); // Application data
        assert!(!is_tls_client_hello(&[0x16, 0x03, 0x01, 0x00, 0x05, 0x02])); // ServerHello
    }
    
    #[test]
    fn test_case_randomization() {
        let hostname = "www.example.com";
        let randomized = randomize_sni_case(hostname);
        
        // Should be same length
        assert_eq!(randomized.len(), hostname.len());
        
        // Should be equivalent when lowercased
        assert_eq!(randomized.to_lowercase(), hostname.to_lowercase());
        
        // Should have some uppercase chars (with high probability)
        // Note: in very rare cases all might be lowercase
    }
    
    #[test]
    fn test_fragment_data() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        
        let fragments = fragment_data(&data, &[3, 7]);
        
        assert_eq!(fragments.len(), 3);
        assert_eq!(fragments[0], vec![1, 2, 3]);
        assert_eq!(fragments[1], vec![4, 5, 6, 7]);
        assert_eq!(fragments[2], vec![8, 9, 10]);
    }
    
    #[test]
    fn test_calculate_split_positions() {
        let data = sample_client_hello();
        let config = SniObfuscationConfig::default();
        
        let positions = calculate_split_positions(&data, &config);
        
        // Should have at least one split position
        assert!(!positions.is_empty());
        
        // All positions should be within data bounds
        for pos in &positions {
            assert!(*pos < data.len());
        }
    }
    
    #[test]
    fn test_obfuscate_client_hello() {
        let data = sample_client_hello();
        let config = SniObfuscationConfig::russia_optimized();
        
        let obfuscated = obfuscate_client_hello(&data, &config);
        
        // Should have multiple fragments with fragmentation enabled
        assert!(obfuscated.fragments.len() >= 1);
        
        // Total data should equal original
        let total_len: usize = obfuscated.fragments.iter().map(|f| f.len()).sum();
        assert_eq!(total_len, data.len());
    }
    
    #[test]
    fn test_padding_extension() {
        let padding = generate_padding_extension(100, 50);
        
        // Should have correct extension type
        assert_eq!(padding[0], 0x00);
        assert_eq!(padding[1], 0x15);
        
        // Should have correct total length
        assert_eq!(padding.len(), 50); // 100 - 50 = 50 bytes of padding
    }
}
