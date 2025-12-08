/// DNS Padding Module (RFC 8467)
///
/// This module implements EDNS(0) Padding Option for DNS-over-HTTPS and DNS-over-TLS
/// to enhance privacy and evade DPI analysis based on DNS query sizes.
///
/// ## Why DNS Padding Matters
/// Russian DPI (TSPU) and other sophisticated systems analyze:
/// - DNS query sizes (correlate domain length with query size)
/// - DNS answer sizes (can infer domain type)
/// - Query patterns (timing, frequency)
///
/// RFC 8467 padding makes all DNS queries appear similar in size, breaking
/// size-based fingerprinting.
///
/// ## Implementation
/// - Padding is added to EDNS(0) as OPT record
/// - Padding size is randomized to avoid patterns
/// - Block sizes: 128, 256, 468 bytes (common MTU-aligned values)
/// - Padding data is all zeros (per RFC)
///
/// ## References
/// - RFC 8467: Padding Policies for Extension Mechanisms for DNS (EDNS(0))
/// - RFC 6891: Extension Mechanisms for DNS (EDNS(0))

use rand::Rng;

/// DNS padding block sizes (bytes)
/// These are chosen to align with common network MTU sizes
pub const PADDING_BLOCK_SIZES: [usize; 5] = [
    128,  // Small queries
    256,  // Medium queries
    384,  // Large queries
    468,  // ~512 (UDP DNS limit) - overhead
    512,  // Maximum for UDP
];

/// DNS padding strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingStrategy {
    /// No padding (default)
    None,
    
    /// Pad to fixed block size
    FixedBlock(usize),
    
    /// Pad to next block size from predefined list
    BlockAligned,
    
    /// Random padding (0-N bytes)
    Random(usize),
    
    /// Recommended strategy for DoH (RFC 8467 Section 4.1)
    /// - Pad to 128-byte blocks for queries
    /// - Adds randomness to break patterns
    Recommended,
}

impl Default for PaddingStrategy {
    fn default() -> Self {
        Self::None
    }
}

/// DNS padding configuration
#[derive(Debug, Clone)]
pub struct DnsPaddingConfig {
    /// Padding strategy
    pub strategy: PaddingStrategy,
    
    /// Enable padding for queries
    pub pad_queries: bool,
    
    /// Enable padding for responses (server-side)
    pub pad_responses: bool,
    
    /// Add random jitter to padding size (0.0-1.0)
    /// 0.1 = add up to 10% random variation
    pub jitter: f32,
}

impl Default for DnsPaddingConfig {
    fn default() -> Self {
        Self {
            strategy: PaddingStrategy::Recommended,
            pad_queries: true,
            pad_responses: false, // Client doesn't control server responses
            jitter: 0.15, // 15% jitter
        }
    }
}

impl DnsPaddingConfig {
    /// Create config with recommended settings for DoH
    pub fn recommended_doh() -> Self {
        Self {
            strategy: PaddingStrategy::Recommended,
            pad_queries: true,
            pad_responses: false,
            jitter: 0.15,
        }
    }
    
    /// Create config with maximum privacy
    pub fn maximum_privacy() -> Self {
        Self {
            strategy: PaddingStrategy::BlockAligned,
            pad_queries: true,
            pad_responses: false,
            jitter: 0.25, // More jitter for variation
        }
    }
    
    /// Create config for minimal overhead
    pub fn minimal() -> Self {
        Self {
            strategy: PaddingStrategy::FixedBlock(128),
            pad_queries: true,
            pad_responses: false,
            jitter: 0.05,
        }
    }
    
    /// Disable padding
    pub fn disabled() -> Self {
        Self {
            strategy: PaddingStrategy::None,
            pad_queries: false,
            pad_responses: false,
            jitter: 0.0,
        }
    }
}

/// Calculate padding size for a DNS message
///
/// ## Arguments
/// * `message_size` - Current size of DNS message (bytes)
/// * `config` - Padding configuration
///
/// ## Returns
/// Number of padding bytes to add
pub fn calculate_padding_size(message_size: usize, config: &DnsPaddingConfig) -> usize {
    if !config.pad_queries {
        return 0;
    }
    
    let base_padding = match config.strategy {
        PaddingStrategy::None => 0,
        
        PaddingStrategy::FixedBlock(block_size) => {
            // Pad to fixed block size
            if message_size >= block_size {
                0
            } else {
                block_size - message_size
            }
        }
        
        PaddingStrategy::BlockAligned => {
            // Find next block size larger than current message
            let next_block = PADDING_BLOCK_SIZES
                .iter()
                .find(|&&size| size > message_size)
                .copied()
                .unwrap_or(PADDING_BLOCK_SIZES[PADDING_BLOCK_SIZES.len() - 1]);
            
            next_block.saturating_sub(message_size)
        }
        
        PaddingStrategy::Random(max_padding) => {
            // Random padding up to max_padding bytes
            let mut rng = rand::rng();
            rng.random_range(0..=max_padding)
        }
        
        PaddingStrategy::Recommended => {
            // RFC 8467 recommended: pad to 128-byte blocks
            const BLOCK_SIZE: usize = 128;
            let remainder = message_size % BLOCK_SIZE;
            if remainder == 0 {
                0
            } else {
                BLOCK_SIZE - remainder
            }
        }
    };
    
    // Apply jitter if configured
    if config.jitter > 0.0 && base_padding > 0 {
        let mut rng = rand::rng();
        let jitter_amount = (base_padding as f32 * config.jitter) as usize;
        let jitter = rng.random_range(0..=jitter_amount);
        base_padding + jitter
    } else {
        base_padding
    }
}

/// Generate padding bytes (all zeros per RFC 8467)
pub fn generate_padding_bytes(size: usize) -> Vec<u8> {
    vec![0u8; size]
}

/// Check if padding should be applied for a domain
///
/// Some domains may not benefit from padding (e.g., localhost, well-known domains)
pub fn should_pad_domain(domain: &str) -> bool {
    // Don't pad for local domains
    if domain.ends_with(".local") || domain == "localhost" {
        return false;
    }
    
    // Don't pad for IP addresses (they're already known)
    if domain.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    
    // Pad everything else
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_fixed_block_padding() {
        let config = DnsPaddingConfig {
            strategy: PaddingStrategy::FixedBlock(128),
            pad_queries: true,
            pad_responses: false,
            jitter: 0.0,
        };
        
        // 50 byte message should pad to 128 bytes
        let padding = calculate_padding_size(50, &config);
        assert_eq!(padding, 78);
        
        // 128 byte message needs no padding
        let padding = calculate_padding_size(128, &config);
        assert_eq!(padding, 0);
        
        // 200 byte message needs no padding (already over block size)
        let padding = calculate_padding_size(200, &config);
        assert_eq!(padding, 0);
    }
    
    #[test]
    fn test_block_aligned_padding() {
        let config = DnsPaddingConfig {
            strategy: PaddingStrategy::BlockAligned,
            pad_queries: true,
            pad_responses: false,
            jitter: 0.0,
        };
        
        // 50 byte message should pad to 128 bytes
        let padding = calculate_padding_size(50, &config);
        assert_eq!(padding, 78);
        
        // 200 byte message should pad to 256 bytes
        let padding = calculate_padding_size(200, &config);
        assert_eq!(padding, 56);
    }
    
    #[test]
    fn test_recommended_padding() {
        let config = DnsPaddingConfig::recommended_doh();
        
        // 50 byte message should pad to next 128-byte boundary (128)
        let padding = calculate_padding_size(50, &config);
        assert!(padding > 0 && padding <= 78 + (78 * 15 / 100)); // 78 + 15% jitter
        
        // 128 byte message needs no padding (already on boundary)
        let padding = calculate_padding_size(128, &config);
        assert_eq!(padding, 0);
    }
    
    #[test]
    fn test_random_padding() {
        let config = DnsPaddingConfig {
            strategy: PaddingStrategy::Random(100),
            pad_queries: true,
            pad_responses: false,
            jitter: 0.0,
        };
        
        // Should be between 0 and 100
        let padding = calculate_padding_size(50, &config);
        assert!(padding <= 100);
    }
    
    #[test]
    fn test_disabled_padding() {
        let config = DnsPaddingConfig::disabled();
        
        let padding = calculate_padding_size(50, &config);
        assert_eq!(padding, 0);
    }
    
    #[test]
    fn test_padding_bytes_generation() {
        let bytes = generate_padding_bytes(100);
        assert_eq!(bytes.len(), 100);
        assert!(bytes.iter().all(|&b| b == 0)); // All zeros per RFC
    }
    
    #[test]
    fn test_should_pad_domain() {
        assert!(should_pad_domain("example.com"));
        assert!(should_pad_domain("www.google.com"));
        assert!(!should_pad_domain("localhost"));
        assert!(!should_pad_domain("server.local"));
        assert!(!should_pad_domain("192.168.1.1"));
        assert!(!should_pad_domain("::1"));
    }
    
    #[test]
    fn test_jitter() {
        let config = DnsPaddingConfig {
            strategy: PaddingStrategy::FixedBlock(128),
            pad_queries: true,
            pad_responses: false,
            jitter: 0.2, // 20% jitter
        };
        
        // Test multiple times to verify jitter variation
        let mut sizes = Vec::new();
        for _ in 0..10 {
            let padding = calculate_padding_size(50, &config);
            sizes.push(padding);
        }
        
        // Should have some variation due to jitter
        let min = sizes.iter().min().unwrap();
        let max = sizes.iter().max().unwrap();
        assert!(max > min, "Jitter should create variation");
    }
}
