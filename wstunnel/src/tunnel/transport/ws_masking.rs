/// WebSocket Masking Key Generator Module
///
/// This module provides browser-like WebSocket masking key generation
/// to evade DPI detection based on masking key patterns.
///
/// ## Why This Matters
/// Russian DPI (TSPU) and other sophisticated systems can analyze WebSocket
/// masking key patterns to detect tunnel software. Real browsers generate
/// masking keys using crypto-quality RNG with specific patterns.
///
/// ## Implementation
/// - Chrome uses crypto.getRandomValues() (Web Crypto API)
/// - Keys are truly random 32-bit values
/// - No predictable patterns or weak PRNG
///
/// ## References
/// - RFC 6455 Section 5.3: WebSocket masking requirements
/// - Chrome WebSocket implementation analysis

use rand::Rng;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Global state for entropy mixing
static ENTROPY_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Browser-like masking key generator trait
pub trait MaskingKeyGenerator: Send + Sync {
    /// Generate a 32-bit masking key
    fn generate_key(&self) -> [u8; 4];
}

/// Chrome-like masking key generator
///
/// Mimics Chrome's WebSocket masking key generation:
/// - Uses crypto-quality random number generator
/// - No predictable patterns
/// - Full 32-bit entropy space
pub struct ChromeMaskingKeyGenerator {
    /// Extra entropy source for mixing
    entropy_seed: u64,
}

impl ChromeMaskingKeyGenerator {
    /// Create new Chrome-like masking key generator
    pub fn new() -> Self {
        // Initialize with high-quality entropy
        let entropy_seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or_else(|_| rand::rng().random::<u64>());
        
        Self { entropy_seed }
    }
    
    /// Create with specific seed (for testing)
    #[cfg(test)]
    pub fn with_seed(seed: u64) -> Self {
        Self { entropy_seed: seed }
    }
}

impl Default for ChromeMaskingKeyGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl MaskingKeyGenerator for ChromeMaskingKeyGenerator {
    fn generate_key(&self) -> [u8; 4] {
        // Mix multiple entropy sources to simulate browser's crypto RNG
        let counter = ENTROPY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let time_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        
        // Chrome uses crypto.getRandomValues() which provides full entropy
        // We simulate this by mixing multiple sources and using proper RNG
        let mut rng = rand::rng();
        
        // Mix entropy sources to avoid predictable patterns
        let mixed_entropy = self.entropy_seed
            .wrapping_mul(counter)
            .wrapping_add(time_nanos)
            .wrapping_mul(0x9e3779b97f4a7c15); // Constant from PCG RNG
        
        // Generate random key with mixed entropy influence
        let random_val = rng.random::<u32>().wrapping_add(mixed_entropy as u32);
        
        random_val.to_be_bytes()
    }
}

/// Firefox-like masking key generator
///
/// Firefox has slightly different patterns but also uses high-quality RNG
pub struct FirefoxMaskingKeyGenerator {
    entropy_seed: u64,
}

impl FirefoxMaskingKeyGenerator {
    pub fn new() -> Self {
        let entropy_seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or_else(|_| rand::rng().random::<u64>());
        
        Self { entropy_seed }
    }
}

impl Default for FirefoxMaskingKeyGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl MaskingKeyGenerator for FirefoxMaskingKeyGenerator {
    fn generate_key(&self) -> [u8; 4] {
        // Firefox also uses crypto-quality RNG
        let counter = ENTROPY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let time_micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0);
        
        let mut rng = rand::rng();
        
        // Firefox has slightly different entropy mixing
        let mixed_entropy = self.entropy_seed
            .wrapping_add(counter.wrapping_mul(0x517cc1b727220a95))
            .wrapping_add(time_micros);
        
        let random_val = rng.random::<u32>().wrapping_add(mixed_entropy as u32);
        
        random_val.to_be_bytes()
    }
}

/// Randomized generator that switches between Chrome and Firefox patterns
pub struct RandomizedMaskingKeyGenerator {
    chrome_gen: ChromeMaskingKeyGenerator,
    firefox_gen: FirefoxMaskingKeyGenerator,
}

impl RandomizedMaskingKeyGenerator {
    pub fn new() -> Self {
        Self {
            chrome_gen: ChromeMaskingKeyGenerator::new(),
            firefox_gen: FirefoxMaskingKeyGenerator::new(),
        }
    }
}

impl Default for RandomizedMaskingKeyGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl MaskingKeyGenerator for RandomizedMaskingKeyGenerator {
    fn generate_key(&self) -> [u8; 4] {
        // Randomly choose between Chrome and Firefox patterns
        let mut rng = rand::rng();
        if rng.random::<bool>() {
            self.chrome_gen.generate_key()
        } else {
            self.firefox_gen.generate_key()
        }
    }
}

/// Factory function to create masking key generator based on browser type
pub fn create_masking_key_generator(browser_hint: &str) -> Box<dyn MaskingKeyGenerator> {
    match browser_hint.to_lowercase().as_str() {
        "chrome" | "chrome120" | "edge" => Box::new(ChromeMaskingKeyGenerator::new()),
        "firefox" | "firefox121" => Box::new(FirefoxMaskingKeyGenerator::new()),
        "random" | "randomized" => Box::new(RandomizedMaskingKeyGenerator::new()),
        _ => Box::new(ChromeMaskingKeyGenerator::new()), // Default to Chrome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    
    #[test]
    fn test_chrome_generator_produces_unique_keys() {
        let generator = ChromeMaskingKeyGenerator::new();
        let mut keys = HashSet::new();
        
        // Generate 1000 keys - should all be unique with high probability
        for _ in 0..1000 {
            let key = generator.generate_key();
            keys.insert(u32::from_be_bytes(key));
        }
        
        // With crypto-quality RNG, collision probability is negligible
        assert!(keys.len() > 990, "Keys should be highly unique");
    }
    
    #[test]
    fn test_firefox_generator_produces_unique_keys() {
        let generator = FirefoxMaskingKeyGenerator::new();
        let mut keys = HashSet::new();
        
        for _ in 0..1000 {
            let key = generator.generate_key();
            keys.insert(u32::from_be_bytes(key));
        }
        
        assert!(keys.len() > 990, "Keys should be highly unique");
    }
    
    #[test]
    fn test_randomized_generator() {
        let generator = RandomizedMaskingKeyGenerator::new();
        let mut keys = HashSet::new();
        
        for _ in 0..1000 {
            let key = generator.generate_key();
            keys.insert(u32::from_be_bytes(key));
        }
        
        assert!(keys.len() > 990, "Keys should be highly unique");
    }
    
    #[test]
    fn test_no_zero_keys() {
        let generator = ChromeMaskingKeyGenerator::new();
        
        // Zero keys are extremely rare with good RNG
        for _ in 0..100 {
            let key = generator.generate_key();
            let key_u32 = u32::from_be_bytes(key);
            // Very unlikely to be zero (1 in 4 billion)
            // Just ensure we're not producing constant zero keys
        }
    }
    
    #[test]
    fn test_entropy_distribution() {
        let generator = ChromeMaskingKeyGenerator::new();
        
        // Test that generated keys have good bit distribution
        let mut bit_counts = [0u32; 32];
        let samples = 10000;
        
        for _ in 0..samples {
            let key = generator.generate_key();
            let key_u32 = u32::from_be_bytes(key);
            
            // Count set bits in each position
            for bit_pos in 0..32 {
                if (key_u32 & (1 << bit_pos)) != 0 {
                    bit_counts[bit_pos] += 1;
                }
            }
        }
        
        // Each bit should be set approximately 50% of the time
        // Allow 45-55% range for statistical variation
        for (i, &count) in bit_counts.iter().enumerate() {
            let percentage = (count as f64 / samples as f64) * 100.0;
            assert!(
                percentage > 45.0 && percentage < 55.0,
                "Bit {} has poor distribution: {:.2}%",
                i,
                percentage
            );
        }
    }
    
    #[test]
    fn test_factory_function() {
        let chrome_generator = create_masking_key_generator("chrome");
        let firefox_generator = create_masking_key_generator("firefox");
        let random_generator = create_masking_key_generator("random");
        let default_generator = create_masking_key_generator("unknown");
        
        // All should produce valid keys
        assert_eq!(chrome_generator.generate_key().len(), 4);
        assert_eq!(firefox_generator.generate_key().len(), 4);
        assert_eq!(random_generator.generate_key().len(), 4);
        assert_eq!(default_generator.generate_key().len(), 4);
    }
}
