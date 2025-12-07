/// Adversarial ML Module - Traffic Flow Watermarking Resistance
///
/// This module implements advanced techniques to evade ML-based traffic analysis
/// that creates "watermarks" from packet size sequences and Inter-Arrival Times (IAT).
///
/// ## Problem
/// Modern DPI systems use Machine Learning models to classify encrypted traffic by:
/// - Analyzing sequences of packet sizes (e.g., [512, 1024, 256, ...])
/// - Measuring Inter-Arrival Times between packets
/// - Detecting burst patterns and flow characteristics
/// - Creating statistical "fingerprints" (watermarks) that identify tunnel traffic
///
/// ## Solution: Adversarial Padding with ML Classifier Awareness
///
/// This module implements several defense techniques:
///
/// 1. **Adversarial Packet Size Perturbation**
///    - Add padding that breaks ML feature extraction
///    - Use directional padding (make small packets larger, split large packets)
///    - Apply FRONT/TOTAL padding strategies from academic research
///
/// 2. **IAT (Inter-Arrival Time) Randomization**
///    - Add controlled delays between packets
///    - Mimic realistic application timing patterns
///    - Avoid perfect timing that ML models can detect
///
/// 3. **Dummy Packet Injection**
///    - Insert fake packets to change flow statistics
///    - Use realistic sizes and timing
///    - Maintain protocol compatibility
///
/// 4. **Burst Pattern Obfuscation**
///    - Break up suspicious burst patterns
///    - Add micro-delays within bursts
///    - Mimic natural application behavior
///
/// ## References
/// - "A Multi-tab Website Fingerprinting Attack" (ACSAC 2020)
/// - "Effective Attacks and Defenses for Website Fingerprinting" (USENIX 2014)
/// - "Walkie-Talkie: An Efficient Defense Against Passive Website Fingerprinting" (USENIX 2017)

use bytes::{BufMut, BytesMut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use super::pcap_learning::TrafficProfile;

// ===== Crypto-based Padding Generator =====
// Uses ChaCha20-like PRNG for high-quality random padding that looks like encrypted data
// This is critical for Russian DPI which analyzes entropy patterns

/// ChaCha20-based pseudo-random padding generator
/// Produces high-entropy bytes indistinguishable from encrypted traffic
struct CryptoPaddingGenerator {
    state: [u32; 16],
    output_block: [u8; 64],
    output_pos: usize,
}

impl CryptoPaddingGenerator {
    /// Create new generator with seed
    fn new(seed: u64) -> Self {
        // Initialize ChaCha20-like state
        // Constants from original ChaCha20
        let mut state = [0u32; 16];
        state[0] = 0x61707865; // "expa"
        state[1] = 0x3320646e; // "nd 3"
        state[2] = 0x79622d32; // "2-by"
        state[3] = 0x6b206574; // "te k"
        
        // Key from seed (expand to 256 bits)
        let key_parts = [
            seed as u32,
            (seed >> 32) as u32,
            seed.wrapping_mul(0x9e3779b97f4a7c15) as u32,
            (seed.wrapping_mul(0x9e3779b97f4a7c15) >> 32) as u32,
            seed.wrapping_add(0xdeadbeef) as u32,
            (seed.wrapping_add(0xdeadbeef) >> 32) as u32,
            seed.wrapping_mul(0x517cc1b727220a95) as u32,
            (seed.wrapping_mul(0x517cc1b727220a95) >> 32) as u32,
        ];
        
        for (i, &k) in key_parts.iter().enumerate() {
            state[4 + i] = k;
        }
        
        // Counter and nonce
        state[12] = 0;
        state[13] = 0;
        state[14] = (seed >> 16) as u32;
        state[15] = (seed >> 48) as u32;
        
        let mut generator = Self {
            state,
            output_block: [0u8; 64],
            output_pos: 64, // Force regeneration on first use
        };
        
        generator.generate_block();
        generator
    }
    
    /// Quarter round - core ChaCha operation
    #[inline(always)]
    fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(16);
        
        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(12);
        
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(8);
        
        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(7);
    }
    
    /// Generate 64 bytes of random output
    fn generate_block(&mut self) {
        let mut working = self.state;
        
        // 20 rounds (10 double-rounds)
        for _ in 0..10 {
            // Column rounds
            Self::quarter_round(&mut working, 0, 4, 8, 12);
            Self::quarter_round(&mut working, 1, 5, 9, 13);
            Self::quarter_round(&mut working, 2, 6, 10, 14);
            Self::quarter_round(&mut working, 3, 7, 11, 15);
            
            // Diagonal rounds
            Self::quarter_round(&mut working, 0, 5, 10, 15);
            Self::quarter_round(&mut working, 1, 6, 11, 12);
            Self::quarter_round(&mut working, 2, 7, 8, 13);
            Self::quarter_round(&mut working, 3, 4, 9, 14);
        }
        
        // Add original state
        for (w, s) in working.iter_mut().zip(self.state.iter()) {
            *w = w.wrapping_add(*s);
        }
        
        // Convert to bytes
        for (i, word) in working.iter().enumerate() {
            let bytes = word.to_le_bytes();
            self.output_block[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }
        
        // Increment counter
        self.state[12] = self.state[12].wrapping_add(1);
        if self.state[12] == 0 {
            self.state[13] = self.state[13].wrapping_add(1);
        }
        
        self.output_pos = 0;
    }
    
    /// Get next random byte
    #[inline]
    fn next_byte(&mut self) -> u8 {
        if self.output_pos >= 64 {
            self.generate_block();
        }
        let byte = self.output_block[self.output_pos];
        self.output_pos += 1;
        byte
    }
    
    /// Fill buffer with random bytes
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            *byte = self.next_byte();
        }
    }
}

/// Generate cryptographically-strong random padding
/// This padding looks indistinguishable from encrypted traffic
pub fn generate_crypto_padding(size: usize, seed: u64) -> Vec<u8> {
    let mut generator = CryptoPaddingGenerator::new(seed);
    let mut padding = vec![0u8; size];
    generator.fill_bytes(&mut padding);
    padding
}

/// Fill BytesMut with crypto padding (avoids allocation)
pub fn fill_crypto_padding(buf: &mut BytesMut, size: usize, seed: u64) {
    let mut generator = CryptoPaddingGenerator::new(seed);
    buf.reserve(size);
    for _ in 0..size {
        buf.put_u8(generator.next_byte());
    }
}

/// Global state for adversarial perturbation (PRNG state)
/// Using atomic for thread-safe pseudo-random generation without locks
static ADVERSARIAL_STATE: AtomicU64 = AtomicU64::new(0xDEADBEEF_CAFEBABE);

/// Configuration for adversarial ML defense
#[derive(Debug, Clone)]
pub struct AdversarialConfig {
    /// Enable adversarial padding
    pub enable_padding: bool,
    
    /// Enable IAT randomization
    pub enable_iat_randomization: bool,
    
    /// Enable dummy packet injection
    pub enable_dummy_packets: bool,
    
    /// Padding strategy
    pub padding_strategy: PaddingStrategy,
    
    /// IAT randomization level (0.0 = none, 1.0 = aggressive)
    pub iat_randomization_level: f64,
    
    /// Dummy packet injection rate (packets per second)
    pub dummy_packet_rate: f64,
    
    /// Target application profile (for realistic mimicking)
    pub target_profile: Option<String>,
}

impl Default for AdversarialConfig {
    fn default() -> Self {
        Self {
            enable_padding: true,
            enable_iat_randomization: true,
            enable_dummy_packets: false, // Off by default (adds overhead)
            padding_strategy: PaddingStrategy::DirectionalPadding,
            iat_randomization_level: 0.5, // Moderate randomization
            dummy_packet_rate: 0.0,
            target_profile: None,
        }
    }
}

/// Padding strategy for adversarial defense
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingStrategy {
    /// FRONT padding: Add all padding to first packet in a burst
    /// Good for defeating early packet size classifiers
    Front,
    
    /// TOTAL padding: Pad to fixed total size per burst
    /// Good for defeating burst-based classifiers
    Total,
    
    /// Directional padding: Make small packets bigger, don't touch large ones
    /// Efficient and effective against many ML classifiers
    DirectionalPadding,
    
    /// Adaptive padding: Change strategy based on traffic patterns
    /// Most sophisticated but higher overhead
    Adaptive,
    
    /// Random padding: Add random amount to each packet
    /// Good baseline defense
    Random,
}

/// Apply adversarial padding to a packet
///
/// This function adds padding that is specifically designed to fool ML classifiers
/// by breaking their feature extraction patterns.
///
/// # Arguments
/// * `buf` - The packet buffer to pad
/// * `config` - Adversarial configuration
/// * `packet_index_in_burst` - Index of this packet in current burst (0 = first)
/// * `burst_total_size` - Total size of all packets in this burst
///
/// # Returns
/// The amount of padding added
pub fn apply_adversarial_padding(
    buf: &mut BytesMut,
    config: &AdversarialConfig,
    packet_index_in_burst: usize,
    burst_total_size: usize,
) -> usize {
    if !config.enable_padding {
        return 0;
    }
    
    let _original_size = buf.len();
    
    match config.padding_strategy {
        PaddingStrategy::Front => {
            // FRONT padding: Only pad the first packet
            if packet_index_in_burst == 0 {
                apply_front_padding(buf, burst_total_size)
            } else {
                0
            }
        }
        
        PaddingStrategy::Total => {
            // TOTAL padding: Pad to reach fixed total size
            apply_total_padding(buf, packet_index_in_burst, burst_total_size)
        }
        
        PaddingStrategy::DirectionalPadding => {
            // Directional: Small packets get padded more
            apply_directional_padding(buf)
        }
        
        PaddingStrategy::Adaptive => {
            // Adaptive: Choose strategy based on packet characteristics
            apply_adaptive_padding(buf, packet_index_in_burst, burst_total_size)
        }
        
        PaddingStrategy::Random => {
            // Random: Simple random padding
            apply_random_padding(buf)
        }
    }
}

/// Calculate IAT (Inter-Arrival Time) delay with adversarial randomization
///
/// ML models often use IAT patterns as strong features. This function adds
/// realistic randomization that breaks IAT-based fingerprints while maintaining
/// acceptable latency and mimicking real application behavior.
///
/// # Arguments
/// * `base_iat_ms` - Base inter-arrival time in milliseconds
/// * `config` - Adversarial configuration
/// * `traffic_profile` - Optional traffic profile to mimic
///
/// # Returns
/// Duration to delay before sending next packet
pub fn calculate_adversarial_iat(
    base_iat_ms: u64,
    config: &AdversarialConfig,
    traffic_profile: Option<&TrafficProfile>,
) -> Duration {
    if !config.enable_iat_randomization {
        return Duration::from_millis(base_iat_ms);
    }
    
    let state = ADVERSARIAL_STATE.fetch_add(1, Ordering::Relaxed);
    
    // If we have a profile, use its IAT distribution
    if let Some(profile) = traffic_profile {
        let profile_iat = profile.select_iat_ms(state);
        
        // Blend between base IAT and profile IAT based on randomization level
        let blend_factor = config.iat_randomization_level;
        let blended = (base_iat_ms as f64 * (1.0 - blend_factor)) 
                    + (profile_iat as f64 * blend_factor);
        
        return Duration::from_millis(blended as u64);
    }
    
    // Otherwise, apply randomization to base IAT
    // Use exponential distribution for realistic network jitter
    let randomization = config.iat_randomization_level;
    
    // Generate pseudo-random factor using fast PRNG
    // This creates variation without expensive crypto RNG
    let random_factor = generate_random_factor(state);
    
    // Apply randomization: ±(randomization_level * 100)% variation
    // Example: level=0.5 gives ±50% variation
    let variation = (random_factor - 0.5) * 2.0 * randomization;
    let adjusted_iat = base_iat_ms as f64 * (1.0 + variation);
    
    // Clamp to reasonable range (don't go negative, don't exceed 10x)
    let clamped = adjusted_iat.max(0.0).min(base_iat_ms as f64 * 10.0);
    
    Duration::from_millis(clamped as u64)
}

/// Determine if a dummy packet should be injected
///
/// Dummy packets change flow statistics and make ML classification harder.
/// However, they add overhead, so use sparingly.
pub fn should_inject_dummy_packet(
    config: &AdversarialConfig,
    time_since_last_dummy_ms: u64,
) -> bool {
    if !config.enable_dummy_packets || config.dummy_packet_rate <= 0.0 {
        return false;
    }
    
    // Calculate expected interval between dummy packets
    let expected_interval_ms = (1000.0 / config.dummy_packet_rate) as u64;
    
    // Add some randomness to avoid perfect timing
    let state = ADVERSARIAL_STATE.fetch_add(1, Ordering::Relaxed);
    let jitter = ((state % 40) as i64) - 20; // ±20% jitter
    let actual_interval = ((expected_interval_ms as i64) + 
                          (expected_interval_ms as i64 * jitter / 100)) as u64;
    
    time_since_last_dummy_ms >= actual_interval
}

/// Generate a dummy packet with realistic size
///
/// Dummy packets should look like real traffic to avoid detection.
/// Uses crypto-based random generation to match encrypted traffic entropy.
pub fn generate_dummy_packet(traffic_profile: Option<&TrafficProfile>) -> BytesMut {
    let state = ADVERSARIAL_STATE.fetch_add(1, Ordering::Relaxed);
    
    // Determine size
    let size = if let Some(profile) = traffic_profile {
        profile.select_packet_size(state)
    } else {
        // Use common sizes if no profile
        let sizes = [128, 256, 512, 1024, 1460];
        sizes[(state as usize) % sizes.len()]
    };
    
    // Create buffer with high-entropy data that matches encrypted traffic
    // This is critical for Russian DPI which analyzes entropy patterns
    let mut buf = BytesMut::with_capacity(size);
    fill_crypto_padding(&mut buf, size, state);
    
    buf
}

/// Analyze burst pattern and return burst metadata
///
/// ML models analyze burst patterns. This function helps identify bursts
/// so we can apply appropriate defenses.
#[derive(Debug, Clone)]
pub struct BurstMetadata {
    pub size: usize,
    pub packet_count: usize,
    pub total_bytes: usize,
    pub should_split: bool,
}

pub fn analyze_burst(
    packet_sizes: &[usize],
    _iat_threshold_ms: u64,
) -> BurstMetadata {
    let packet_count = packet_sizes.len();
    let total_bytes: usize = packet_sizes.iter().sum();
    
    // Determine if this looks like a suspicious burst
    // Large bursts (>10 packets) are fingerprinted by ML
    let should_split = packet_count > 10 && total_bytes > 100_000;
    
    BurstMetadata {
        size: packet_count,
        packet_count,
        total_bytes,
        should_split,
    }
}

// ===== Private implementation functions =====

fn apply_front_padding(buf: &mut BytesMut, _burst_total_size: usize) -> usize {
    // Pad first packet to MTU size (1460 bytes)
    const MTU_SIZE: usize = 1460;
    
    let current_size = buf.len();
    if current_size >= MTU_SIZE {
        return 0; // Already large enough
    }
    
    let padding_needed = MTU_SIZE - current_size;
    
    // Use crypto-based padding for high entropy (defeats DPI entropy analysis)
    let seed = ADVERSARIAL_STATE.fetch_add(1, Ordering::Relaxed);
    fill_crypto_padding(buf, padding_needed, seed);
    
    padding_needed
}

fn apply_total_padding(
    buf: &mut BytesMut,
    _packet_index: usize,
    burst_total_size: usize,
) -> usize {
    // TOTAL padding: Distribute padding across burst to reach fixed size
    // Target: Round up burst size to nearest multiple of 16KB
    const BLOCK_SIZE: usize = 16 * 1024;
    
    let target_burst_size = ((burst_total_size / BLOCK_SIZE) + 1) * BLOCK_SIZE;
    let total_padding_needed = target_burst_size.saturating_sub(burst_total_size);
    
    if total_padding_needed == 0 {
        return 0;
    }
    
    // Distribute padding evenly across packets in burst
    // (In real implementation, caller would track burst state)
    // For now, add small amount to each packet
    let padding_per_packet = 512; // Fixed amount per packet
    
    // Use crypto-based padding for high entropy (defeats DPI entropy analysis)
    let seed = ADVERSARIAL_STATE.fetch_add(1, Ordering::Relaxed);
    fill_crypto_padding(buf, padding_per_packet, seed);
    
    padding_per_packet
}

fn apply_directional_padding(buf: &mut BytesMut) -> usize {
    let current_size = buf.len();
    
    // Directional padding: Make small packets look bigger
    // This is very effective against ML classifiers that use packet size as feature
    
    // Small packets (<500 bytes): Pad to 1200-1400 bytes
    // Medium packets (500-1400): Pad to 1400-1500
    // Large packets (>1400): Don't pad (efficient)
    
    let target_size = if current_size < 500 {
        // Pad small packets aggressively
        1200 + ((current_size * 7) % 200) // 1200-1400 with variation
    } else if current_size < 1400 {
        // Pad medium packets moderately
        1400 + ((current_size * 3) % 100) // 1400-1500
    } else {
        // Don't pad large packets
        return 0;
    };
    
    let padding_needed = target_size.saturating_sub(current_size);
    
    if padding_needed > 0 {
        // Use crypto-based padding for high entropy (defeats DPI entropy analysis)
        let seed = ADVERSARIAL_STATE.fetch_add(1, Ordering::Relaxed);
        fill_crypto_padding(buf, padding_needed, seed);
    }
    
    padding_needed
}

fn apply_adaptive_padding(
    buf: &mut BytesMut,
    packet_index: usize,
    burst_total_size: usize,
) -> usize {
    // Adaptive: Choose strategy based on packet characteristics
    let current_size = buf.len();
    
    let state = ADVERSARIAL_STATE.fetch_add(1, Ordering::Relaxed);
    
    // Heuristics to choose strategy:
    // - First packet in burst: Use FRONT padding
    // - Small packets: Use directional padding
    // - Large burst: Use TOTAL padding
    // - Default: Random padding
    
    if packet_index == 0 && burst_total_size > 10000 {
        apply_front_padding(buf, burst_total_size)
    } else if current_size < 800 {
        apply_directional_padding(buf)
    } else if (state % 3) == 0 {
        apply_total_padding(buf, packet_index, burst_total_size)
    } else {
        apply_random_padding(buf)
    }
}

fn apply_random_padding(buf: &mut BytesMut) -> usize {
    let state = ADVERSARIAL_STATE.fetch_add(1, Ordering::Relaxed);
    
    // Add random padding between 0-512 bytes
    let padding_size = (state % 512) as usize;
    
    if padding_size > 0 {
        // Use crypto-based padding for high entropy (defeats DPI entropy analysis)
        fill_crypto_padding(buf, padding_size, state);
    }
    
    padding_size
}

/// Generate pseudo-random factor in range [0.0, 1.0]
/// Uses fast non-cryptographic PRNG for performance
fn generate_random_factor(seed: u64) -> f64 {
    // Use a simple splitmix64-like hash for good distribution
    let mut state = seed.wrapping_add(0x9e3779b97f4a7c15);
    state = (state ^ (state >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    state = (state ^ (state >> 27)).wrapping_mul(0x94d049bb133111eb);
    state = state ^ (state >> 31);
    
    // Convert to [0.0, 1.0]
    (state as f64) / (u64::MAX as f64)
}

/// Split data into multiple chunks with adversarial sizes
///
/// This is the key technique for evading ML classifiers WITHOUT modifying the tunneled data.
/// Instead of adding padding, we split large blocks into smaller WebSocket frames with
/// realistic sizes that match the target profile.
///
/// This is safe for binary protocols (SSH, etc.) because we don't modify the data,
/// just how it's framed for transport.
///
/// # Arguments
/// * `data_len` - Total length of data to send
/// * `config` - Adversarial configuration
/// * `traffic_profile` - Optional traffic profile for realistic sizes
///
/// # Returns
/// Vec of chunk sizes that sum to data_len
pub fn calculate_frame_split_sizes(
    data_len: usize,
    config: &AdversarialConfig,
    traffic_profile: Option<&TrafficProfile>,
) -> Vec<usize> {
    if !config.enable_padding || data_len == 0 {
        return vec![data_len];
    }
    
    // For small data, don't split
    if data_len < 1024 {
        return vec![data_len];
    }
    
    let mut chunks = Vec::new();
    let mut remaining = data_len;
    let state = ADVERSARIAL_STATE.fetch_add(1, Ordering::Relaxed);
    
    // Determine target chunk sizes based on profile or defaults
    let target_sizes = if let Some(profile) = traffic_profile {
        // Use profile's packet sizes as chunk targets
        let mut sizes = Vec::new();
        let mut seed = state;
        while remaining > 0 {
            seed = seed.wrapping_add(1);
            let size = profile.select_packet_size(seed);
            sizes.push(size);
            if sizes.len() > 100 {
                break; // Safety limit
            }
        }
        sizes
    } else {
        // Use realistic browser WebSocket frame sizes
        vec![1019, 1460, 2048, 4096, 8192, 16384]
    };
    
    // Split data into chunks matching target sizes
    let mut size_idx = 0;
    while remaining > 0 {
        let target = target_sizes[size_idx % target_sizes.len()];
        
        // Take smaller of target size or remaining data
        let chunk_size = if remaining <= target {
            remaining
        } else {
            // Add slight variation to avoid perfect patterns
            let variation = ((state.wrapping_add(size_idx as u64)) % 100) as usize;
            (target.saturating_sub(50) + variation).min(remaining)
        };
        
        chunks.push(chunk_size);
        remaining = remaining.saturating_sub(chunk_size);
        size_idx += 1;
        
        // Safety limit
        if chunks.len() > 100 {
            if remaining > 0 {
                chunks.push(remaining);
            }
            break;
        }
    }
    
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_directional_padding() {
        let mut small_buf = BytesMut::new();
        small_buf.extend_from_slice(&[0u8; 400]);
        
        let config = AdversarialConfig::default();
        let padded = apply_adversarial_padding(
            &mut small_buf, 
            &config, 
            0, 
            400
        );
        
        // Small packet should be padded significantly
        assert!(padded > 0);
        assert!(small_buf.len() >= 1200);
    }
    
    #[test]
    fn test_iat_randomization() {
        let config = AdversarialConfig {
            enable_iat_randomization: true,
            iat_randomization_level: 0.5,
            ..Default::default()
        };
        
        let base_iat = 100; // 100ms
        
        // Generate multiple IATs and check they vary
        let mut iats = Vec::new();
        for _ in 0..10 {
            let iat = calculate_adversarial_iat(base_iat, &config, None);
            iats.push(iat.as_millis());
        }
        
        // Should have variation
        let min = iats.iter().min().unwrap();
        let max = iats.iter().max().unwrap();
        assert!(max > min); // Should have some variation
        
        // Should be within reasonable range
        for iat in iats {
            assert!(iat <= base_iat as u128 * 10); // Not more than 10x
        }
    }
    
    #[test]
    fn test_dummy_packet_injection() {
        let config = AdversarialConfig {
            enable_dummy_packets: true,
            dummy_packet_rate: 10.0, // 10 packets per second = 100ms interval
            ..Default::default()
        };
        
        // Should inject after enough time
        assert!(should_inject_dummy_packet(&config, 150));
        
        // Should not inject too early
        assert!(!should_inject_dummy_packet(&config, 10));
    }
    
    #[test]
    fn test_dummy_packet_generation() {
        let packet = generate_dummy_packet(None);
        
        // Should be reasonable size
        assert!(packet.len() >= 128);
        assert!(packet.len() <= 2048);
        
        // Should contain data
        assert!(!packet.is_empty());
    }
    
    #[test]
    fn test_burst_analysis() {
        let packet_sizes = vec![512, 1024, 256, 512, 1024, 512];
        let metadata = analyze_burst(&packet_sizes, 10);
        
        assert_eq!(metadata.packet_count, 6);
        assert_eq!(metadata.total_bytes, 3840);
    }
    
    #[test]
    fn test_random_factor_distribution() {
        let mut factors = Vec::new();
        for i in 0..1000 {
            let factor = generate_random_factor(i);
            assert!(factor >= 0.0 && factor <= 1.0);
            factors.push(factor);
        }
        
        // Check distribution is somewhat uniform
        let avg: f64 = factors.iter().sum::<f64>() / factors.len() as f64;
        assert!(avg > 0.4 && avg < 0.6); // Should be around 0.5
    }
    
    #[test]
    fn test_frame_split_sizes() {
        let config = AdversarialConfig::default();
        
        // Test small data (should not split)
        let chunks = calculate_frame_split_sizes(512, &config, None);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], 512);
        
        // Test large data (should split)
        let chunks = calculate_frame_split_sizes(10000, &config, None);
        assert!(chunks.len() > 1); // Should be split into multiple chunks
        
        // Verify all chunks sum to original size
        let total: usize = chunks.iter().sum();
        assert_eq!(total, 10000);
        
        // Verify chunks are reasonable sizes
        for chunk in chunks {
            assert!(chunk > 0);
            assert!(chunk <= 16384); // Not larger than max frame size
        }
    }
    
    #[test]
    fn test_frame_split_with_profile() {
        let config = AdversarialConfig::default();
        let profile = TrafficProfile::default();
        
        let chunks = calculate_frame_split_sizes(20000, &config, Some(&profile));
        
        assert!(chunks.len() > 1);
        
        // Verify chunks sum to original
        let total: usize = chunks.iter().sum();
        assert_eq!(total, 20000);
    }
    
    #[test]
    fn test_frame_split_disabled() {
        let config = AdversarialConfig {
            enable_padding: false,
            ..Default::default()
        };
        
        // Should not split when disabled
        let chunks = calculate_frame_split_sizes(10000, &config, None);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], 10000);
    }
}

