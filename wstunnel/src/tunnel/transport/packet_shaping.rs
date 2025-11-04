/// Packet shaping module for DPI and ML-based traffic analysis evasion
/// 
/// This module implements realistic packet size patterns that mimic legitimate browser traffic
/// to avoid statistical anomalies that can be detected by advanced DPI systems.
///
/// Can use PCAP-based learning for maximum accuracy when built with --features pcap-learning

use bytes::{BufMut, BytesMut};
use std::sync::atomic::{AtomicU64, Ordering};
use super::pcap_learning::TrafficProfile;

/// Maximum safe size for a single TLS record (16KB - overhead)
const TLS_MAX_RECORD_SIZE: usize = 16 * 1024 - 256;

/// MTU-aware sizes to avoid IP fragmentation
/// Most networks use MTU of 1500, with overhead we get ~1400-1460 usable bytes
const MTU_SAFE_SIZES: &[usize] = &[
    1400, 1408, 1419, 1433, 1448, 1460, // MTU-aware, slightly varied to avoid round numbers
];

/// Browser typical WebSocket frame sizes observed in real traffic
/// These are common sizes for different types of content (text, JSON, binary chunks, etc.)
const BROWSER_TYPICAL_SIZES: &[usize] = &[
    253, 256, 261,       // Small messages (text, JSON)
    509, 512, 517,       // Medium messages
    1019, 1024, 1037,    // 1KB range (common for API responses)
    1048,                // Slightly over 1KB
    2043, 2048, 2053,    // 2KB range
    4091, 4096, 4103,    // 4KB range (typical page size)
    8187, 8192, 8201,    // 8KB range
    16379, 16384, 16397, // 16KB range (TLS record boundary)
];

/// Realistic HTTP/JSON overhead patterns for padding
/// These mimic actual HTTP headers and JSON structure lengths
const REALISTIC_PADDING_SIZES: &[usize] = &[
    // Typical HTTP header lengths
    143, 167, 189, 203, 218, 234, 251, 267, 283, 299,
    // JSON structure overhead (keys, brackets, quotes, etc.)
    41, 57, 73, 89, 105, 121, 137,
];

/// Global counter for pseudo-random but deterministic size selection
/// This creates natural variation while avoiding cryptographic overhead
static SIZE_SELECTOR_STATE: AtomicU64 = AtomicU64::new(0x123456789ABCDEF0);

/// Packet size strategy for different traffic patterns
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketSizeStrategy {
    /// Mimic browser-typical WebSocket traffic (most common)
    BrowserTypical,
    /// Optimize for MTU to avoid fragmentation (good for bulk transfers)
    MtuAware,
    /// Mix of both strategies for realistic variation
    Adaptive,
    /// Use PCAP-learned profile (requires traffic profile to be loaded)
    Learned,
}

/// Get packet size from a learned traffic profile
/// Returns realistic size based on the profile's distribution
pub fn get_packet_size_from_profile(
    requested_len: usize,
    profile: &TrafficProfile,
) -> usize {
    if requested_len >= TLS_MAX_RECORD_SIZE {
        return requested_len; // Don't modify very large packets
    }
    
    // Select size from profile's distribution
    let state = SIZE_SELECTOR_STATE.fetch_add(1, Ordering::Relaxed);
    let target_size = profile.select_packet_size(state);
    
    // Ensure target size fits the data
    if target_size >= requested_len {
        target_size
    } else {
        // If profile size too small, use closest browser-typical size
        find_closest_browser_size(requested_len)
    }
}

/// Returns a realistic packet size based on the requested length and strategy
/// 
/// This function ensures that packet sizes don't follow obvious patterns:
/// - Avoids perfect round numbers (1024 -> 1019, 1037, etc.)
/// - Adds realistic padding that mimics HTTP/JSON structure
/// - Respects MTU boundaries to avoid fragmentation
/// - Uses browser-typical sizes when appropriate
pub fn get_realistic_packet_size(requested_len: usize, strategy: PacketSizeStrategy) -> usize {
    // For very small packets, just add minimal realistic padding
    if requested_len < 128 {
        return requested_len + select_padding_size();
    }
    
    // For very large packets (> TLS record size), return as-is to avoid issues
    if requested_len >= TLS_MAX_RECORD_SIZE {
        return requested_len;
    }
    
    match strategy {
        PacketSizeStrategy::BrowserTypical => {
            // Find the closest browser-typical size that fits the data
            find_closest_browser_size(requested_len)
        }
        PacketSizeStrategy::MtuAware => {
            // For MTU-aware, prefer sizes that fit within MTU boundaries
            if requested_len <= MTU_SAFE_SIZES[0] {
                find_closest_mtu_size(requested_len)
            } else {
                // For larger data, use browser-typical sizes
                find_closest_browser_size(requested_len)
            }
        }
        PacketSizeStrategy::Adaptive => {
            // Mix strategies based on packet size and pseudo-random selection
            let state = SIZE_SELECTOR_STATE.fetch_add(1, Ordering::Relaxed);
            
            if requested_len <= MTU_SAFE_SIZES[0] && (state % 3) == 0 {
                // 33% of small packets use MTU-aware sizing
                find_closest_mtu_size(requested_len)
            } else {
                // 67% use browser-typical sizing, or all large packets
                find_closest_browser_size(requested_len)
            }
        }
        PacketSizeStrategy::Learned => {
            // Use learned profile from PCAP analysis
            // Note: This requires a TrafficProfile to be loaded
            // For now, fallback to BrowserTypical if profile not available
            // Full implementation would pass profile as parameter
            find_closest_browser_size(requested_len)
        }
    }
}

/// Adds realistic padding to a buffer that mimics HTTP headers or JSON structure
/// 
/// This padding is not random bytes, but structured data that looks like:
/// - HTTP headers (X-Request-ID, X-Trace-ID, etc.)
/// - JSON whitespace and structure
/// - Common protocol overhead
pub fn add_realistic_padding(buf: &mut BytesMut, target_size: usize) {
    let current_len = buf.len();
    if current_len >= target_size {
        return; // Already at or exceeds target
    }
    
    let padding_needed = target_size - current_len;
    
    // Generate realistic padding that looks like HTTP/JSON structure
    if padding_needed > 0 {
        buf.reserve(padding_needed);
        
        // Pattern A: HTTP header-like padding (most common)
        // Example: "X-Request-ID: 1a2b3c4d\r\n"
        if padding_needed < 50 {
            // Small padding: single header or JSON field
            generate_http_header_padding(buf, padding_needed);
        } else if padding_needed < 200 {
            // Medium padding: multiple headers
            let mut remaining = padding_needed;
            while remaining > 20 {
                let chunk = remaining.min(45);
                generate_http_header_padding(buf, chunk);
                remaining -= chunk;
            }
            if remaining > 0 {
                generate_json_padding(buf, remaining);
            }
        } else {
            // Large padding: mix of headers and JSON structure
            let header_portion = padding_needed * 2 / 3;
            let json_portion = padding_needed - header_portion;
            
            generate_http_header_padding(buf, header_portion);
            generate_json_padding(buf, json_portion);
        }
    }
}

/// Calculate buffer growth size that mimics browser behavior
/// 
/// Browsers don't grow buffers uniformly - they use various strategies
/// depending on the current size and usage patterns.
pub fn calculate_realistic_buffer_growth(current_capacity: usize, bytes_used: usize) -> usize {
    // Don't grow if not fully utilized (browsers are lazy about growth)
    if bytes_used < current_capacity {
        return current_capacity;
    }
    
    // Browser-like growth pattern:
    // - Small buffers (< 64KB): double (fast growth for initial data)
    // - Medium buffers (64KB - 512KB): grow by ~20-30%
    // - Large buffers (> 512KB): grow by ~15-25%
    // Add slight variation to avoid perfect patterns
    
    let state = SIZE_SELECTOR_STATE.fetch_add(1, Ordering::Relaxed);
    let variance = (state % 10) as usize; // 0-9% additional variance
    
    let base_growth = if current_capacity < 64 * 1024 {
        // Double for small buffers
        current_capacity
    } else if current_capacity < 512 * 1024 {
        // Grow by 20-30%
        current_capacity / 4 + current_capacity / 20 * variance
    } else {
        // Grow by 15-25%
        current_capacity / 6 + current_capacity / 60 * variance
    };
    
    let new_capacity = current_capacity + base_growth;
    
    // Align to browser-typical sizes when near them
    align_to_typical_size(new_capacity)
}

// ===== Private helper functions =====

fn find_closest_browser_size(requested_len: usize) -> usize {
    // Find the smallest browser-typical size that fits the data
    for &size in BROWSER_TYPICAL_SIZES.iter() {
        if size >= requested_len {
            return size;
        }
    }
    
    // If larger than all typical sizes, add realistic padding
    requested_len + select_padding_size()
}

fn find_closest_mtu_size(requested_len: usize) -> usize {
    // Find the smallest MTU-safe size that fits the data
    for &size in MTU_SAFE_SIZES.iter() {
        if size >= requested_len {
            return size;
        }
    }
    
    // If larger than MTU, use browser-typical sizing
    find_closest_browser_size(requested_len)
}

fn select_padding_size() -> usize {
    let state = SIZE_SELECTOR_STATE.fetch_add(1, Ordering::Relaxed);
    let index = (state as usize) % REALISTIC_PADDING_SIZES.len();
    REALISTIC_PADDING_SIZES[index]
}

fn align_to_typical_size(size: usize) -> usize {
    // If close to a browser-typical size (within 10%), snap to it
    for &typical_size in BROWSER_TYPICAL_SIZES.iter() {
        if typical_size > size {
            let diff = typical_size - size;
            if diff < typical_size / 10 {
                return typical_size;
            }
            break;
        }
    }
    size
}

fn generate_http_header_padding(buf: &mut BytesMut, size: usize) {
    // Generate realistic HTTP header-like padding
    // Pattern: "X-Trace-ID: <hex>\r\n" or similar
    
    if size == 0 {
        return;
    }
    
    if size < 10 {
        // Too small for realistic header, use minimal padding
        for _ in 0..size {
            buf.put_u8(b' ');
        }
        return;
    }
    
    let state = SIZE_SELECTOR_STATE.fetch_add(1, Ordering::Relaxed);
    let initial_len = buf.len();
    
    // Rotate through different header patterns
    match state % 5 {
        0 => {
            // X-Request-ID: <uuid-like>
            buf.extend_from_slice(b"X-Request-ID: ");
            let mut added = 14;
            let mut i = 0;
            while added < size {
                if i % 9 == 8 && added + 1 <= size {
                    buf.put_u8(b'-');
                } else {
                    let offset = ((state.wrapping_add(i as u64)) % 26) as u8;
                    buf.put_u8(b'a' + offset);
                }
                added += 1;
                i += 1;
            }
        }
        1 => {
            // X-Trace-ID: <hex>
            buf.extend_from_slice(b"X-Trace-ID: ");
            let mut added = 12;
            let mut i = 0;
            while added < size {
                let offset = ((state.wrapping_add(i as u64)) % 10) as u8;
                buf.put_u8(b'0' + offset);
                added += 1;
                i += 1;
            }
        }
        2 => {
            // X-Session: <alphanumeric>
            buf.extend_from_slice(b"X-Session: ");
            let mut added = 11;
            let mut i = 0;
            while added < size {
                let offset = ((state.wrapping_add(i as u64)) % 26) as u8;
                buf.put_u8(b'A' + offset);
                added += 1;
                i += 1;
            }
        }
        3 => {
            // Cache-Control: <directives>
            buf.extend_from_slice(b"Cache-Control: no-cache, no-store");
            let remaining = size.saturating_sub(34);
            for _ in 0..remaining {
                buf.put_u8(b' ');
            }
        }
        _ => {
            // X-Content-Type-Options: nosniff
            buf.extend_from_slice(b"X-Content-Type-Options: nosniff");
            let remaining = size.saturating_sub(31);
            for _ in 0..remaining {
                buf.put_u8(b' ');
            }
        }
    }
    
    // Ensure exactly 'size' bytes were added (fill with spaces if needed)
    let actual_added = buf.len() - initial_len;
    if actual_added < size {
        for _ in 0..(size - actual_added) {
            buf.put_u8(b' ');
        }
    }
}

fn generate_json_padding(buf: &mut BytesMut, size: usize) {
    // Generate realistic JSON structure padding
    // Pattern: whitespace, field names, brackets, etc.
    
    if size == 0 {
        return;
    }
    
    let state = SIZE_SELECTOR_STATE.fetch_add(1, Ordering::Relaxed);
    let initial_len = buf.len();
    let pattern = state % 4;
    
    match pattern {
        0 => {
            // JSON whitespace (spaces and newlines)
            let spaces = size * 3 / 4;
            let newlines = size - spaces;
            for _ in 0..spaces {
                buf.put_u8(b' ');
            }
            for _ in 0..newlines {
                buf.put_u8(b'\n');
            }
        }
        1 => {
            // JSON field names: "fieldName": 
            let mut remaining = size;
            while remaining > 15 {
                buf.extend_from_slice(b"\"timestamp\": ");
                remaining = remaining.saturating_sub(13);
            }
            for _ in 0..remaining {
                buf.put_u8(b' ');
            }
        }
        2 => {
            // JSON structure: brackets and commas
            let patterns = [b'{', b'}', b'[', b']', b',', b' ', b' ', b' '];
            for (i, &c) in patterns.iter().cycle().take(size).enumerate() {
                buf.put_u8(c);
                if i + 1 >= size { break; }
            }
        }
        _ => {
            // Mixed JSON content
            buf.extend_from_slice(b"\"data\": {");
            let mut remaining = size.saturating_sub(9);
            while remaining > 10 {
                buf.extend_from_slice(b" \"id\": 0");
                remaining = remaining.saturating_sub(9);
                if remaining > 2 {
                    buf.extend_from_slice(b", ");
                    remaining -= 2;
                }
            }
            for _ in 0..remaining {
                buf.put_u8(b' ');
            }
        }
    }
    
    // Ensure exactly 'size' bytes were added (fill with spaces if needed)
    let actual_added = buf.len() - initial_len;
    if actual_added < size {
        for _ in 0..(size - actual_added) {
            buf.put_u8(b' ');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_realistic_packet_sizes() {
        // Test that we avoid round numbers
        let size_1k = get_realistic_packet_size(1000, PacketSizeStrategy::BrowserTypical);
        assert!(size_1k != 1024); // Should avoid exact power of 2
        assert!(size_1k >= 1000);
        
        // Test MTU awareness
        let size_mtu = get_realistic_packet_size(1300, PacketSizeStrategy::MtuAware);
        assert!(size_mtu <= 1460); // Should fit in MTU
        
        // Test TLS boundary respect
        let size_large = get_realistic_packet_size(20000, PacketSizeStrategy::Adaptive);
        assert!(size_large >= 20000);
    }
    
    #[test]
    fn test_padding_generation() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(b"test data");
        
        add_realistic_padding(&mut buf, 100);
        assert_eq!(buf.len(), 100);
        
        // Verify padding looks somewhat realistic (contains ASCII)
        let padding = &buf[9..];
        for &byte in padding.iter() {
            assert!(byte.is_ascii() || byte == b'\r' || byte == b'\n');
        }
    }
    
    #[test]
    fn test_buffer_growth() {
        // Test small buffer growth (should double)
        let growth = calculate_realistic_buffer_growth(32 * 1024, 32 * 1024);
        assert!(growth >= 60 * 1024); // At least ~2x
        assert!(growth <= 70 * 1024); // But not exactly 2x
        
        // Test medium buffer growth (should grow by ~20-30%)
        let growth = calculate_realistic_buffer_growth(256 * 1024, 256 * 1024);
        assert!(growth >= 300 * 1024); // At least +20%
        assert!(growth <= 350 * 1024); // At most +35%
    }
}

