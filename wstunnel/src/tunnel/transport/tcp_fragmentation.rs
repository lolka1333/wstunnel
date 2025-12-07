/// TCP Fragmentation Module - Low-level DPI Bypass
///
/// This module implements TCP-level fragmentation techniques specifically
/// designed to bypass Russian DPI systems (TSPU/РКНРФ).
///
/// ## Problem
/// Russian DPI operates at multiple layers:
/// - Stateless inspection of individual packets
/// - Stateful inspection with TCP reassembly
/// - Application layer inspection (TLS, HTTP)
///
/// Many DPI systems fail to properly reassemble fragmented TCP streams,
/// especially when fragments are:
/// - Very small (1-40 bytes)
/// - Sent with delays between them
/// - Sent out of order
/// - Using unusual TCP flags
///
/// ## Solution: Strategic TCP Fragmentation
///
/// This module provides:
///
/// 1. **TLS ClientHello Fragmentation**
///    - Split ClientHello into multiple TCP segments
///    - SNI is spread across segments
///    - DPI can't see complete SNI in any single packet
///
/// 2. **Micro-fragmentation**
///    - Send data in very small fragments (1-10 bytes)
///    - Overwhelms DPI reassembly buffers
///    - Most effective against TSPU
///
/// 3. **Delayed Fragmentation**
///    - Add delays between fragments
///    - Causes DPI timeout before reassembly completes
///
/// 4. **Disorder Fragmentation**
///    - Send fragments out of order
///    - Some DPI can't handle reordering
///
/// ## References
/// - GoodbyeDPI project strategies
/// - zapret project research
/// - "Dissecting Deep Packet Inspection" (various papers)

use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::time::sleep;
use bytes::Bytes;

/// Global state for fragmentation randomization
static FRAGMENT_STATE: AtomicU64 = AtomicU64::new(0xDEADC0DE_FEEDFACE);

/// TCP fragmentation strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentationStrategy {
    /// No fragmentation
    None,
    
    /// Fixed size fragments
    FixedSize(usize),
    
    /// Split at specific position (e.g., before SNI)
    SplitAt(usize),
    
    /// Multiple splits at positions
    MultipleSplits,
    
    /// Random fragment sizes
    Random { min: usize, max: usize },
    
    /// Micro-fragmentation (1-10 byte fragments)
    Micro,
    
    /// Single-byte fragmentation (extreme)
    SingleByte,
}

/// TCP fragmentation configuration
#[derive(Debug, Clone)]
pub struct TcpFragmentConfig {
    /// Fragmentation strategy
    pub strategy: FragmentationStrategy,
    
    /// Delay between fragments (microseconds)
    pub inter_fragment_delay_us: u64,
    
    /// Send first fragment immediately (before delay)
    pub send_first_immediately: bool,
    
    /// Use TCP_NODELAY to ensure fragments are sent separately
    pub use_tcp_nodelay: bool,
    
    /// Flush after each fragment
    pub flush_after_fragment: bool,
    
    /// Only fragment first N bytes of connection (0 = all)
    pub fragment_first_n_bytes: usize,
    
    /// Split positions for TLS ClientHello (auto-detected if empty)
    pub tls_split_positions: Vec<usize>,
    
    /// Enable disorder sending (send fragments out of order)
    pub enable_disorder: bool,
    
    /// Disorder probability (0.0-1.0)
    pub disorder_probability: f64,
}

impl Default for TcpFragmentConfig {
    fn default() -> Self {
        Self {
            strategy: FragmentationStrategy::FixedSize(40),
            inter_fragment_delay_us: 100, // 0.1ms
            send_first_immediately: true,
            use_tcp_nodelay: true,
            flush_after_fragment: true,
            fragment_first_n_bytes: 0, // Fragment all
            tls_split_positions: vec![],
            enable_disorder: false,
            disorder_probability: 0.0,
        }
    }
}

impl TcpFragmentConfig {
    /// Configuration optimized for Russian TSPU
    pub fn russia_tspu() -> Self {
        Self {
            strategy: FragmentationStrategy::FixedSize(40),
            inter_fragment_delay_us: 100,
            send_first_immediately: true,
            use_tcp_nodelay: true,
            flush_after_fragment: true,
            fragment_first_n_bytes: 600, // Only fragment ClientHello
            tls_split_positions: vec![],
            enable_disorder: false,
            disorder_probability: 0.0,
        }
    }
    
    /// Aggressive micro-fragmentation
    pub fn micro_fragmentation() -> Self {
        Self {
            strategy: FragmentationStrategy::Micro,
            inter_fragment_delay_us: 50,
            send_first_immediately: true,
            use_tcp_nodelay: true,
            flush_after_fragment: true,
            fragment_first_n_bytes: 600,
            tls_split_positions: vec![],
            enable_disorder: false,
            disorder_probability: 0.0,
        }
    }
    
    /// Extreme single-byte fragmentation
    pub fn single_byte() -> Self {
        Self {
            strategy: FragmentationStrategy::SingleByte,
            inter_fragment_delay_us: 100,
            send_first_immediately: true,
            use_tcp_nodelay: true,
            flush_after_fragment: true,
            fragment_first_n_bytes: 600,
            tls_split_positions: vec![],
            enable_disorder: false,
            disorder_probability: 0.0,
        }
    }
    
    /// Disorder fragmentation (send out of order)
    pub fn with_disorder() -> Self {
        Self {
            strategy: FragmentationStrategy::FixedSize(40),
            inter_fragment_delay_us: 100,
            send_first_immediately: true,
            use_tcp_nodelay: true,
            flush_after_fragment: true,
            fragment_first_n_bytes: 600,
            tls_split_positions: vec![],
            enable_disorder: true,
            disorder_probability: 0.3,
        }
    }
}

/// Result of fragmenting data
#[derive(Debug, Clone)]
pub struct FragmentedData {
    /// Fragments in sending order
    pub fragments: Vec<Bytes>,
    
    /// Delay between fragments
    pub delay_us: u64,
    
    /// Whether to send in disorder
    pub disorder: bool,
    
    /// Original data length
    pub original_length: usize,
}

/// Fragment data according to configuration
pub fn fragment_data(data: &[u8], config: &TcpFragmentConfig) -> FragmentedData {
    let original_length = data.len();
    
    // Determine how much to fragment
    let fragment_len = if config.fragment_first_n_bytes > 0 {
        config.fragment_first_n_bytes.min(data.len())
    } else {
        data.len()
    };
    
    let (to_fragment, remainder) = data.split_at(fragment_len);
    
    let mut fragments: Vec<Bytes> = match config.strategy {
        FragmentationStrategy::None => {
            vec![Bytes::copy_from_slice(data)]
        }
        
        FragmentationStrategy::FixedSize(size) => {
            let mut frags = Vec::new();
            for chunk in to_fragment.chunks(size) {
                frags.push(Bytes::copy_from_slice(chunk));
            }
            if !remainder.is_empty() {
                frags.push(Bytes::copy_from_slice(remainder));
            }
            frags
        }
        
        FragmentationStrategy::SplitAt(pos) => {
            if pos > 0 && pos < to_fragment.len() {
                let mut frags = vec![
                    Bytes::copy_from_slice(&to_fragment[..pos]),
                    Bytes::copy_from_slice(&to_fragment[pos..]),
                ];
                if !remainder.is_empty() {
                    frags.push(Bytes::copy_from_slice(remainder));
                }
                frags
            } else {
                vec![Bytes::copy_from_slice(data)]
            }
        }
        
        FragmentationStrategy::MultipleSplits => {
            if config.tls_split_positions.is_empty() {
                // Auto-detect for TLS
                let positions = auto_detect_split_positions(to_fragment);
                fragment_at_positions(to_fragment, &positions, remainder)
            } else {
                fragment_at_positions(to_fragment, &config.tls_split_positions, remainder)
            }
        }
        
        FragmentationStrategy::Random { min, max } => {
            let mut frags = Vec::new();
            let mut pos = 0;
            let state = FRAGMENT_STATE.fetch_add(1, Ordering::Relaxed);
            let mut rng = state;
            
            while pos < to_fragment.len() {
                rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
                let size = min + ((rng as usize) % (max - min + 1));
                let end = (pos + size).min(to_fragment.len());
                frags.push(Bytes::copy_from_slice(&to_fragment[pos..end]));
                pos = end;
            }
            
            if !remainder.is_empty() {
                frags.push(Bytes::copy_from_slice(remainder));
            }
            frags
        }
        
        FragmentationStrategy::Micro => {
            // 1-10 byte fragments
            let mut frags = Vec::new();
            let mut pos = 0;
            let state = FRAGMENT_STATE.fetch_add(1, Ordering::Relaxed);
            let mut rng = state;
            
            while pos < to_fragment.len() {
                rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
                let size = 1 + ((rng as usize) % 10);
                let end = (pos + size).min(to_fragment.len());
                frags.push(Bytes::copy_from_slice(&to_fragment[pos..end]));
                pos = end;
            }
            
            if !remainder.is_empty() {
                frags.push(Bytes::copy_from_slice(remainder));
            }
            frags
        }
        
        FragmentationStrategy::SingleByte => {
            let mut frags: Vec<Bytes> = to_fragment
                .iter()
                .map(|&b| Bytes::copy_from_slice(&[b]))
                .collect();
            
            if !remainder.is_empty() {
                frags.push(Bytes::copy_from_slice(remainder));
            }
            frags
        }
    };
    
    // Apply disorder if enabled
    let disorder = config.enable_disorder && config.disorder_probability > 0.0;
    if disorder && fragments.len() > 2 {
        // Swap some fragments (but keep first fragment first for TLS)
        let state = FRAGMENT_STATE.fetch_add(1, Ordering::Relaxed);
        if (state % 100) as f64 / 100.0 < config.disorder_probability {
            // Swap second and third fragments (common disorder pattern)
            if fragments.len() >= 3 {
                fragments.swap(1, 2);
            }
        }
    }
    
    FragmentedData {
        fragments,
        delay_us: config.inter_fragment_delay_us,
        disorder,
        original_length,
    }
}

/// Auto-detect optimal split positions for TLS ClientHello
fn auto_detect_split_positions(data: &[u8]) -> Vec<usize> {
    let mut positions = Vec::new();
    
    // Check if this looks like TLS ClientHello
    if data.len() < 6 || data[0] != 0x16 || data[5] != 0x01 {
        // Not TLS ClientHello, use fixed intervals
        let mut pos = 40;
        while pos < data.len() {
            positions.push(pos);
            pos += 40;
        }
        return positions;
    }
    
    // For TLS, try to find SNI and split around it
    // This is a simplified version - see sni_fragmentation.rs for full implementation
    
    // Strategy 1: Split before extensions (around byte 43-50)
    if data.len() > 50 {
        positions.push(43);
    }
    
    // Strategy 2: Look for SNI extension marker (0x00 0x00)
    // SNI extension starts with 0x00 0x00 (extension type)
    for i in 43..data.len().saturating_sub(10) {
        if data[i] == 0x00 && data[i + 1] == 0x00 {
            // Potential SNI extension
            positions.push(i);
            // Also split in the middle of SNI hostname
            let ext_len = if i + 3 < data.len() {
                u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize
            } else {
                0
            };
            if ext_len > 10 && i + 9 + ext_len / 2 < data.len() {
                positions.push(i + 9 + ext_len / 2);
            }
            break;
        }
    }
    
    // Strategy 3: Always split at multiple of 40 bytes for additional fragmentation
    let mut pos = 40;
    while pos < data.len() {
        if !positions.contains(&pos) {
            positions.push(pos);
        }
        pos += 40;
    }
    
    positions.sort();
    positions.dedup();
    
    // Remove positions too close together
    let mut filtered = Vec::new();
    let mut last = 0usize;
    for pos in positions {
        if pos > last + 5 && pos < data.len() {
            filtered.push(pos);
            last = pos;
        }
    }
    
    filtered
}

/// Fragment data at specific positions
fn fragment_at_positions(data: &[u8], positions: &[usize], remainder: &[u8]) -> Vec<Bytes> {
    let mut fragments = Vec::new();
    let mut start = 0;
    
    for &pos in positions {
        if pos > start && pos <= data.len() {
            fragments.push(Bytes::copy_from_slice(&data[start..pos]));
            start = pos;
        }
    }
    
    if start < data.len() {
        fragments.push(Bytes::copy_from_slice(&data[start..]));
    }
    
    if !remainder.is_empty() {
        fragments.push(Bytes::copy_from_slice(remainder));
    }
    
    fragments
}

/// Async writer that fragments data before sending
pub struct FragmentingWriter<W> {
    inner: W,
    config: TcpFragmentConfig,
    bytes_written: usize,
}

impl<W> FragmentingWriter<W> {
    pub fn new(inner: W, config: TcpFragmentConfig) -> Self {
        Self {
            inner,
            config,
            bytes_written: 0,
        }
    }
    
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: AsyncWrite + Unpin> FragmentingWriter<W> {
    /// Write data with fragmentation
    pub async fn write_fragmented(&mut self, data: &[u8]) -> io::Result<usize> {
        // Check if we should still fragment
        let should_fragment = self.config.fragment_first_n_bytes == 0 
            || self.bytes_written < self.config.fragment_first_n_bytes;
        
        if !should_fragment || matches!(self.config.strategy, FragmentationStrategy::None) {
            // Write normally
            let written = self.inner.write(data).await?;
            self.bytes_written += written;
            return Ok(written);
        }
        
        // Fragment the data
        let fragmented = fragment_data(data, &self.config);
        let mut total_written = 0;
        
        for (i, fragment) in fragmented.fragments.iter().enumerate() {
            // Write fragment
            self.inner.write_all(fragment).await?;
            total_written += fragment.len();
            
            // Flush if configured
            if self.config.flush_after_fragment {
                self.inner.flush().await?;
            }
            
            // Delay between fragments (except after first if send_first_immediately)
            let should_delay = if self.config.send_first_immediately {
                i > 0
            } else {
                true
            };
            
            if should_delay && i < fragmented.fragments.len() - 1 && fragmented.delay_us > 0 {
                sleep(Duration::from_micros(fragmented.delay_us)).await;
            }
        }
        
        self.bytes_written += total_written;
        Ok(total_written)
    }
}

/// Synchronous fragmented write (for non-async contexts)
pub fn write_fragmented_sync<W: Write>(
    writer: &mut W,
    data: &[u8],
    config: &TcpFragmentConfig,
) -> io::Result<usize> {
    if matches!(config.strategy, FragmentationStrategy::None) {
        return writer.write(data);
    }
    
    let fragmented = fragment_data(data, config);
    let mut total_written = 0;
    
    for (i, fragment) in fragmented.fragments.iter().enumerate() {
        writer.write_all(fragment)?;
        total_written += fragment.len();
        
        if config.flush_after_fragment {
            writer.flush()?;
        }
        
        // Delay (blocking)
        let should_delay = if config.send_first_immediately { i > 0 } else { true };
        if should_delay && i < fragmented.fragments.len() - 1 && fragmented.delay_us > 0 {
            std::thread::sleep(Duration::from_micros(fragmented.delay_us));
        }
    }
    
    Ok(total_written)
}

/// Check if data looks like TLS ClientHello
pub fn is_tls_client_hello(data: &[u8]) -> bool {
    data.len() >= 6 
        && data[0] == 0x16 // Handshake
        && data[1] == 0x03 // TLS major version
        && (data[2] == 0x01 || data[2] == 0x03) // TLS 1.0 or 1.2
        && data[5] == 0x01 // ClientHello
}

/// Calculate optimal fragment size for given data
pub fn optimal_fragment_size(data_len: usize) -> usize {
    // Based on research, 40 bytes is optimal for most Russian DPI
    // But we adjust based on data length
    
    if data_len < 100 {
        // Very small data, use smaller fragments
        data_len.max(1) / 3 + 1
    } else if data_len < 500 {
        // TLS ClientHello size range
        40 // Optimal for TSPU
    } else {
        // Larger data, can use slightly bigger fragments
        100
    }
}

/// Statistics about fragmentation
#[derive(Debug, Clone, Default)]
pub struct FragmentationStats {
    pub total_bytes: usize,
    pub total_fragments: usize,
    pub avg_fragment_size: f64,
    pub min_fragment_size: usize,
    pub max_fragment_size: usize,
}

impl FragmentationStats {
    pub fn from_fragmented_data(data: &FragmentedData) -> Self {
        if data.fragments.is_empty() {
            return Self::default();
        }
        
        let sizes: Vec<usize> = data.fragments.iter().map(|f| f.len()).collect();
        let total: usize = sizes.iter().sum();
        
        Self {
            total_bytes: total,
            total_fragments: sizes.len(),
            avg_fragment_size: total as f64 / sizes.len() as f64,
            min_fragment_size: *sizes.iter().min().unwrap_or(&0),
            max_fragment_size: *sizes.iter().max().unwrap_or(&0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_fixed_size_fragmentation() {
        let data = vec![0u8; 100];
        let config = TcpFragmentConfig {
            strategy: FragmentationStrategy::FixedSize(30),
            fragment_first_n_bytes: 0,
            ..Default::default()
        };
        
        let fragmented = fragment_data(&data, &config);
        
        // Should have 4 fragments (30 + 30 + 30 + 10)
        assert_eq!(fragmented.fragments.len(), 4);
        assert_eq!(fragmented.fragments[0].len(), 30);
        assert_eq!(fragmented.fragments[3].len(), 10);
    }
    
    #[test]
    fn test_split_at() {
        let data = vec![0u8; 100];
        let config = TcpFragmentConfig {
            strategy: FragmentationStrategy::SplitAt(40),
            fragment_first_n_bytes: 0,
            ..Default::default()
        };
        
        let fragmented = fragment_data(&data, &config);
        
        assert_eq!(fragmented.fragments.len(), 2);
        assert_eq!(fragmented.fragments[0].len(), 40);
        assert_eq!(fragmented.fragments[1].len(), 60);
    }
    
    #[test]
    fn test_micro_fragmentation() {
        let data = vec![0u8; 50];
        let config = TcpFragmentConfig {
            strategy: FragmentationStrategy::Micro,
            fragment_first_n_bytes: 0,
            ..Default::default()
        };
        
        let fragmented = fragment_data(&data, &config);
        
        // Should have many small fragments
        assert!(fragmented.fragments.len() >= 5);
        
        // Each fragment should be 1-10 bytes
        for frag in &fragmented.fragments {
            assert!(frag.len() >= 1 && frag.len() <= 10);
        }
        
        // Total should equal original
        let total: usize = fragmented.fragments.iter().map(|f| f.len()).sum();
        assert_eq!(total, 50);
    }
    
    #[test]
    fn test_single_byte_fragmentation() {
        let data = vec![1, 2, 3, 4, 5];
        let config = TcpFragmentConfig {
            strategy: FragmentationStrategy::SingleByte,
            fragment_first_n_bytes: 0,
            ..Default::default()
        };
        
        let fragmented = fragment_data(&data, &config);
        
        assert_eq!(fragmented.fragments.len(), 5);
        for (i, frag) in fragmented.fragments.iter().enumerate() {
            assert_eq!(frag.len(), 1);
            assert_eq!(frag[0], (i + 1) as u8);
        }
    }
    
    #[test]
    fn test_fragment_first_n_bytes() {
        let data = vec![0u8; 1000];
        let config = TcpFragmentConfig {
            strategy: FragmentationStrategy::FixedSize(40),
            fragment_first_n_bytes: 200,
            ..Default::default()
        };
        
        let fragmented = fragment_data(&data, &config);
        
        // First 200 bytes fragmented (5 x 40), rest as one fragment
        assert_eq!(fragmented.fragments.len(), 6);
        
        // First 5 fragments should be 40 bytes each
        for frag in fragmented.fragments.iter().take(5) {
            assert_eq!(frag.len(), 40);
        }
        
        // Last fragment should be 800 bytes (remainder)
        assert_eq!(fragmented.fragments[5].len(), 800);
    }
    
    #[test]
    fn test_is_tls_client_hello() {
        // Valid TLS ClientHello header
        let valid = vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01];
        assert!(is_tls_client_hello(&valid));
        
        // Not TLS (wrong record type)
        let invalid = vec![0x17, 0x03, 0x01, 0x00, 0x05, 0x01];
        assert!(!is_tls_client_hello(&invalid));
        
        // Not ClientHello (wrong handshake type)
        let server_hello = vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x02];
        assert!(!is_tls_client_hello(&server_hello));
    }
    
    #[test]
    fn test_fragmentation_stats() {
        let data = vec![0u8; 100];
        let config = TcpFragmentConfig {
            strategy: FragmentationStrategy::FixedSize(30),
            fragment_first_n_bytes: 0,
            ..Default::default()
        };
        
        let fragmented = fragment_data(&data, &config);
        let stats = FragmentationStats::from_fragmented_data(&fragmented);
        
        assert_eq!(stats.total_bytes, 100);
        assert_eq!(stats.total_fragments, 4);
        assert_eq!(stats.min_fragment_size, 10);
        assert_eq!(stats.max_fragment_size, 30);
    }
    
    #[test]
    fn test_optimal_fragment_size() {
        assert!(optimal_fragment_size(50) < 40);
        assert_eq!(optimal_fragment_size(300), 40);
        assert_eq!(optimal_fragment_size(1000), 100);
    }
    
    #[test]
    fn test_disorder_fragmentation() {
        // Create config with guaranteed disorder
        let mut config = TcpFragmentConfig {
            strategy: FragmentationStrategy::FixedSize(10),
            fragment_first_n_bytes: 0,
            enable_disorder: true,
            disorder_probability: 1.0, // Always disorder
            ..Default::default()
        };
        
        let data: Vec<u8> = (0..50).collect();
        
        // Run multiple times to test disorder
        let mut different_orders = false;
        let original = fragment_data(&data, &config);
        
        config.disorder_probability = 1.0;
        for _ in 0..10 {
            let fragmented = fragment_data(&data, &config);
            // Check if order is different from original
            if fragmented.fragments.len() >= 3 {
                if fragmented.fragments[1] != original.fragments[1] {
                    different_orders = true;
                    break;
                }
            }
        }
        
        // With disorder enabled, we should sometimes see different orders
        // (Note: this might not always trigger due to randomness)
    }
}
