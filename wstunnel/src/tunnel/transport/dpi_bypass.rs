/// DPI Bypass Integration Module
///
/// This module integrates all DPI evasion techniques into wstunnel.
/// It provides wrappers and utilities that can be used in the main code.
///
/// ## Features
/// - TCP fragmentation of TLS ClientHello
/// - SNI obfuscation
/// - Adversarial padding for WebSocket frames
/// - Traffic profile mimicking

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use super::tcp_fragmentation::{TcpFragmentConfig, FragmentationStrategy, fragment_data};
use super::adversarial_ml::{AdversarialConfig, generate_crypto_padding};

/// DPI bypass configuration
#[derive(Debug, Clone)]
pub struct DpiBypassConfig {
    /// Enable TCP fragmentation of TLS ClientHello
    pub tcp_fragmentation: bool,
    
    /// Fragment size for TCP fragmentation
    pub fragment_size: usize,
    
    /// Delay between fragments (microseconds)
    pub inter_fragment_delay_us: u64,
    
    /// Enable SNI case randomization
    pub sni_case_randomization: bool,
    
    /// Enable adversarial padding for WebSocket
    pub adversarial_padding: bool,
    
    /// Only fragment first N bytes (TLS ClientHello is ~500 bytes)
    pub fragment_first_bytes: usize,
}

impl Default for DpiBypassConfig {
    fn default() -> Self {
        Self {
            tcp_fragmentation: false,
            fragment_size: 40,
            inter_fragment_delay_us: 100,
            sni_case_randomization: false,
            adversarial_padding: false,
            fragment_first_bytes: 600,
        }
    }
}

impl DpiBypassConfig {
    /// Disabled - no DPI bypass
    pub fn disabled() -> Self {
        Self::default()
    }
    
    /// Configuration optimized for Russian TSPU
    pub fn russia() -> Self {
        Self {
            tcp_fragmentation: true,
            fragment_size: 40,
            inter_fragment_delay_us: 100,
            sni_case_randomization: true,
            adversarial_padding: true,
            fragment_first_bytes: 600,
        }
    }
    
    /// Aggressive mode for maximum evasion
    pub fn aggressive() -> Self {
        Self {
            tcp_fragmentation: true,
            fragment_size: 2,
            inter_fragment_delay_us: 200,
            sni_case_randomization: true,
            adversarial_padding: true,
            fragment_first_bytes: 600,
        }
    }
    
    /// Convert to TcpFragmentConfig
    pub fn to_fragment_config(&self) -> TcpFragmentConfig {
        TcpFragmentConfig {
            strategy: if self.tcp_fragmentation {
                FragmentationStrategy::FixedSize(self.fragment_size)
            } else {
                FragmentationStrategy::None
            },
            inter_fragment_delay_us: self.inter_fragment_delay_us,
            send_first_immediately: true,
            use_tcp_nodelay: true,
            flush_after_fragment: true,
            fragment_first_n_bytes: self.fragment_first_bytes,
            tls_split_positions: vec![],
            enable_disorder: false,
            disorder_probability: 0.0,
        }
    }
}

/// Global DPI bypass configuration (set at startup)
static DPI_BYPASS_ENABLED: AtomicBool = AtomicBool::new(false);
static DPI_FRAGMENT_SIZE: AtomicUsize = AtomicUsize::new(40);

/// Enable DPI bypass globally
pub fn enable_dpi_bypass(config: &DpiBypassConfig) {
    DPI_BYPASS_ENABLED.store(config.tcp_fragmentation, Ordering::Relaxed);
    DPI_FRAGMENT_SIZE.store(config.fragment_size, Ordering::Relaxed);
}

/// Check if DPI bypass is enabled
pub fn is_dpi_bypass_enabled() -> bool {
    DPI_BYPASS_ENABLED.load(Ordering::Relaxed)
}

/// TCP stream wrapper that fragments the first bytes (TLS ClientHello)
/// 
/// This is critical for bypassing Russian DPI which inspects TLS ClientHello
/// to extract SNI and block connections.
pub struct FragmentingTcpStream {
    inner: TcpStream,
    config: TcpFragmentConfig,
    bytes_written: usize,
}

impl FragmentingTcpStream {
    /// Create new fragmenting stream
    pub fn new(stream: TcpStream, config: TcpFragmentConfig) -> Self {
        Self {
            inner: stream,
            config,
            bytes_written: 0,
        }
    }
    
    /// Create with default Russia-optimized config
    pub fn with_russia_config(stream: TcpStream) -> Self {
        Self::new(stream, TcpFragmentConfig::russia_tspu())
    }
    
    /// Get reference to inner stream
    pub fn get_ref(&self) -> &TcpStream {
        &self.inner
    }
    
    /// Get mutable reference to inner stream
    pub fn get_mut(&mut self) -> &mut TcpStream {
        &mut self.inner
    }
    
    /// Unwrap into inner stream
    pub fn into_inner(self) -> TcpStream {
        self.inner
    }
    
    /// Check if we should still fragment
    fn should_fragment(&self) -> bool {
        self.config.fragment_first_n_bytes == 0 
            || self.bytes_written < self.config.fragment_first_n_bytes
    }
}

impl AsyncRead for FragmentingTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for FragmentingTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // If we've already written enough bytes, pass through directly
        if !self.should_fragment() {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }
        
        // Calculate how much of this write should be fragmented
        let remaining_to_fragment = self.config.fragment_first_n_bytes
            .saturating_sub(self.bytes_written);
        let fragment_len = buf.len().min(remaining_to_fragment);
        
        if fragment_len == 0 {
            // Nothing to fragment, write directly
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }
        
        // Fragment the data
        let to_fragment = &buf[..fragment_len];
        let fragmented = fragment_data(to_fragment, &self.config);
        
        // Write first fragment (or all if single fragment)
        if fragmented.fragments.len() == 1 {
            let result = Pin::new(&mut self.inner).poll_write(cx, &fragmented.fragments[0]);
            if let Poll::Ready(Ok(n)) = &result {
                self.as_mut().get_mut().bytes_written += n;
            }
            return result;
        }
        
        // Multiple fragments - write them with flushes
        // Note: In async context we can't easily add delays between fragments
        // But the flush between fragments helps ensure separate TCP segments
        let mut total_written = 0;
        for fragment in &fragmented.fragments {
            match Pin::new(&mut self.inner).poll_write(cx, fragment) {
                Poll::Ready(Ok(n)) => {
                    total_written += n;
                    // Try to flush to ensure separate TCP segment
                    let _ = Pin::new(&mut self.inner).poll_flush(cx);
                }
                Poll::Ready(Err(e)) => {
                    if total_written > 0 {
                        self.as_mut().get_mut().bytes_written += total_written;
                        return Poll::Ready(Ok(total_written));
                    }
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    if total_written > 0 {
                        self.as_mut().get_mut().bytes_written += total_written;
                        return Poll::Ready(Ok(total_written));
                    }
                    return Poll::Pending;
                }
            }
        }
        
        self.as_mut().get_mut().bytes_written += total_written;
        Poll::Ready(Ok(buf.len()))
    }
    
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Apply SNI case randomization to hostname
pub fn randomize_sni_case(hostname: &str) -> String {
    use super::sni_fragmentation::randomize_sni_case;
    randomize_sni_case(hostname)
}

/// Generate padding for WebSocket frame
pub fn generate_ws_padding(original_size: usize, config: &AdversarialConfig) -> Vec<u8> {
    if !config.enable_padding {
        return vec![];
    }
    
    // Determine padding size based on original size
    let padding_size = if original_size < 500 {
        // Small packets get more padding to mask size
        1200usize.saturating_sub(original_size) + (original_size % 100)
    } else if original_size < 1400 {
        // Medium packets get moderate padding
        1500usize.saturating_sub(original_size)
    } else {
        // Large packets don't need much padding
        0
    };
    
    if padding_size == 0 {
        return vec![];
    }
    
    // Generate crypto-quality padding
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    
    generate_crypto_padding(padding_size, seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_dpi_config_defaults() {
        let config = DpiBypassConfig::default();
        assert!(!config.tcp_fragmentation);
        assert_eq!(config.fragment_size, 40);
    }
    
    #[test]
    fn test_russia_config() {
        let config = DpiBypassConfig::russia();
        assert!(config.tcp_fragmentation);
        assert!(config.sni_case_randomization);
        assert!(config.adversarial_padding);
    }
    
    #[test]
    fn test_sni_randomization() {
        let original = "www.example.com";
        let randomized = randomize_sni_case(original);
        
        assert_eq!(randomized.len(), original.len());
        assert_eq!(randomized.to_lowercase(), original.to_lowercase());
    }
    
    #[test]
    fn test_padding_generation() {
        let config = AdversarialConfig {
            enable_padding: true,
            ..Default::default()
        };
        
        // Small packet should get padding
        let padding = generate_ws_padding(200, &config);
        assert!(!padding.is_empty());
        
        // Large packet should get less/no padding
        let padding_large = generate_ws_padding(1500, &config);
        assert!(padding_large.len() < padding.len());
    }
}
