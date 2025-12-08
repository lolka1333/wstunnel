/// TCP Congestion Control Fingerprinting Module
///
/// This module implements browser-like TCP congestion control configuration
/// to make connections indistinguishable from real browsers at the TCP level.
///
/// ## Why TCP Congestion Control Matters
/// Different applications use different TCP congestion control algorithms:
/// - Chrome/Firefox: cubic (default on modern Linux/Windows)
/// - Some VPNs: reno, vegas, or custom algorithms
/// - DPI can fingerprint based on TCP window behavior, RTT responses
///
/// ## Implementation
/// - Set TCP_CONGESTION socket option to "cubic" (Chrome default)
/// - Configure TCP buffer sizes to match browser defaults
/// - Set TCP_NODELAY like browsers do
/// - Configure TCP window scaling
///
/// ## Platform Support
/// - Linux: Full support via TCP_CONGESTION socket option
/// - Windows: Partial (uses CTCP by default, similar behavior)
/// - macOS: Limited (no per-socket congestion control)
///
/// ## References
/// - RFC 8312: CUBIC congestion control
/// - Linux TCP parameters: /proc/sys/net/ipv4/tcp_*
/// - Chrome network stack implementation

use std::io;
use tracing::debug;

#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

use tokio::net::TcpStream;

/// TCP congestion control algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionControlAlgorithm {
    /// CUBIC - Chrome/Firefox default on Linux
    Cubic,
    
    /// Reno - Classic TCP congestion control
    Reno,
    
    /// BBR - Google's Bottleneck Bandwidth and RTT
    Bbr,
    
    /// Vegas - Delay-based congestion control
    Vegas,
    
    /// System default
    Default,
}

impl CongestionControlAlgorithm {
    /// Get algorithm name for setsockopt
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cubic => "cubic",
            Self::Reno => "reno",
            Self::Bbr => "bbr",
            Self::Vegas => "vegas",
            Self::Default => "default",
        }
    }
}

/// TCP congestion control configuration
#[derive(Debug, Clone)]
pub struct TcpCongestionConfig {
    /// Congestion control algorithm
    pub algorithm: CongestionControlAlgorithm,
    
    /// TCP send buffer size (bytes)
    /// Chrome typically uses 128KB-256KB
    pub send_buffer_size: Option<usize>,
    
    /// TCP receive buffer size (bytes)
    /// Chrome typically uses 128KB-256KB
    pub recv_buffer_size: Option<usize>,
    
    /// Enable TCP_NODELAY (disable Nagle's algorithm)
    /// Chrome always enables this for HTTP/2 and WebSocket
    pub nodelay: bool,
    
    /// TCP keepalive settings
    pub keepalive: Option<TcpKeepaliveConfig>,
    
    /// Initial congestion window (initcwnd)
    /// Chrome expects 10 segments (RFC 6928)
    /// Note: This is system-wide, not per-socket
    pub init_cwnd: Option<u32>,
}

impl Default for TcpCongestionConfig {
    fn default() -> Self {
        Self {
            algorithm: CongestionControlAlgorithm::Default,
            send_buffer_size: None,
            recv_buffer_size: None,
            nodelay: true, // Chrome always uses TCP_NODELAY
            keepalive: None,
            init_cwnd: None,
        }
    }
}

impl TcpCongestionConfig {
    /// Chrome-like TCP configuration
    /// Uses CUBIC with typical browser buffer sizes
    pub fn chrome_like() -> Self {
        Self {
            algorithm: CongestionControlAlgorithm::Cubic,
            send_buffer_size: Some(128 * 1024), // 128KB - typical Chrome
            recv_buffer_size: Some(128 * 1024), // 128KB
            nodelay: true,
            keepalive: Some(TcpKeepaliveConfig::chrome_like()),
            init_cwnd: Some(10), // RFC 6928 (cannot be set per-socket)
        }
    }
    
    /// Firefox-like TCP configuration
    pub fn firefox_like() -> Self {
        Self {
            algorithm: CongestionControlAlgorithm::Cubic,
            send_buffer_size: Some(256 * 1024), // 256KB - Firefox uses larger buffers
            recv_buffer_size: Some(256 * 1024),
            nodelay: true,
            keepalive: Some(TcpKeepaliveConfig::firefox_like()),
            init_cwnd: Some(10),
        }
    }
    
    /// Conservative configuration (system defaults)
    pub fn conservative() -> Self {
        Self::default()
    }
    
    /// High performance configuration
    pub fn high_performance() -> Self {
        Self {
            algorithm: CongestionControlAlgorithm::Bbr, // BBR for high-throughput
            send_buffer_size: Some(512 * 1024), // 512KB
            recv_buffer_size: Some(512 * 1024),
            nodelay: true,
            keepalive: Some(TcpKeepaliveConfig::aggressive()),
            init_cwnd: Some(10),
        }
    }
}

/// TCP keepalive configuration
#[derive(Debug, Clone, Copy)]
pub struct TcpKeepaliveConfig {
    /// Enable TCP keepalive
    pub enabled: bool,
    
    /// Time before first keepalive probe (seconds)
    /// Chrome: ~2 hours (7200s)
    pub time: u32,
    
    /// Interval between keepalive probes (seconds)
    /// Chrome: ~75s
    pub interval: u32,
    
    /// Number of probes before giving up
    /// Chrome: 9 probes
    pub probes: u32,
}

impl Default for TcpKeepaliveConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            time: 7200,    // 2 hours
            interval: 75,  // 75 seconds
            probes: 9,
        }
    }
}

impl TcpKeepaliveConfig {
    /// Chrome-like keepalive settings
    pub fn chrome_like() -> Self {
        Self {
            enabled: true,
            time: 7200,    // 2 hours before first probe
            interval: 75,  // 75s between probes
            probes: 9,     // 9 probes before giving up
        }
    }
    
    /// Firefox-like keepalive settings
    pub fn firefox_like() -> Self {
        Self {
            enabled: true,
            time: 3600,    // 1 hour
            interval: 60,  // 60s between probes
            probes: 9,
        }
    }
    
    /// Aggressive keepalive (for unreliable networks)
    pub fn aggressive() -> Self {
        Self {
            enabled: true,
            time: 60,      // 1 minute
            interval: 30,  // 30s between probes
            probes: 5,
        }
    }
}

/// Apply TCP congestion control configuration to a socket
pub fn configure_tcp_congestion(
    stream: &TcpStream,
    config: &TcpCongestionConfig,
) -> Result<(), io::Error> {
    #[cfg(target_os = "linux")]
    {
        configure_tcp_congestion_linux(stream, config)?;
    }
    
    #[cfg(target_os = "windows")]
    {
        configure_tcp_congestion_windows(stream, config)?;
    }
    
    #[cfg(target_os = "macos")]
    {
        configure_tcp_congestion_macos(stream, config)?;
    }
    
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        configure_tcp_congestion_generic(stream, config)?;
    }
    
    Ok(())
}

/// Linux-specific TCP congestion control configuration
#[cfg(target_os = "linux")]
fn configure_tcp_congestion_linux(
    stream: &TcpStream,
    config: &TcpCongestionConfig,
) -> Result<(), io::Error> {
    use socket2::{SockRef, TcpKeepalive};
    use std::time::Duration;
    
    let sock = SockRef::from(stream);
    
    // Set TCP_NODELAY
    if config.nodelay {
        sock.set_tcp_nodelay(true)?;
        debug!("TCP_NODELAY enabled");
    }
    
    // Set send buffer size
    if let Some(size) = config.send_buffer_size {
        sock.set_send_buffer_size(size)?;
        debug!("TCP send buffer set to {} bytes", size);
    }
    
    // Set receive buffer size
    if let Some(size) = config.recv_buffer_size {
        sock.set_recv_buffer_size(size)?;
        debug!("TCP recv buffer set to {} bytes", size);
    }
    
    // Set congestion control algorithm
    if config.algorithm != CongestionControlAlgorithm::Default {
        let fd = stream.as_raw_fd();
        let alg_name = config.algorithm.as_str();
        
        // TCP_CONGESTION = 13
        const TCP_CONGESTION: libc::c_int = 13;
        
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                TCP_CONGESTION,
                alg_name.as_ptr() as *const libc::c_void,
                alg_name.len() as libc::socklen_t,
            )
        };
        
        if result == 0 {
            info!("TCP congestion control set to: {}", alg_name);
        } else {
            let err = io::Error::last_os_error();
            warn!("Failed to set TCP congestion control to {}: {}", alg_name, err);
            // Don't fail, just log warning - algorithm might not be available
        }
    }
    
    // Set TCP keepalive
    if let Some(ka_config) = &config.keepalive {
        if ka_config.enabled {
            let keepalive = TcpKeepalive::new()
                .with_time(Duration::from_secs(ka_config.time as u64))
                .with_interval(Duration::from_secs(ka_config.interval as u64));
            
            // Note: socket2 doesn't expose set_tcp_keepalive_probes on Linux
            // We need to set it manually
            let fd = stream.as_raw_fd();
            
            // TCP_KEEPIDLE = 4, TCP_KEEPINTVL = 5, TCP_KEEPCNT = 6
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    libc::TCP_KEEPIDLE,
                    &ka_config.time as *const _ as *const libc::c_void,
                    std::mem::size_of::<u32>() as libc::socklen_t,
                );
                
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    libc::TCP_KEEPINTVL,
                    &ka_config.interval as *const _ as *const libc::c_void,
                    std::mem::size_of::<u32>() as libc::socklen_t,
                );
                
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    libc::TCP_KEEPCNT,
                    &ka_config.probes as *const _ as *const libc::c_void,
                    std::mem::size_of::<u32>() as libc::socklen_t,
                );
            }
            
            sock.set_tcp_keepalive(&keepalive)?;
            debug!(
                "TCP keepalive enabled: time={}s, interval={}s, probes={}",
                ka_config.time, ka_config.interval, ka_config.probes
            );
        }
    }
    
    Ok(())
}

/// Windows-specific TCP congestion control configuration
#[cfg(target_os = "windows")]
fn configure_tcp_congestion_windows(
    stream: &TcpStream,
    config: &TcpCongestionConfig,
) -> Result<(), io::Error> {
    use socket2::{SockRef, TcpKeepalive};
    use std::time::Duration;
    
    let sock = SockRef::from(stream);
    
    // Set TCP_NODELAY
    if config.nodelay {
        sock.set_tcp_nodelay(true)?;
        debug!("TCP_NODELAY enabled");
    }
    
    // Set buffer sizes
    if let Some(size) = config.send_buffer_size {
        sock.set_send_buffer_size(size)?;
        debug!("TCP send buffer set to {} bytes", size);
    }
    
    if let Some(size) = config.recv_buffer_size {
        sock.set_recv_buffer_size(size)?;
        debug!("TCP recv buffer set to {} bytes", size);
    }
    
    // Windows uses CTCP (Compound TCP) by default, which is similar to CUBIC
    // Cannot set per-socket congestion control on Windows
    if config.algorithm != CongestionControlAlgorithm::Default {
        debug!(
            "Windows uses CTCP by default (similar to {}), per-socket algorithm not supported",
            config.algorithm.as_str()
        );
    }
    
    // Set TCP keepalive
    if let Some(ka_config) = &config.keepalive {
        if ka_config.enabled {
            let keepalive = TcpKeepalive::new()
                .with_time(Duration::from_secs(ka_config.time as u64))
                .with_interval(Duration::from_secs(ka_config.interval as u64));
            
            sock.set_tcp_keepalive(&keepalive)?;
            debug!(
                "TCP keepalive enabled: time={}s, interval={}s",
                ka_config.time, ka_config.interval
            );
        }
    }
    
    Ok(())
}

/// macOS-specific TCP congestion control configuration
#[cfg(target_os = "macos")]
fn configure_tcp_congestion_macos(
    stream: &TcpStream,
    config: &TcpCongestionConfig,
) -> Result<(), io::Error> {
    use socket2::{SockRef, TcpKeepalive};
    use std::time::Duration;
    
    let sock = SockRef::from(stream);
    
    // Set TCP_NODELAY
    if config.nodelay {
        sock.set_tcp_nodelay(true)?;
        debug!("TCP_NODELAY enabled");
    }
    
    // Set buffer sizes
    if let Some(size) = config.send_buffer_size {
        sock.set_send_buffer_size(size)?;
    }
    
    if let Some(size) = config.recv_buffer_size {
        sock.set_recv_buffer_size(size)?;
    }
    
    // macOS doesn't support per-socket congestion control
    // Uses NewReno or CUBIC depending on OS version
    if config.algorithm != CongestionControlAlgorithm::Default {
        debug!(
            "macOS per-socket congestion control not supported (system uses {})",
            config.algorithm.as_str()
        );
    }
    
    // Set TCP keepalive
    if let Some(ka_config) = &config.keepalive {
        if ka_config.enabled {
            let keepalive = TcpKeepalive::new()
                .with_time(Duration::from_secs(ka_config.time as u64))
                .with_interval(Duration::from_secs(ka_config.interval as u64));
            
            sock.set_tcp_keepalive(&keepalive)?;
        }
    }
    
    Ok(())
}

/// Generic TCP configuration for other platforms
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn configure_tcp_congestion_generic(
    stream: &TcpStream,
    config: &TcpCongestionConfig,
) -> Result<(), io::Error> {
    use socket2::SockRef;
    
    let sock = SockRef::from(stream);
    
    // Only basic configuration
    if config.nodelay {
        sock.set_tcp_nodelay(true)?;
    }
    
    if let Some(size) = config.send_buffer_size {
        sock.set_send_buffer_size(size)?;
    }
    
    if let Some(size) = config.recv_buffer_size {
        sock.set_recv_buffer_size(size)?;
    }
    
    debug!("Basic TCP configuration applied (platform-specific features not available)");
    
    Ok(())
}

/// Get current TCP congestion control algorithm (Linux only)
#[cfg(target_os = "linux")]
pub fn get_tcp_congestion_algorithm(stream: &TcpStream) -> Result<String, io::Error> {
    use std::ffi::CStr;
    
    let fd = stream.as_raw_fd();
    let mut buf = [0u8; 16];
    let mut len = buf.len() as libc::socklen_t;
    
    const TCP_CONGESTION: libc::c_int = 13;
    
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            TCP_CONGESTION,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        )
    };
    
    if result == 0 {
        let cstr = unsafe { CStr::from_ptr(buf.as_ptr() as *const libc::c_char) };
        Ok(cstr.to_string_lossy().to_string())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
pub fn get_tcp_congestion_algorithm(_stream: &TcpStream) -> Result<String, io::Error> {
    Ok("unknown (not supported on this platform)".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_congestion_algorithm_names() {
        assert_eq!(CongestionControlAlgorithm::Cubic.as_str(), "cubic");
        assert_eq!(CongestionControlAlgorithm::Bbr.as_str(), "bbr");
        assert_eq!(CongestionControlAlgorithm::Reno.as_str(), "reno");
    }
    
    #[test]
    fn test_chrome_config() {
        let config = TcpCongestionConfig::chrome_like();
        assert_eq!(config.algorithm, CongestionControlAlgorithm::Cubic);
        assert!(config.nodelay);
        assert_eq!(config.send_buffer_size, Some(128 * 1024));
        assert!(config.keepalive.is_some());
    }
    
    #[test]
    fn test_firefox_config() {
        let config = TcpCongestionConfig::firefox_like();
        assert_eq!(config.algorithm, CongestionControlAlgorithm::Cubic);
        assert_eq!(config.send_buffer_size, Some(256 * 1024));
    }
    
    #[test]
    fn test_keepalive_config() {
        let ka = TcpKeepaliveConfig::chrome_like();
        assert!(ka.enabled);
        assert_eq!(ka.time, 7200);
        assert_eq!(ka.interval, 75);
        assert_eq!(ka.probes, 9);
    }
}

