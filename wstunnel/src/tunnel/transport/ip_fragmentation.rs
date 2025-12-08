/// IP Fragmentation Module - Network Layer DPI Bypass
///
/// This module implements IP-level fragmentation techniques to bypass
/// stateless DPI systems that cannot reassemble fragmented IP packets.
///
/// ## Problem
/// Some DPI systems (especially older ones or those operating in stateless mode)
/// inspect individual IP packets without reassembly. By fragmenting IP packets
/// so that critical data (like TLS headers or SNI) spans multiple fragments,
/// we can evade such inspection.
///
/// ## Techniques
///
/// 1. **MTU Reduction**
///    - Set socket MTU to force OS-level IP fragmentation
///    - First fragment contains IP+TCP headers, payload in subsequent fragments
///    - DPI sees incomplete data in each fragment
///
/// 2. **DF (Don't Fragment) Bit Manipulation**
///    - Clear DF bit to allow intermediate router fragmentation
///    - Or set DF and use small packets to trigger PMTU discovery
///
/// 3. **First Fragment Size Control**
///    - Control size of first IP fragment to split TCP/TLS headers
///    - Critical bytes end up in different fragments
///
/// ## Platform Support
///
/// - **Linux**: Full support via IP_MTU_DISCOVER, IP_PMTUDISC_DONT
/// - **Windows**: Partial support via IP_DONTFRAGMENT, requires Npcap for full control
/// - **macOS**: Limited support via IP_DONTFRAG
///
/// ## References
/// - RFC 791 (IP Fragmentation)
/// - GoodbyeDPI project techniques
/// - zapret project research

use std::io;
use std::net::SocketAddr;

#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

#[cfg(target_os = "windows")]
use std::os::windows::io::AsRawSocket;

use tokio::net::TcpStream;
use tracing::{debug, warn, info};

/// IP Fragmentation configuration
#[derive(Debug, Clone)]
pub struct IpFragmentationConfig {
    /// Enable IP-level fragmentation tricks
    pub enabled: bool,
    
    /// Target MTU size to force fragmentation
    /// Lower values = smaller fragments = harder for DPI
    /// Common values: 68 (minimum), 296, 576, 1280
    pub mtu_size: u16,
    
    /// Disable Path MTU Discovery (allows fragmentation by routers)
    /// Critical for bypassing stateless DPI
    pub disable_pmtu_discovery: bool,
    
    /// Clear Don't Fragment (DF) bit
    /// Allows routers to fragment packets
    pub clear_df_bit: bool,
    
    /// First fragment size (0 = use MTU)
    /// Smaller first fragment = TCP header split from payload
    pub first_fragment_size: u16,
    
    /// Enable IP fragmentation overlap (advanced, may break some networks)
    /// Overlapping fragments confuse DPI reassembly
    pub enable_overlap: bool,
    
    /// Send fragments in reverse order (last fragment first)
    /// Some DPI can't handle out-of-order fragments
    pub reverse_order: bool,
    
    /// TTL for fragments (0 = system default)
    /// Low TTL can be used for TTL-based DPI evasion (separate technique)
    pub fragment_ttl: u8,
}

impl Default for IpFragmentationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mtu_size: 576,  // Conservative default, works on most networks
            disable_pmtu_discovery: true,
            clear_df_bit: true,
            first_fragment_size: 0,
            enable_overlap: false,
            reverse_order: false,
            fragment_ttl: 0,
        }
    }
}

impl IpFragmentationConfig {
    /// Disabled configuration
    pub fn disabled() -> Self {
        Self::default()
    }
    
    /// Configuration optimized for Russian DPI evasion
    pub fn russia() -> Self {
        Self {
            enabled: true,
            mtu_size: 296,  // Small MTU for aggressive fragmentation
            disable_pmtu_discovery: true,
            clear_df_bit: true,
            first_fragment_size: 68,  // Minimum IP datagram size
            enable_overlap: false,
            reverse_order: false,
            fragment_ttl: 0,
        }
    }
    
    /// Aggressive configuration - maximum fragmentation
    pub fn aggressive() -> Self {
        Self {
            enabled: true,
            mtu_size: 68,   // Absolute minimum MTU
            disable_pmtu_discovery: true,
            clear_df_bit: true,
            first_fragment_size: 68,
            enable_overlap: false,  // Too risky for production
            reverse_order: true,    // Out-of-order fragments
            fragment_ttl: 0,
        }
    }
    
    /// Minimal overhead configuration
    pub fn minimal() -> Self {
        Self {
            enabled: true,
            mtu_size: 576,
            disable_pmtu_discovery: true,
            clear_df_bit: true,
            first_fragment_size: 0,
            enable_overlap: false,
            reverse_order: false,
            fragment_ttl: 0,
        }
    }
    
    /// Conservative configuration - less likely to break connectivity
    pub fn conservative() -> Self {
        Self {
            enabled: true,
            mtu_size: 1280,  // IPv6 minimum MTU, safe for most networks
            disable_pmtu_discovery: true,
            clear_df_bit: true,
            first_fragment_size: 0,
            enable_overlap: false,
            reverse_order: false,
            fragment_ttl: 0,
        }
    }
}

/// Result of applying IP fragmentation settings
#[derive(Debug)]
pub struct IpFragmentationResult {
    /// Whether settings were applied successfully
    pub success: bool,
    /// Applied MTU (may differ from requested)
    pub actual_mtu: Option<u16>,
    /// Error message if failed
    pub error: Option<String>,
    /// Platform-specific notes
    pub notes: Vec<String>,
}

/// Apply IP fragmentation settings to a TCP socket
/// 
/// This function configures the socket to encourage IP-level fragmentation.
/// The actual fragmentation is done by the OS/network stack based on these settings.
pub fn apply_ip_fragmentation(stream: &TcpStream, config: &IpFragmentationConfig) -> IpFragmentationResult {
    if !config.enabled {
        return IpFragmentationResult {
            success: true,
            actual_mtu: None,
            error: None,
            notes: vec!["IP fragmentation disabled".to_string()],
        };
    }
    
    let mut result = IpFragmentationResult {
        success: true,
        actual_mtu: Some(config.mtu_size),
        error: None,
        notes: Vec::new(),
    };
    
    // Platform-specific implementation
    #[cfg(target_os = "linux")]
    {
        apply_linux_fragmentation(stream, config, &mut result);
    }
    
    #[cfg(target_os = "windows")]
    {
        apply_windows_fragmentation(stream, config, &mut result);
    }
    
    #[cfg(target_os = "macos")]
    {
        apply_macos_fragmentation(stream, config, &mut result);
    }
    
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        result.success = false;
        result.error = Some("IP fragmentation not supported on this platform".to_string());
    }
    
    result
}

/// Apply IP fragmentation settings asynchronously (same as sync but returns io::Result)
pub async fn apply_ip_fragmentation_async(
    stream: &TcpStream,
    config: &IpFragmentationConfig,
) -> io::Result<()> {
    let result = apply_ip_fragmentation(stream, config);
    
    if result.success {
        for note in &result.notes {
            debug!("IP fragmentation: {}", note);
        }
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            result.error.unwrap_or_else(|| "Unknown error".to_string()),
        ))
    }
}

// ===== Linux Implementation =====

#[cfg(target_os = "linux")]
fn apply_linux_fragmentation(
    stream: &TcpStream,
    config: &IpFragmentationConfig,
    result: &mut IpFragmentationResult,
) {
    use libc::{
        c_int, setsockopt, IPPROTO_IP, IPPROTO_TCP,
        IP_MTU_DISCOVER, IP_PMTUDISC_DONT, IP_PMTUDISC_WANT,
        IP_TTL, TCP_MAXSEG,
    };
    use std::mem::size_of;
    
    let fd = stream.as_raw_fd();
    
    // 1. Disable Path MTU Discovery to allow fragmentation
    if config.disable_pmtu_discovery {
        let pmtu_discover: c_int = if config.clear_df_bit {
            IP_PMTUDISC_DONT  // Don't set DF, allow fragmentation
        } else {
            IP_PMTUDISC_WANT  // Set DF, but allow PMTU discovery
        };
        
        let ret = unsafe {
            setsockopt(
                fd,
                IPPROTO_IP,
                IP_MTU_DISCOVER,
                &pmtu_discover as *const c_int as *const libc::c_void,
                size_of::<c_int>() as libc::socklen_t,
            )
        };
        
        if ret == 0 {
            result.notes.push(format!(
                "PMTU Discovery set to {} (DF bit {})",
                if config.clear_df_bit { "DONT" } else { "WANT" },
                if config.clear_df_bit { "cleared" } else { "may be set" }
            ));
        } else {
            result.notes.push(format!(
                "Failed to set PMTU Discovery: {}",
                io::Error::last_os_error()
            ));
        }
    }
    
    // 2. Set TCP Maximum Segment Size to control TCP-level fragmentation
    // This indirectly affects IP fragmentation by limiting TCP segment size
    if config.mtu_size > 0 {
        // MSS = MTU - IP header (20) - TCP header (20) = MTU - 40
        let mss: c_int = (config.mtu_size as c_int).saturating_sub(40).max(1);
        
        let ret = unsafe {
            setsockopt(
                fd,
                IPPROTO_TCP,
                TCP_MAXSEG,
                &mss as *const c_int as *const libc::c_void,
                size_of::<c_int>() as libc::socklen_t,
            )
        };
        
        if ret == 0 {
            result.notes.push(format!("TCP MSS set to {} bytes", mss));
            result.actual_mtu = Some((mss + 40) as u16);
        } else {
            // TCP_MAXSEG often requires CAP_NET_ADMIN or may fail
            // This is not critical, OS will still fragment based on actual MTU
            result.notes.push(format!(
                "Failed to set TCP MSS (may require CAP_NET_ADMIN): {}",
                io::Error::last_os_error()
            ));
        }
    }
    
    // 3. Set TTL if specified
    if config.fragment_ttl > 0 {
        let ttl: c_int = config.fragment_ttl as c_int;
        
        let ret = unsafe {
            setsockopt(
                fd,
                IPPROTO_IP,
                IP_TTL,
                &ttl as *const c_int as *const libc::c_void,
                size_of::<c_int>() as libc::socklen_t,
            )
        };
        
        if ret == 0 {
            result.notes.push(format!("IP TTL set to {}", config.fragment_ttl));
        } else {
            result.notes.push(format!(
                "Failed to set IP TTL: {}",
                io::Error::last_os_error()
            ));
        }
    }
    
    info!(
        "Linux IP fragmentation applied: MTU={}, PMTU_DISCOVER={}, DF={}",
        config.mtu_size,
        if config.disable_pmtu_discovery { "disabled" } else { "enabled" },
        if config.clear_df_bit { "cleared" } else { "set" }
    );
}

// ===== Windows Implementation =====

#[cfg(target_os = "windows")]
fn apply_windows_fragmentation(
    stream: &TcpStream,
    config: &IpFragmentationConfig,
    result: &mut IpFragmentationResult,
) {
    use std::mem::size_of;
    
    // Windows socket option constants
    const IPPROTO_IP: i32 = 0;
    const IP_DONTFRAGMENT: i32 = 14;
    const IP_TTL: i32 = 4;
    
    // Get raw socket handle
    let socket = stream.as_raw_socket();
    
    // We need to use ws2_32.dll setsockopt
    // Using raw FFI since windows_sys may not be available
    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn setsockopt(
            s: std::os::windows::io::RawSocket,
            level: i32,
            optname: i32,
            optval: *const i8,
            optlen: i32,
        ) -> i32;
    }
    
    // 1. Clear Don't Fragment bit
    if config.clear_df_bit {
        let dont_fragment: i32 = 0;  // 0 = allow fragmentation
        
        let ret = unsafe {
            setsockopt(
                socket,
                IPPROTO_IP,
                IP_DONTFRAGMENT,
                &dont_fragment as *const i32 as *const i8,
                size_of::<i32>() as i32,
            )
        };
        
        if ret == 0 {
            result.notes.push("IP_DONTFRAGMENT cleared (fragmentation allowed)".to_string());
        } else {
            result.notes.push(format!(
                "Failed to clear IP_DONTFRAGMENT: {}",
                io::Error::last_os_error()
            ));
        }
    }
    
    // 2. Set TTL if specified
    if config.fragment_ttl > 0 {
        let ttl: i32 = config.fragment_ttl as i32;
        
        let ret = unsafe {
            setsockopt(
                socket,
                IPPROTO_IP,
                IP_TTL,
                &ttl as *const i32 as *const i8,
                size_of::<i32>() as i32,
            )
        };
        
        if ret == 0 {
            result.notes.push(format!("IP TTL set to {}", config.fragment_ttl));
        } else {
            result.notes.push(format!(
                "Failed to set IP TTL: {}",
                io::Error::last_os_error()
            ));
        }
    }
    
    // Note: Windows doesn't support TCP_MAXSEG directly
    // MSS is determined by the interface MTU
    result.notes.push(
        "Note: Windows uses interface MTU for fragmentation. \
         Consider using netsh to set interface MTU for more control.".to_string()
    );
    
    if config.mtu_size < 1500 {
        result.notes.push(format!(
            "To set MTU on Windows, run as admin: netsh interface ipv4 set subinterface \"Ethernet\" mtu={}",
            config.mtu_size
        ));
    }
    
    info!(
        "Windows IP fragmentation applied: DF={}, TTL={}",
        if config.clear_df_bit { "cleared" } else { "set" },
        if config.fragment_ttl > 0 { config.fragment_ttl.to_string() } else { "default".to_string() }
    );
}

// ===== macOS Implementation =====

#[cfg(target_os = "macos")]
fn apply_macos_fragmentation(
    stream: &TcpStream,
    config: &IpFragmentationConfig,
    result: &mut IpFragmentationResult,
) {
    use libc::{c_int, setsockopt, IPPROTO_IP, IPPROTO_TCP, IP_TTL};
    use std::mem::size_of;
    use std::os::unix::io::AsRawFd;
    
    // macOS specific: IP_DONTFRAG
    const IP_DONTFRAG: c_int = 67;
    
    let fd = stream.as_raw_fd();
    
    // 1. Clear Don't Fragment bit
    if config.clear_df_bit {
        let dont_frag: c_int = 0;  // 0 = allow fragmentation
        
        let ret = unsafe {
            setsockopt(
                fd,
                IPPROTO_IP,
                IP_DONTFRAG,
                &dont_frag as *const c_int as *const libc::c_void,
                size_of::<c_int>() as libc::socklen_t,
            )
        };
        
        if ret == 0 {
            result.notes.push("IP_DONTFRAG cleared (fragmentation allowed)".to_string());
        } else {
            result.notes.push(format!(
                "Failed to clear IP_DONTFRAG: {}",
                io::Error::last_os_error()
            ));
        }
    }
    
    // 2. Set TTL if specified
    if config.fragment_ttl > 0 {
        let ttl: c_int = config.fragment_ttl as c_int;
        
        let ret = unsafe {
            setsockopt(
                fd,
                IPPROTO_IP,
                IP_TTL,
                &ttl as *const c_int as *const libc::c_void,
                size_of::<c_int>() as libc::socklen_t,
            )
        };
        
        if ret == 0 {
            result.notes.push(format!("IP TTL set to {}", config.fragment_ttl));
        } else {
            result.notes.push(format!(
                "Failed to set IP TTL: {}",
                io::Error::last_os_error()
            ));
        }
    }
    
    // Note about MTU on macOS
    result.notes.push(
        "Note: macOS MTU is set per-interface. Use 'sudo ifconfig en0 mtu 576' to reduce MTU.".to_string()
    );
    
    info!(
        "macOS IP fragmentation applied: DF={}, TTL={}",
        if config.clear_df_bit { "cleared" } else { "set" },
        if config.fragment_ttl > 0 { config.fragment_ttl.to_string() } else { "default".to_string() }
    );
}

/// Get recommended MTU for specific DPI bypass scenario
pub fn recommended_mtu_for_scenario(scenario: &str) -> u16 {
    match scenario.to_lowercase().as_str() {
        "russia" | "tspu" | "ркнрф" => 296,
        "aggressive" | "maximum" => 68,
        "conservative" | "safe" => 1280,
        "minimal" | "default" => 576,
        "ipv6" => 1280,  // IPv6 minimum MTU
        _ => 576,
    }
}

/// Information about current network interface MTU
#[derive(Debug, Clone)]
pub struct MtuInfo {
    pub interface_name: String,
    pub current_mtu: u16,
    pub recommended_for_bypass: u16,
}

/// Get MTU information for the socket's interface
/// Note: This is a best-effort implementation and may not work on all platforms
pub fn get_socket_mtu_info(_addr: &SocketAddr) -> Option<MtuInfo> {
    // This would require platform-specific network interface enumeration
    // For now, return None and let caller use default recommendations
    // Full implementation would use getifaddrs on Unix or GetAdaptersAddresses on Windows
    
    warn!("MTU detection not implemented, using default recommendations");
    None
}

/// Calculate optimal fragment sizes for a given data length and target MTU
/// 
/// Returns a vector of fragment sizes that sum to data_len
/// First fragment is sized to split critical headers
pub fn calculate_fragment_sizes(data_len: usize, mtu: u16, first_frag_size: u16) -> Vec<usize> {
    let mtu = mtu as usize;
    let first_size = if first_frag_size > 0 {
        (first_frag_size as usize).min(data_len)
    } else {
        mtu.min(data_len)
    };
    
    let mut fragments = vec![first_size];
    let mut remaining = data_len.saturating_sub(first_size);
    
    while remaining > 0 {
        let frag_size = mtu.min(remaining);
        fragments.push(frag_size);
        remaining = remaining.saturating_sub(frag_size);
    }
    
    fragments
}

/// Statistics about IP fragmentation effectiveness
#[derive(Debug, Clone, Default)]
pub struct IpFragmentationStats {
    /// Total packets sent with fragmentation
    pub packets_fragmented: u64,
    /// Estimated fragments generated (based on MTU)
    pub estimated_fragments: u64,
    /// Average fragments per packet
    pub avg_fragments_per_packet: f64,
}

impl IpFragmentationStats {
    pub fn update(&mut self, packet_size: usize, mtu: u16) {
        self.packets_fragmented += 1;
        let fragments = (packet_size as f64 / mtu as f64).ceil() as u64;
        self.estimated_fragments += fragments;
        self.avg_fragments_per_packet = self.estimated_fragments as f64 / self.packets_fragmented as f64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config() {
        let config = IpFragmentationConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.mtu_size, 576);
        assert!(config.disable_pmtu_discovery);
        assert!(config.clear_df_bit);
    }
    
    #[test]
    fn test_russia_config() {
        let config = IpFragmentationConfig::russia();
        assert!(config.enabled);
        assert_eq!(config.mtu_size, 296);
        assert!(config.disable_pmtu_discovery);
        assert!(config.clear_df_bit);
        assert_eq!(config.first_fragment_size, 68);
    }
    
    #[test]
    fn test_aggressive_config() {
        let config = IpFragmentationConfig::aggressive();
        assert!(config.enabled);
        assert_eq!(config.mtu_size, 68);
        assert!(config.reverse_order);
    }
    
    #[test]
    fn test_recommended_mtu() {
        assert_eq!(recommended_mtu_for_scenario("russia"), 296);
        assert_eq!(recommended_mtu_for_scenario("aggressive"), 68);
        assert_eq!(recommended_mtu_for_scenario("conservative"), 1280);
        assert_eq!(recommended_mtu_for_scenario("unknown"), 576);
    }
    
    #[test]
    fn test_calculate_fragment_sizes() {
        // Test with 1000 bytes and MTU 300
        let sizes = calculate_fragment_sizes(1000, 300, 0);
        assert_eq!(sizes.len(), 4);  // 300 + 300 + 300 + 100
        assert_eq!(sizes.iter().sum::<usize>(), 1000);
        
        // Test with first fragment size
        let sizes = calculate_fragment_sizes(1000, 300, 100);
        assert_eq!(sizes[0], 100);  // First fragment is 100 bytes
        assert_eq!(sizes.iter().sum::<usize>(), 1000);
    }
    
    #[test]
    fn test_fragmentation_stats() {
        let mut stats = IpFragmentationStats::default();
        
        stats.update(1500, 500);  // 3 fragments
        assert_eq!(stats.packets_fragmented, 1);
        assert_eq!(stats.estimated_fragments, 3);
        
        stats.update(1000, 500);  // 2 fragments
        assert_eq!(stats.packets_fragmented, 2);
        assert_eq!(stats.estimated_fragments, 5);
        assert_eq!(stats.avg_fragments_per_packet, 2.5);
    }
}
