/// PCAP-based Traffic Learning Module
///
/// This module analyzes real packet captures (PCAP files) to extract statistical
/// patterns and apply them to wstunnel traffic for maximum stealth.
///
/// Extracts:
/// - Packet size distribution
/// - Inter-arrival time (IAT) patterns
/// - Burst patterns
/// - Frame size preferences
///
/// Usage:
/// ```bash
/// # Capture real Chrome WebSocket traffic:
/// tcpdump -i any 'host example.com and port 443' -w chrome-ws.pcap
///
/// # Build wstunnel with PCAP learning:
/// cargo build --release --features pcap-learning
///
/// # Use learned profile:
/// wstunnel client --traffic-profile chrome-ws.pcap -L ... wss://server.com
/// ```

#[cfg(feature = "pcap-learning")]
use pcap_file::pcap::PcapReader;
#[cfg(feature = "pcap-learning")]
use std::fs::File;
#[cfg(feature = "pcap-learning")]
use std::path::Path;

/// Traffic profile learned from PCAP analysis
#[derive(Debug, Clone)]
pub struct TrafficProfile {
    /// Packet size distribution (histogram)
    /// Index = size bucket, Value = frequency
    pub packet_size_distribution: Vec<(usize, f64)>,
    
    /// Inter-arrival time distribution (milliseconds)
    /// Index = IAT bucket, Value = frequency
    pub iat_distribution: Vec<(u64, f64)>,
    
    /// Average packet size
    pub avg_packet_size: usize,
    
    /// Standard deviation of packet sizes
    pub packet_size_stddev: f64,
    
    /// Average inter-arrival time (ms)
    pub avg_iat_ms: f64,
    
    /// IAT standard deviation
    pub iat_stddev: f64,
    
    /// Burst patterns (number of packets sent in quick succession)
    pub burst_sizes: Vec<usize>,
    
    /// Profile name
    pub name: String,
}

impl Default for TrafficProfile {
    fn default() -> Self {
        // Default profile: Generic browser WebSocket traffic
        Self {
            packet_size_distribution: vec![
                (256, 0.15),
                (512, 0.20),
                (1024, 0.25),
                (1460, 0.15),
                (4096, 0.15),
                (16384, 0.10),
            ],
            iat_distribution: vec![
                (10, 0.10),
                (20, 0.15),
                (50, 0.25),
                (100, 0.20),
                (200, 0.15),
                (500, 0.10),
                (1000, 0.05),
            ],
            avg_packet_size: 1200,
            packet_size_stddev: 800.0,
            avg_iat_ms: 100.0,
            iat_stddev: 80.0,
            burst_sizes: vec![1, 2, 3],
            name: "default-browser".to_string(),
        }
    }
}

impl TrafficProfile {
    /// Select a packet size from the distribution
    /// Uses weighted random selection based on learned frequencies
    pub fn select_packet_size(&self, seed: u64) -> usize {
        if self.packet_size_distribution.is_empty() {
            return 1024; // Fallback
        }
        
        // Weighted random selection
        let total_weight: f64 = self.packet_size_distribution.iter().map(|(_, w)| w).sum();
        let mut random = ((seed % 10000) as f64) / 10000.0 * total_weight;
        
        for (size, weight) in &self.packet_size_distribution {
            random -= weight;
            if random <= 0.0 {
                return *size;
            }
        }
        
        // Fallback to last size
        self.packet_size_distribution.last().map(|(s, _)| *s).unwrap_or(1024)
    }
    
    /// Select an inter-arrival time from the distribution
    pub fn select_iat_ms(&self, seed: u64) -> u64 {
        if self.iat_distribution.is_empty() {
            return 50; // Fallback
        }
        
        // Weighted random selection
        let total_weight: f64 = self.iat_distribution.iter().map(|(_, w)| w).sum();
        let mut random = ((seed % 10000) as f64) / 10000.0 * total_weight;
        
        for (iat, weight) in &self.iat_distribution {
            random -= weight;
            if random <= 0.0 {
                return *iat;
            }
        }
        
        // Fallback to last IAT
        self.iat_distribution.last().map(|(i, _)| *i).unwrap_or(50)
    }
}

/// Parse PCAP file and extract traffic patterns
#[cfg(feature = "pcap-learning")]
pub fn learn_from_pcap(pcap_path: &Path) -> Result<TrafficProfile, Box<dyn std::error::Error>> {
    let file = File::open(pcap_path)?;
    let mut pcap_reader = PcapReader::new(file)?;
    
    let mut packet_sizes: Vec<usize> = Vec::new();
    let mut timestamps: Vec<u64> = Vec::new();
    
    // Read all packets from PCAP
    while let Some(pkt) = pcap_reader.next_packet() {
        let pkt = pkt?;
        
        // Extract packet size (data length)
        let size = pkt.data.len();
        packet_sizes.push(size);
        
        // Extract timestamp (microseconds)
        let ts_us = pkt.timestamp.as_micros() as u64;
        timestamps.push(ts_us);
    }
    
    if packet_sizes.is_empty() {
        return Ok(TrafficProfile::default());
    }
    
    // Calculate statistics
    let avg_size = packet_sizes.iter().sum::<usize>() as f64 / packet_sizes.len() as f64;
    
    // Calculate standard deviation
    let variance: f64 = packet_sizes.iter()
        .map(|&size| {
            let diff = size as f64 - avg_size;
            diff * diff
        })
        .sum::<f64>() / packet_sizes.len() as f64;
    let stddev = variance.sqrt();
    
    // Build packet size distribution (histogram with buckets)
    let mut size_histogram = std::collections::HashMap::new();
    for &size in &packet_sizes {
        // Bucket into size ranges
        let bucket = if size < 256 { 128 }
        else if size < 512 { 256 }
        else if size < 1024 { 512 }
        else if size < 2048 { 1024 }
        else if size < 4096 { 2048 }
        else if size < 8192 { 4096 }
        else if size < 16384 { 8192 }
        else { 16384 };
        
        *size_histogram.entry(bucket).or_insert(0) += 1;
    }
    
    // Convert to frequency distribution
    let total_packets = packet_sizes.len() as f64;
    let mut size_dist: Vec<(usize, f64)> = size_histogram.iter()
        .map(|(&size, &count)| (size, count as f64 / total_packets))
        .collect();
    size_dist.sort_by_key(|(size, _)| *size);
    
    // Calculate inter-arrival times
    let mut iats: Vec<u64> = Vec::new();
    for i in 1..timestamps.len() {
        let iat_us = timestamps[i].saturating_sub(timestamps[i-1]);
        let iat_ms = iat_us / 1000; // Convert to milliseconds
        if iat_ms > 0 && iat_ms < 10000 { // Filter out unrealistic IATs
            iats.push(iat_ms);
        }
    }
    
    let avg_iat = if !iats.is_empty() {
        iats.iter().sum::<u64>() as f64 / iats.len() as f64
    } else {
        100.0
    };
    
    // IAT variance
    let iat_variance: f64 = if !iats.is_empty() {
        iats.iter()
            .map(|&iat| {
                let diff = iat as f64 - avg_iat;
                diff * diff
            })
            .sum::<f64>() / iats.len() as f64
    } else {
        50.0
    };
    let iat_stddev = iat_variance.sqrt();
    
    // Build IAT distribution
    let mut iat_histogram = std::collections::HashMap::new();
    for &iat in &iats {
        let bucket = if iat < 10 { 5 }
        else if iat < 20 { 10 }
        else if iat < 50 { 20 }
        else if iat < 100 { 50 }
        else if iat < 200 { 100 }
        else if iat < 500 { 200 }
        else if iat < 1000 { 500 }
        else { 1000 };
        
        *iat_histogram.entry(bucket).or_insert(0) += 1;
    }
    
    let total_iats = iats.len() as f64;
    let mut iat_dist: Vec<(u64, f64)> = iat_histogram.iter()
        .map(|(&iat, &count)| (iat, count as f64 / total_iats))
        .collect();
    iat_dist.sort_by_key(|(iat, _)| *iat);
    
    // Detect burst patterns (consecutive packets with IAT < 5ms)
    let mut bursts = Vec::new();
    let mut current_burst = 1;
    for &iat in &iats {
        if iat < 5 {
            current_burst += 1;
        } else {
            if current_burst > 1 {
                bursts.push(current_burst);
            }
            current_burst = 1;
        }
    }
    
    Ok(TrafficProfile {
        packet_size_distribution: size_dist,
        iat_distribution: iat_dist,
        avg_packet_size: avg_size as usize,
        packet_size_stddev: stddev,
        avg_iat_ms: avg_iat,
        iat_stddev,
        burst_sizes: bursts,
        name: pcap_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("learned-profile")
            .to_string(),
    })
}

/// Built-in profiles for common applications
pub fn get_builtin_profile(name: &str) -> Option<TrafficProfile> {
    match name {
        "chrome-browsing" => Some(TrafficProfile {
            packet_size_distribution: vec![
                (253, 0.12),
                (512, 0.18),
                (1019, 0.22),
                (1460, 0.18),
                (4091, 0.15),
                (16384, 0.15),
            ],
            iat_distribution: vec![
                (10, 0.08),
                (20, 0.12),
                (50, 0.22),
                (100, 0.20),
                (200, 0.18),
                (500, 0.12),
                (1000, 0.08),
            ],
            avg_packet_size: 1850,
            packet_size_stddev: 1200.0,
            avg_iat_ms: 150.0,
            iat_stddev: 120.0,
            burst_sizes: vec![1, 2, 3, 4],
            name: "chrome-browsing".to_string(),
        }),
        
        "webrtc-video" => Some(TrafficProfile {
            // WebRTC video: Regular 16.6ms frames (60fps)
            packet_size_distribution: vec![
                (1200, 0.40),  // Typical video frame size
                (1400, 0.30),
                (800, 0.20),
                (500, 0.10),
            ],
            iat_distribution: vec![
                (16, 0.70),    // 60fps = 16.6ms per frame
                (33, 0.20),    // Occasional dropped frames
                (10, 0.05),
                (50, 0.05),
            ],
            avg_packet_size: 1100,
            packet_size_stddev: 300.0,
            avg_iat_ms: 17.0,
            iat_stddev: 5.0,
            burst_sizes: vec![1, 1, 1], // Mostly single packets
            name: "webrtc-video".to_string(),
        }),
        
        "discord-voice" => Some(TrafficProfile {
            // Discord: Opus audio at 20ms frames
            packet_size_distribution: vec![
                (80, 0.50),    // Opus @48kbps
                (120, 0.30),   // Opus @64kbps
                (160, 0.15),   // Opus @96kbps
                (40, 0.05),    // Silence frames
            ],
            iat_distribution: vec![
                (20, 0.85),    // 20ms frames (Opus standard)
                (40, 0.10),    // Occasional doubling
                (10, 0.05),
            ],
            avg_packet_size: 95,
            packet_size_stddev: 30.0,
            avg_iat_ms: 20.0,
            iat_stddev: 3.0,
            burst_sizes: vec![1],  // Single packets
            name: "discord-voice".to_string(),
        }),
        
        _ => None,
    }
}

#[cfg(feature = "pcap-learning")]
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_traffic_profile_selection() {
        let profile = TrafficProfile::default();
        
        // Test packet size selection
        let size1 = profile.select_packet_size(12345);
        let size2 = profile.select_packet_size(67890);
        
        assert!(size1 > 0);
        assert!(size2 > 0);
        
        // Should select from distribution
        assert!(profile.packet_size_distribution.iter()
            .any(|(s, _)| *s == size1));
    }
    
    #[test]
    fn test_iat_selection() {
        let profile = TrafficProfile::default();
        
        let iat1 = profile.select_iat_ms(11111);
        let iat2 = profile.select_iat_ms(22222);
        
        assert!(iat1 > 0);
        assert!(iat2 > 0);
        
        // Should select from distribution
        assert!(profile.iat_distribution.iter()
            .any(|(i, _)| *i == iat1));
    }
    
    #[test]
    fn test_builtin_profiles() {
        let chrome = get_builtin_profile("chrome-browsing").expect("chrome profile");
        assert_eq!(chrome.name, "chrome-browsing");
        assert!(!chrome.packet_size_distribution.is_empty());
        
        let webrtc = get_builtin_profile("webrtc-video").expect("webrtc profile");
        assert_eq!(webrtc.name, "webrtc-video");
        assert!(webrtc.avg_iat_ms < 20.0); // Should be ~16-17ms for 60fps
        
        let discord = get_builtin_profile("discord-voice").expect("discord profile");
        assert_eq!(discord.name, "discord-voice");
        assert!(discord.avg_iat_ms < 25.0); // Should be ~20ms for Opus
    }
}

#[cfg(not(feature = "pcap-learning"))]
#[cfg(test)]
mod tests {
    use super::{get_builtin_profile, TrafficProfile};
    
    #[test]
    fn test_builtin_profiles_without_pcap() {
        // Builtin profiles should work even without pcap-learning feature
        let chrome = get_builtin_profile("chrome-browsing").expect("chrome profile");
        assert_eq!(chrome.name, "chrome-browsing");
        
        let profile = TrafficProfile::default();
        assert!(!profile.packet_size_distribution.is_empty());
    }
}

