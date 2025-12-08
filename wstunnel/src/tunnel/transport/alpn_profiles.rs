/// ALPN Protocol Profiles Module
///
/// This module provides browser-specific ALPN (Application-Layer Protocol Negotiation)
/// configurations to enhance TLS fingerprint authenticity and evade ML-based DPI detection.
///
/// ## Why ALPN Matters for DPI Evasion
/// Modern DPI systems (especially Russian TSPU) use ML models trained on:
/// - ALPN protocol order (which protocols, in which order)
/// - Protocol combinations (h2+http/1.1 vs h3+h2+http/1.1)
/// - Rare/experimental protocols (grpc-exp, webrtc, etc.)
///
/// Real browsers have distinct ALPN patterns that change over time and context.
///
/// ## Implementation
/// - Chrome: h2, http/1.1 (simple, stable)
/// - Firefox: h2, http/1.1 (similar to Chrome, sometimes includes h3)
/// - Safari: h2, http/1.1, sometimes spdy/3.1 for legacy
/// - Edge: Same as Chrome (Chromium-based)
/// - Mobile browsers: May include additional protocols
///
/// ## References
/// - RFC 7301: TLS ALPN Extension
/// - Chrome/Firefox ALPN implementation analysis
/// - HTTP/3 QUIC ALPN: h3, h3-29, h3-Q050

use rand::Rng;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Global counter for ALPN rotation
static ALPN_ROTATION_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// ALPN profile for a specific browser/context
#[derive(Debug, Clone, PartialEq)]
pub struct AlpnProfile {
    /// Profile name
    pub name: String,
    
    /// Primary ALPN protocols (always included)
    pub primary_protocols: Vec<String>,
    
    /// Optional protocols (may be included based on context)
    pub optional_protocols: Vec<String>,
    
    /// Protocol weight (for randomization)
    pub protocol_weights: Vec<f32>,
    
    /// Whether to include experimental protocols
    pub include_experimental: bool,
}

impl AlpnProfile {
    /// Chrome ALPN profile
    /// 
    /// Chrome consistently uses h2 and http/1.1 in that order.
    /// Occasionally includes experimental protocols in development builds.
    pub fn chrome() -> Self {
        Self {
            name: "Chrome".to_string(),
            primary_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            optional_protocols: vec![
                // Rarely: gRPC experimental (Chrome DevTools, extensions)
                "grpc-exp".to_string(),
            ],
            protocol_weights: vec![1.0, 1.0, 0.05], // 5% chance for grpc-exp
            include_experimental: false,
        }
    }
    
    /// Firefox ALPN profile
    /// 
    /// Firefox similar to Chrome but may prioritize HTTP/3 when available
    pub fn firefox() -> Self {
        Self {
            name: "Firefox".to_string(),
            primary_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            optional_protocols: vec![
                // Firefox sometimes advertises HTTP/3
                "h3".to_string(),
            ],
            protocol_weights: vec![1.0, 1.0, 0.1], // 10% chance for h3
            include_experimental: false,
        }
    }
    
    /// Safari ALPN profile
    /// 
    /// Safari uses h2 and http/1.1, legacy versions may include spdy
    pub fn safari() -> Self {
        Self {
            name: "Safari".to_string(),
            primary_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            optional_protocols: vec![
                // Very rare: legacy SPDY support
                "spdy/3.1".to_string(),
            ],
            protocol_weights: vec![1.0, 1.0, 0.01], // 1% chance for spdy
            include_experimental: false,
        }
    }
    
    /// Edge ALPN profile (Chromium-based, identical to Chrome)
    pub fn edge() -> Self {
        let mut profile = Self::chrome();
        profile.name = "Edge".to_string();
        profile
    }
    
    /// Chrome Android ALPN profile
    /// 
    /// Mobile Chrome may include additional protocols
    pub fn chrome_android() -> Self {
        Self {
            name: "Chrome Android".to_string(),
            primary_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            optional_protocols: vec![
                // Mobile may include WebRTC-related protocols
                "webrtc".to_string(),
            ],
            protocol_weights: vec![1.0, 1.0, 0.03], // 3% chance
            include_experimental: false,
        }
    }
    
    /// Firefox Android ALPN profile
    pub fn firefox_android() -> Self {
        Self {
            name: "Firefox Android".to_string(),
            primary_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            optional_protocols: vec!["h3".to_string()],
            protocol_weights: vec![1.0, 1.0, 0.15], // 15% chance for h3 on mobile
            include_experimental: false,
        }
    }
    
    /// Get ALPN protocols with randomized optional protocols
    /// 
    /// Returns a realistic set of ALPN protocols based on:
    /// - Primary protocols (always included)
    /// - Optional protocols (included based on weights)
    /// - Connection count (for temporal variation)
    pub fn get_protocols(&self, connection_count: u64) -> Vec<String> {
        let mut protocols = self.primary_protocols.clone();
        
        // Add optional protocols based on weights
        for (i, optional) in self.optional_protocols.iter().enumerate() {
            if i < self.protocol_weights.len() - self.primary_protocols.len() {
                let weight_idx = self.primary_protocols.len() + i;
                let weight = self.protocol_weights.get(weight_idx).unwrap_or(&0.0);
                
                // Use connection count for deterministic variation
                let threshold = ((connection_count as f64 * 0.1) % 1.0) as f32;
                
                if *weight > threshold {
                    protocols.push(optional.clone());
                }
            }
        }
        
        protocols
    }
    
    /// Get ALPN protocols with full randomization
    pub fn get_protocols_randomized(&self) -> Vec<String> {
        let mut protocols = self.primary_protocols.clone();
        let mut rng = rand::rng();
        
        for (i, optional) in self.optional_protocols.iter().enumerate() {
            if i < self.protocol_weights.len() - self.primary_protocols.len() {
                let weight_idx = self.primary_protocols.len() + i;
                let weight = self.protocol_weights.get(weight_idx).unwrap_or(&0.0);
                
                if rng.random::<f32>() < *weight {
                    protocols.push(optional.clone());
                }
            }
        }
        
        protocols
    }
}

/// ALPN Profile Manager for dynamic protocol selection
pub struct AlpnProfileManager {
    /// Current profile
    profile: AlpnProfile,
    
    /// Connection counter
    connection_count: AtomicUsize,
}

impl AlpnProfileManager {
    /// Create new ALPN profile manager
    pub fn new(profile: AlpnProfile) -> Self {
        Self {
            profile,
            connection_count: AtomicUsize::new(0),
        }
    }
    
    /// Create manager for Chrome
    pub fn chrome() -> Self {
        Self::new(AlpnProfile::chrome())
    }
    
    /// Create manager for Firefox
    pub fn firefox() -> Self {
        Self::new(AlpnProfile::firefox())
    }
    
    /// Create manager for Safari
    pub fn safari() -> Self {
        Self::new(AlpnProfile::safari())
    }
    
    /// Get ALPN protocols for next connection
    pub fn get_protocols(&self) -> Vec<String> {
        let count = self.connection_count.fetch_add(1, Ordering::Relaxed);
        self.profile.get_protocols(count as u64)
    }
    
    /// Get randomized ALPN protocols
    pub fn get_protocols_randomized(&self) -> Vec<String> {
        self.connection_count.fetch_add(1, Ordering::Relaxed);
        self.profile.get_protocols_randomized()
    }
}

/// Get ALPN profile for browser fingerprint
pub fn get_alpn_profile_for_browser(browser: &str) -> AlpnProfile {
    match browser.to_lowercase().as_str() {
        "chrome" | "chrome120" | "chrome_windows" | "chrome120_windows" => AlpnProfile::chrome(),
        "chrome_macos" | "chrome120_macos" => AlpnProfile::chrome(),
        "chrome_linux" | "chrome120_linux" => AlpnProfile::chrome(),
        "chrome_android" => AlpnProfile::chrome_android(),
        "firefox" | "firefox121" | "firefox_windows" | "firefox121_windows" => AlpnProfile::firefox(),
        "firefox_macos" | "firefox121_macos" => AlpnProfile::firefox(),
        "firefox_android" => AlpnProfile::firefox_android(),
        "safari" | "safari17" | "safari_macos" | "safari17_macos" => AlpnProfile::safari(),
        "safari_ios" | "safari_ios17" => AlpnProfile::safari(),
        "edge" | "edge120" | "edge_windows" | "edge120_windows" => AlpnProfile::edge(),
        _ => AlpnProfile::chrome(), // Default to Chrome
    }
}

/// Get dynamic ALPN protocols with rotation
/// 
/// This function provides temporal variation in ALPN protocols:
/// - Base protocols stay consistent
/// - Optional protocols rotate based on global counter
/// - Mimics browser behavior over time
pub fn get_rotated_alpn_protocols(browser: &str) -> Vec<String> {
    let profile = get_alpn_profile_for_browser(browser);
    let count = ALPN_ROTATION_COUNTER.fetch_add(1, Ordering::Relaxed);
    profile.get_protocols(count as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_chrome_alpn() {
        let profile = AlpnProfile::chrome();
        assert_eq!(profile.primary_protocols, vec!["h2", "http/1.1"]);
        
        // Should always include primary protocols
        let protocols = profile.get_protocols(0);
        assert!(protocols.contains(&"h2".to_string()));
        assert!(protocols.contains(&"http/1.1".to_string()));
    }
    
    #[test]
    fn test_firefox_alpn() {
        let profile = AlpnProfile::firefox();
        assert_eq!(profile.primary_protocols, vec!["h2", "http/1.1"]);
        
        // Optional h3 may be included
        let protocols = profile.get_protocols_randomized();
        assert!(protocols.len() >= 2);
        assert!(protocols.len() <= 3);
    }
    
    #[test]
    fn test_alpn_rotation() {
        let browser = "chrome";
        
        // Generate protocols multiple times
        let mut protocol_sets = Vec::new();
        for _ in 0..10 {
            let protocols = get_rotated_alpn_protocols(browser);
            protocol_sets.push(protocols);
        }
        
        // All should include base protocols
        for protocols in &protocol_sets {
            assert!(protocols.contains(&"h2".to_string()));
            assert!(protocols.contains(&"http/1.1".to_string()));
        }
    }
    
    #[test]
    fn test_alpn_manager() {
        let manager = AlpnProfileManager::chrome();
        
        // Get protocols multiple times
        for _ in 0..5 {
            let protocols = manager.get_protocols();
            assert!(protocols.len() >= 2);
        }
    }
    
    #[test]
    fn test_browser_specific_profiles() {
        let chrome = get_alpn_profile_for_browser("chrome");
        let firefox = get_alpn_profile_for_browser("firefox");
        let safari = get_alpn_profile_for_browser("safari");
        
        assert_eq!(chrome.name, "Chrome");
        assert_eq!(firefox.name, "Firefox");
        assert_eq!(safari.name, "Safari");
    }
}
