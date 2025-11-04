/// DNS Cache module for realistic browser DNS behavior
///
/// Real browsers cache DNS responses to avoid excessive lookups
/// Typical TTL: 60-300 seconds (Chrome uses this range)
/// This module provides DNS caching that mimics browser behavior

use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// DNS cache entry with TTL
#[derive(Debug, Clone)]
struct DnsCacheEntry {
    /// Resolved addresses
    addresses: Vec<SocketAddr>,
    /// When this entry was cached
    cached_at: Instant,
    /// Time to live (realistic: 60-300 seconds)
    ttl: Duration,
}

impl DnsCacheEntry {
    /// Check if this cache entry is still valid
    fn is_valid(&self) -> bool {
        self.cached_at.elapsed() < self.ttl
    }
}

/// Browser-like DNS cache
/// Chrome typically caches DNS for 60 seconds (min) to 300 seconds (max)
/// with variation based on the DNS TTL from the server
#[derive(Clone)]
pub struct DnsCache {
    cache: Arc<RwLock<HashMap<String, DnsCacheEntry>>>,
}

impl DnsCache {
    /// Create a new DNS cache
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Get cached addresses if available and not expired
    pub fn get(&self, domain: &str, port: u16) -> Option<Vec<SocketAddr>> {
        let key = format!("{}:{}", domain, port);
        let cache = self.cache.read();
        
        if let Some(entry) = cache.get(&key) {
            if entry.is_valid() {
                return Some(entry.addresses.clone());
            }
        }
        
        None
    }
    
    /// Store addresses in cache with browser-like TTL
    pub fn store(&self, domain: &str, port: u16, addresses: Vec<SocketAddr>) {
        if addresses.is_empty() {
            return; // Don't cache empty results
        }
        
        let key = format!("{}:{}", domain, port);
        
        // Chrome-like TTL calculation:
        // - Min: 60 seconds
        // - Max: 300 seconds (5 minutes)
        // - Default: 120 seconds for most domains
        // Add slight variation (±20%) for realism
        let base_ttl = Duration::from_secs(120); // 2 minutes (Chrome default)
        let ttl = calculate_realistic_ttl(base_ttl);
        
        let entry = DnsCacheEntry {
            addresses,
            cached_at: Instant::now(),
            ttl,
        };
        
        let mut cache = self.cache.write();
        cache.insert(key, entry);
    }
    
    /// Clear expired entries (garbage collection)
    /// Chrome does this periodically to free memory
    pub fn cleanup_expired(&self) {
        let mut cache = self.cache.write();
        cache.retain(|_, entry| entry.is_valid());
    }
    
    /// Get cache statistics (for debugging/monitoring)
    pub fn stats(&self) -> DnsCacheStats {
        let cache = self.cache.read();
        let total = cache.len();
        let expired = cache.values().filter(|e| !e.is_valid()).count();
        
        DnsCacheStats {
            total_entries: total,
            valid_entries: total - expired,
            expired_entries: expired,
        }
    }
    
    /// Invalidate (clear) entire cache
    /// Useful when network changes or for testing
    pub fn clear(&self) {
        let mut cache = self.cache.write();
        cache.clear();
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

/// DNS cache statistics
#[derive(Debug, Clone, Copy)]
pub struct DnsCacheStats {
    pub total_entries: usize,
    pub valid_entries: usize,
    pub expired_entries: usize,
}

/// Calculate realistic DNS TTL with variation
/// Chrome uses variable TTLs based on the DNS response, but typically:
/// - Min: 60 seconds (for frequently changing domains)
/// - Default: 120 seconds (most domains)
/// - Max: 300 seconds (stable domains)
fn calculate_realistic_ttl(base_ttl: Duration) -> Duration {
    use std::time::SystemTime;
    
    let now = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0));
    
    // Add ±20% variation to TTL (realistic variation)
    let variation_percent = ((now.as_nanos() % 40) as i64) - 20; // -20% to +20%
    let base_secs = base_ttl.as_secs() as i64;
    let variation_secs = base_secs * variation_percent / 100;
    let final_secs = (base_secs + variation_secs).max(60).min(300) as u64;
    
    Duration::from_secs(final_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    
    #[test]
    fn test_dns_cache_basic() {
        let cache = DnsCache::new();
        let domain = "example.com";
        let port = 443;
        
        // Initially empty
        assert!(cache.get(domain, port).is_none());
        
        // Store addresses
        let addrs = vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), port)];
        cache.store(domain, port, addrs.clone());
        
        // Should be cached now
        let cached = cache.get(domain, port);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap(), addrs);
    }
    
    #[test]
    fn test_dns_cache_expiration() {
        let cache = DnsCache::new();
        let domain = "example.com";
        let port = 443;
        
        // Store with very short TTL
        let addrs = vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), port)];
        cache.store(domain, port, addrs);
        
        // Manually expire by modifying entry
        {
            let mut cache_map = cache.cache.write();
            if let Some(entry) = cache_map.get_mut(&format!("{}:{}", domain, port)) {
                entry.cached_at = Instant::now() - Duration::from_secs(400); // Expired
            }
        }
        
        // Should be expired now
        assert!(cache.get(domain, port).is_none());
    }
    
    #[test]
    fn test_dns_cache_stats() {
        let cache = DnsCache::new();
        
        // Add some entries
        let addrs = vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443)];
        cache.store("domain1.com", 443, addrs.clone());
        cache.store("domain2.com", 443, addrs.clone());
        cache.store("domain3.com", 443, addrs);
        
        let stats = cache.stats();
        assert_eq!(stats.total_entries, 3);
        assert_eq!(stats.valid_entries, 3);
        assert_eq!(stats.expired_entries, 0);
    }
    
    #[test]
    fn test_ttl_variation() {
        let base_ttl = Duration::from_secs(120);
        
        // Generate multiple TTLs
        let ttl1 = calculate_realistic_ttl(base_ttl);
        let ttl2 = calculate_realistic_ttl(base_ttl);
        
        // Should be within range
        assert!(ttl1.as_secs() >= 60);
        assert!(ttl1.as_secs() <= 300);
        assert!(ttl2.as_secs() >= 60);
        assert!(ttl2.as_secs() <= 300);
    }
}

