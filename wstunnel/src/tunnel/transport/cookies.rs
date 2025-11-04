/// Cookie generation module for realistic browser behavior
/// 
/// Real browsers accumulate cookies over time from various sources:
/// - Session cookies
/// - Analytics cookies (Google Analytics, etc.)
/// - Tracking cookies
/// - Functional cookies
///
/// This module generates realistic cookie strings that mimic browser behavior

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Global counter for cookie evolution
static COOKIE_GENERATION: AtomicU64 = AtomicU64::new(0);

/// Generate realistic browser-like cookies that include the JWT session token
/// plus tracking/analytics cookies that browsers typically accumulate
///
/// Returns a cookie string like:
/// "session=JWT; _ga=GA1.2.123456789.1234567890; _gid=GA1.2.987654321; _gat=1"
pub fn generate_realistic_cookies(jwt_token: &str) -> String {
    let generation = COOKIE_GENERATION.fetch_add(1, Ordering::Relaxed);
    
    // Always include the session cookie with JWT (critical for wstunnel auth)
    let mut cookies = vec![format!("session={}", jwt_token)];
    
    // ✅ Google Analytics cookies (very common, present on 80%+ of websites)
    // Format: _ga=GA1.2.{client_id}.{first_visit_timestamp}
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(std::time::Duration::from_secs(0));
    
    let client_id = generate_client_id(generation);
    let first_visit = now.as_secs() - (86400 * 30); // "First visit" 30 days ago (realistic)
    
    cookies.push(format!("_ga=GA1.2.{}.{}", client_id, first_visit));
    
    // ✅ Google Analytics _gid (daily identifier, changes every 24h)
    // Format: _gid=GA1.2.{random}
    let gid = generate_daily_id(now.as_secs());
    cookies.push(format!("_gid=GA1.2.{}", gid));
    
    // ✅ Add occasional tracking cookies (not always, realistic variation)
    // Real browsers don't always have all cookies
    if (generation % 3) != 0 {
        // Google Analytics throttle cookie (appears occasionally)
        cookies.push("_gat=1".to_string());
    }
    
    if (generation % 5) == 0 {
        // Facebook pixel cookie (appears on sites with FB tracking)
        let fbp = generate_fb_pixel(now.as_secs());
        cookies.push(format!("_fbp=fb.1.{}.{}", first_visit, fbp));
    }
    
    if (generation % 4) == 0 {
        // Session identifier (short-lived, realistic for web apps)
        let sess_id = generate_session_id(generation);
        cookies.push(format!("SESSID={}", sess_id));
    }
    
    // Join all cookies with "; " separator (standard format)
    cookies.join("; ")
}

/// Generate a realistic Google Analytics client ID
/// Format: 9-10 digit number
fn generate_client_id(seed: u64) -> u64 {
    // Use timestamp and seed for pseudo-random but deterministic ID
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(std::time::Duration::from_secs(0));
    
    // Generate realistic 9-10 digit number
    let base = 100000000u64; // 9 digits minimum
    let range = 900000000u64; // Up to 10 digits
    base + ((now.as_nanos() as u64).wrapping_add(seed) % range)
}

/// Generate daily Google Analytics ID (changes every 24 hours)
fn generate_daily_id(timestamp: u64) -> u64 {
    // Generate ID based on current day (changes at midnight UTC)
    let day = timestamp / 86400; // Days since epoch
    
    // Generate realistic 9-10 digit number based on day
    let base = 100000000u64;
    let range = 900000000u64;
    base + ((day * 1234567) % range)
}

/// Generate Facebook pixel ID
fn generate_fb_pixel(timestamp: u64) -> u64 {
    let base = 1000000000u64; // 10 digits
    let range = 9000000000u64;
    base + ((timestamp * 7654321) % range)
}

/// Generate session ID (alphanumeric, 32 chars)
fn generate_session_id(seed: u64) -> String {
    // Generate realistic session ID
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(std::time::Duration::from_secs(0));
    
    let mut result = String::with_capacity(32);
    let mut state = now.as_nanos().wrapping_add(seed as u128);
    
    for _ in 0..32 {
        state = state.wrapping_mul(1103515245).wrapping_add(12345); // LCG
        let index = (state % (CHARS.len() as u128)) as usize;
        result.push(CHARS[index] as char);
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cookie_generation() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test";
        let cookies = generate_realistic_cookies(jwt);
        
        // Should contain session cookie
        assert!(cookies.contains("session="));
        assert!(cookies.contains(jwt));
        
        // Should contain Google Analytics
        assert!(cookies.contains("_ga=GA1.2."));
        assert!(cookies.contains("_gid=GA1.2."));
        
        // Cookies should be separated by "; "
        assert!(cookies.contains("; "));
    }
    
    #[test]
    fn test_cookie_evolution() {
        let jwt = "test_token";
        
        // Generate multiple times - should vary
        let cookie1 = generate_realistic_cookies(jwt);
        let cookie2 = generate_realistic_cookies(jwt);
        
        // Session and _ga should be consistent (same generation produces same result)
        // But may have different optional cookies (_gat, _fbp, SESSID)
        assert!(cookie1.contains("session=test_token"));
        assert!(cookie2.contains("session=test_token"));
    }
    
    #[test]
    fn test_daily_id_stability() {
        let now = 1700000000u64; // Fixed timestamp
        
        let id1 = generate_daily_id(now);
        let id2 = generate_daily_id(now + 3600); // 1 hour later, same day
        let id3 = generate_daily_id(now + 86400); // Next day
        
        // Same day should produce same ID
        assert_eq!(id1, id2);
        
        // Different day should produce different ID
        assert_ne!(id1, id3);
    }
}

