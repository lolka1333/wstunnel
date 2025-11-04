/// URL Path Variation module for DPI/ML evasion
///
/// Real web applications use diverse URL patterns that change over time.
/// This module generates realistic URL paths that mimic legitimate web services
/// to avoid static URL fingerprinting.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Global counter for path variation
static PATH_SELECTOR_STATE: AtomicU64 = AtomicU64::new(0x9876543210ABCDEF);

/// Realistic API path patterns observed in modern web applications
const API_PATH_PATTERNS: &[&str] = &[
    "/api/v1/events",
    "/api/v1/ws",
    "/api/v1/stream",
    "/api/v2/realtime",
    "/api/v2/notifications",
    "/v1/events",
    "/v1/stream",
    "/v2/updates",
    "/socket/connect",
    "/stream/live",
    "/updates/realtime",
    "/graphql",
    "/ws/connect",
    "/realtime/events",
];

/// Common query parameter patterns for realistic URL variation
const QUERY_PARAM_KEYS: &[&str] = &[
    "session",
    "client_id", 
    "transport",
    "v",
    "t",
    "EIO",
    "sid",
    "uid",
];

/// Generate a realistic API path with optional query parameters
///
/// Examples:
/// - /api/v1/events
/// - /api/v1/events?session=abc123&t=1234567890
/// - /socket/connect?transport=websocket&v=2.1
pub fn generate_realistic_path(base_prefix: &str, add_query_params: bool) -> String {
    let state = PATH_SELECTOR_STATE.fetch_add(1, Ordering::Relaxed);
    
    // Select path pattern
    // If base_prefix matches a known pattern, use it
    // Otherwise, select a realistic alternative
    let path = if API_PATH_PATTERNS.iter().any(|p| p.contains(base_prefix)) {
        // Use one of the paths containing the prefix
        let matching: Vec<_> = API_PATH_PATTERNS.iter()
            .filter(|p| p.contains(base_prefix))
            .collect();
        if !matching.is_empty() {
            let index = (state as usize) % matching.len();
            matching[index].to_string()
        } else {
            format!("/{}/events", base_prefix)
        }
    } else {
        // Select from realistic patterns
        let index = (state as usize) % API_PATH_PATTERNS.len();
        API_PATH_PATTERNS[index].to_string()
    };
    
    // Add query parameters for variation
    if add_query_params && should_add_query_params(state) {
        let query = generate_query_params(state);
        format!("{}?{}", path, query)
    } else {
        path
    }
}

/// Decide if we should add query parameters (not always, for variation)
fn should_add_query_params(state: u64) -> bool {
    // 60% chance to add query params (realistic variation)
    (state % 10) > 3
}

/// Generate realistic query parameter string
fn generate_query_params(seed: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(std::time::Duration::from_secs(0));
    
    let timestamp = now.as_millis();
    let session_id = generate_session_id(seed);
    
    // Number of query params (1-3 is realistic)
    let num_params = ((seed % 3) + 1) as usize;
    
    let mut params = Vec::new();
    
    // Always include at least one of these common params
    match seed % 4 {
        0 => params.push(format!("session={}", session_id)),
        1 => params.push(format!("client_id={}", session_id)),
        2 => params.push(format!("sid={}", session_id)),
        _ => params.push(format!("uid={}", session_id)),
    }
    
    // Add timestamp param (common for cache busting)
    if num_params > 1 {
        params.push(format!("t={}", timestamp));
    }
    
    // Add version or transport param
    if num_params > 2 {
        if (seed % 2) == 0 {
            let version = format!("2.{}.{}", (seed % 5), (seed % 100));
            params.push(format!("v={}", version));
        } else {
            params.push("transport=websocket".to_string());
        }
    }
    
    params.join("&")
}

/// Generate a realistic session ID (alphanumeric, 16-24 chars)
fn generate_session_id(seed: u64) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(std::time::Duration::from_secs(0));
    
    let length = 16 + ((seed % 9) as usize); // 16-24 chars (realistic)
    let mut result = String::with_capacity(length);
    let mut state = now.as_nanos().wrapping_add(seed as u128);
    
    for _ in 0..length {
        state = state.wrapping_mul(1103515245).wrapping_add(12345);
        let index = (state % (CHARS.len() as u128)) as usize;
        result.push(CHARS[index] as char);
    }
    
    result
}

/// Get a list of realistic path variations for rotation
pub fn get_path_variations(base_prefix: &str) -> Vec<String> {
    let mut variations = Vec::new();
    
    // Add variations with and without query params
    for i in 0..10 {
        let with_params = (i % 2) == 0;
        variations.push(generate_realistic_path(base_prefix, with_params));
    }
    
    variations
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_path_generation() {
        let path1 = generate_realistic_path("v1", false);
        let path2 = generate_realistic_path("v1", true);
        
        // Without params should be clean path
        assert!(!path1.contains('?'));
        
        // With params should have query string (most of the time)
        // (might not always due to should_add_query_params randomization)
        
        // Should start with /
        assert!(path1.starts_with('/'));
        assert!(path2.starts_with('/'));
    }
    
    #[test]
    fn test_path_variation() {
        let variations = get_path_variations("v1");
        
        // Should have 10 variations
        assert_eq!(variations.len(), 10);
        
        // Should have some with and some without params
        let with_params = variations.iter().filter(|p| p.contains('?')).count();
        assert!(with_params > 0);
        assert!(with_params < 10); // Not all should have params
    }
    
    #[test]
    fn test_session_id_generation() {
        let id1 = generate_session_id(12345);
        let id2 = generate_session_id(67890);
        
        // Should be 16-24 chars
        assert!(id1.len() >= 16 && id1.len() <= 24);
        assert!(id2.len() >= 16 && id2.len() <= 24);
        
        // Should be alphanumeric only
        assert!(id1.chars().all(|c| c.is_ascii_alphanumeric()));
        assert!(id2.chars().all(|c| c.is_ascii_alphanumeric()));
        
        // Different seeds should produce different IDs
        assert_ne!(id1, id2);
    }
    
    #[test]
    fn test_query_params_generation() {
        let params = generate_query_params(11111);
        
        // Should contain at least session/client_id/sid/uid
        assert!(params.contains("session=") || 
                params.contains("client_id=") || 
                params.contains("sid=") ||
                params.contains("uid="));
        
        // Should use & separator
        if params.contains('&') {
            let parts: Vec<_> = params.split('&').collect();
            assert!(parts.len() >= 2);
            assert!(parts.len() <= 3);
        }
    }
}

