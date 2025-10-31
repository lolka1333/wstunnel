use crate::tunnel::{LocalProtocol, RemoteAddr};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::ops::Deref;
use std::sync::LazyLock;
use std::time::SystemTime;
use url::Host;
use uuid::Uuid;

// Имитация реалистичного session ID вместо очевидного "authorization.bearer."
pub static JWT_HEADER_PREFIX: LazyLock<String> = LazyLock::new(|| {
    // Генерируем префикс похожий на настоящие CDN/Cloud session tokens
    let session_variants = [
        "session.",
        "token.",
        "auth.",
        "sid.",
        "ssid.",
        "x-session.",
        "cf-session.", // CloudFlare style
        "az-token.",   // Azure style
        "aws-token.",  // AWS style
    ];
    
    let variant = session_variants[rand::thread_rng().gen_range(0..session_variants.len())];
    format!("{}{}", variant, generate_realistic_session_id())
});

static JWT_KEY: LazyLock<(Header, EncodingKey)> = LazyLock::new(|| {
    // Используем более случайный источник для ключа
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    
    // Добавляем дополнительную энтропию
    let mut rng = rand::thread_rng();
    let random_salt: u128 = rng.gen();
    let key_material = now ^ random_salt;
    
    (
        Header::new(Algorithm::HS256),
        EncodingKey::from_secret(&key_material.to_ne_bytes())
    )
});

static JWT_DECODE: LazyLock<(Validation, DecodingKey)> = LazyLock::new(|| {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims = HashSet::with_capacity(0);
    validation.insecure_disable_signature_validation();
    (validation, DecodingKey::from_secret(b"champignonfrais"))
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtTunnelConfig {
    pub id: String,       // tunnel id
    pub p: LocalProtocol, // protocol to use
    pub r: String,        // remote host
    pub rp: u16,          // remote port
    
    // Новые поля для маскировки под реальный JWT
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,  // issued at - timestamp
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,  // expiration - timestamp
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,  // not before - timestamp
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>, // JWT ID - для маскировки
}

impl JwtTunnelConfig {
    fn new(request_id: Uuid, dest: &RemoteAddr) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            id: request_id.to_string(),
            p: match dest.protocol {
                LocalProtocol::Tcp { .. } => dest.protocol.clone(),
                LocalProtocol::Udp { .. } => dest.protocol.clone(),
                LocalProtocol::ReverseTcp => dest.protocol.clone(),
                LocalProtocol::ReverseUdp { .. } => dest.protocol.clone(),
                LocalProtocol::ReverseSocks5 { .. } => dest.protocol.clone(),
                LocalProtocol::ReverseUnix { .. } => dest.protocol.clone(),
                LocalProtocol::ReverseHttpProxy { .. } => dest.protocol.clone(),
                LocalProtocol::TProxyTcp => unreachable!("cannot use tproxy tcp as destination protocol"),
                LocalProtocol::TProxyUdp { .. } => unreachable!("cannot use tproxy udp as destination protocol"),
                LocalProtocol::Stdio { .. } => unreachable!("cannot use stdio as destination protocol"),
                LocalProtocol::Unix { .. } => unreachable!("canont use unix as destination protocol"),
                LocalProtocol::Socks5 { .. } => unreachable!("cannot use socks5 as destination protocol"),
                LocalProtocol::HttpProxy { .. } => unreachable!("cannot use http proxy as destination protocol"),
            },
            r: dest.host.to_string(),
            rp: dest.port,
            
            // Добавляем стандартные JWT поля для маскировки
            iat: Some(now),
            exp: Some(now + 3600), // истекает через час
            nbf: Some(now),
            jti: Some(generate_jwt_id()),
        }
    }
}

/// Генерирует реалистичный session ID похожий на настоящие CDN tokens
fn generate_realistic_session_id() -> String {
    use base64::Engine;
    
    // Имитация различных форматов session ID
    let format_type = rand::thread_rng().gen_range(0..3);
    
    match format_type {
        0 => {
            // CloudFlare style: base64url encoded random bytes (22 chars)
            let random_bytes: [u8; 16] = rand::thread_rng().gen();
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(random_bytes)
        }
        1 => {
            // AWS style: hex encoded timestamp + random (32 chars)
            let timestamp = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let random: u64 = rand::thread_rng().gen();
            format!("{:016x}{:016x}", timestamp, random)
        }
        _ => {
            // UUID style (без дефисов)
            Uuid::new_v4().simple().to_string()
        }
    }
}

/// Генерирует JWT ID (jti claim) для дополнительной маскировки
fn generate_jwt_id() -> String {
    // Короткий UUID для jti claim
    Uuid::new_v4().simple().to_string()[..16].to_string()
}

pub fn tunnel_to_jwt_token(request_id: Uuid, tunnel: &RemoteAddr) -> String {
    let cfg = JwtTunnelConfig::new(request_id, tunnel);
    let (alg, secret) = JWT_KEY.deref();
    
    // Генерируем JWT токен
    let token = jsonwebtoken::encode(alg, &cfg, secret).unwrap_or_default();
    
    // Добавляем реалистичный префикс
    format!("{}{}", JWT_HEADER_PREFIX.as_str(), token)
}

pub fn jwt_token_to_tunnel(token: &str) -> anyhow::Result<TokenData<JwtTunnelConfig>> {
    // Убираем префикс если есть
    let clean_token = strip_token_prefix(token);
    
    let (validation, decode_key) = JWT_DECODE.deref();
    let jwt: TokenData<JwtTunnelConfig> = jsonwebtoken::decode(clean_token, decode_key, validation)?;
    Ok(jwt)
}

/// Удаляет различные возможные префиксы из токена
fn strip_token_prefix(token: &str) -> &str {
    // Список возможных префиксов
    let prefixes = [
        "session.",
        "token.",
        "auth.",
        "sid.",
        "ssid.",
        "x-session.",
        "cf-session.",
        "az-token.",
        "aws-token.",
        "authorization.bearer.", // старый формат для обратной совместимости
    ];
    
    for prefix in &prefixes {
        if let Some(stripped) = token.strip_prefix(prefix) {
            // Пропускаем session ID часть до следующей точки
            if let Some(dot_pos) = stripped.find('.') {
                return &stripped[dot_pos + 1..];
            }
            return stripped;
        }
    }
    
    token
}

impl TryFrom<JwtTunnelConfig> for RemoteAddr {
    type Error = anyhow::Error;
    fn try_from(jwt: JwtTunnelConfig) -> anyhow::Result<Self> {
        Ok(Self {
            protocol: jwt.p,
            host: Host::parse(&jwt.r)?,
            port: jwt.rp,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_generate_realistic_session_id() {
        // Тест генерации различных форматов
        for _ in 0..10 {
            let session_id = generate_realistic_session_id();
            assert!(!session_id.is_empty());
            assert!(session_id.len() >= 16);
            assert!(session_id.len() <= 64);
        }
    }

    #[test]
    fn test_jwt_token_roundtrip() {
        let request_id = Uuid::new_v4();
        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv4(Ipv4Addr::new(127, 0, 0, 1)),
            port: 8080,
        };

        // Создаем токен
        let token = tunnel_to_jwt_token(request_id, &remote);
        
        // Проверяем что токен содержит префикс
        assert!(token.contains("session.") || 
                token.contains("token.") || 
                token.contains("auth.") ||
                token.contains("sid."));
        
        // Декодируем обратно
        let decoded = jwt_token_to_tunnel(&token).unwrap();
        
        assert_eq!(decoded.claims.id, request_id.to_string());
        assert_eq!(decoded.claims.r, "127.0.0.1");
        assert_eq!(decoded.claims.rp, 8080);
    }

    #[test]
    fn test_strip_token_prefix() {
        let test_cases = vec![
            ("session.abc123.token", "token"),
            ("token.xyz789.token", "token"),
            ("cf-session.random.token", "token"),
            ("authorization.bearer.token", "token"),
            ("token", "token"), // без префикса
        ];

        for (input, expected) in test_cases {
            assert_eq!(strip_token_prefix(input), expected);
        }
    }

    #[test]
    fn test_jwt_has_standard_claims() {
        let request_id = Uuid::new_v4();
        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Domain("example.com".to_string()),
            port: 443,
        };

        let token = tunnel_to_jwt_token(request_id, &remote);
        let decoded = jwt_token_to_tunnel(&token).unwrap();
        
        // Проверяем что добавлены стандартные JWT claims
        assert!(decoded.claims.iat.is_some());
        assert!(decoded.claims.exp.is_some());
        assert!(decoded.claims.nbf.is_some());
        assert!(decoded.claims.jti.is_some());
        
        // Проверяем что exp больше iat
        let iat = decoded.claims.iat.unwrap();
        let exp = decoded.claims.exp.unwrap();
        assert!(exp > iat);
    }

    #[test]
    fn test_backward_compatibility() {
        // Тест обратной совместимости со старым форматом
        let old_format = "authorization.bearer.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.token";
        let stripped = strip_token_prefix(old_format);
        assert!(stripped.starts_with("eyJ")); // начало JWT токена
    }

    #[test]
    fn test_jwt_id_length() {
        let jti = generate_jwt_id();
        assert_eq!(jti.len(), 16); // должен быть 16 символов
        assert!(jti.chars().all(|c| c.is_ascii_hexdigit())); // только hex символы
    }

    #[test]
    fn test_session_id_randomness() {
        // Проверяем что генерируются разные session ID
        let mut session_ids = std::collections::HashSet::new();
        
        for _ in 0..100 {
            let sid = generate_realistic_session_id();
            session_ids.insert(sid);
        }
        
        // Должно быть много уникальных значений
        assert!(session_ids.len() > 95);
    }
}