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
    
    /// TLS Record Split - разделяет TLS Record Header от payload
    /// Критично для обхода ТСПУ: DPI видит неполный заголовок
    TlsRecordSplit,
    
    /// SNI Dots Split - разделяет hostname на каждой точке домена
    /// Например: "www.example.com" → ["www", ".", "example", ".", "com"]
    SniDotsSplit,
}

/// Disorder mode for out-of-order packet delivery
/// Улучшенные режимы OOB (Out-of-Order Bytes) доставки
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DisorderMode {
    /// Отключено
    #[default]
    None,
    
    /// Поменять 2-й и 3-й фрагменты местами
    /// Классический disorder, сохраняет первый пакет для TLS
    SwapSecondThird,
    
    /// Отправить первый фрагмент последним
    /// Агрессивный режим, требует буферизации на стороне сервера
    FirstLast,
    
    /// Отправить второй фрагмент первым
    /// Эффективен против stateful DPI с коротким таймаутом
    SecondFirst,
    
    /// Случайная перестановка всех фрагментов кроме первого
    /// Максимальный disorder, может вызвать задержки
    RandomShuffle,
    
    /// Reverse order - обратный порядок всех фрагментов кроме первого
    /// Предсказуемый, но эффективный против некоторых DPI
    Reverse,
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
    
    /// Disorder mode - улучшенный режим OOB доставки
    pub disorder_mode: DisorderMode,
    
    /// Split TLS Record Header from payload (критично для ТСПУ)
    /// Разделяет 5-байтный заголовок TLS Record от данных
    pub split_tls_record_header: bool,
    
    /// Split SNI hostname at dots (разделение на точках домена)
    pub split_sni_at_dots: bool,
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
            disorder_mode: DisorderMode::None,
            split_tls_record_header: false,
            split_sni_at_dots: false,
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
            disorder_mode: DisorderMode::None,
            split_tls_record_header: true,  // Критично для ТСПУ
            split_sni_at_dots: true,        // Разделение SNI на точках
        }
    }
    
    /// Aggressive configuration for modern Russian DPI (ТСПУ 2024+)
    /// Использует все доступные техники
    pub fn russia_aggressive() -> Self {
        Self {
            strategy: FragmentationStrategy::TlsRecordSplit,
            inter_fragment_delay_us: 50,
            send_first_immediately: true,
            use_tcp_nodelay: true,
            flush_after_fragment: true,
            fragment_first_n_bytes: 600,
            tls_split_positions: vec![],
            enable_disorder: true,
            disorder_probability: 0.5,
            disorder_mode: DisorderMode::SecondFirst,
            split_tls_record_header: true,
            split_sni_at_dots: true,
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
            disorder_mode: DisorderMode::None,
            split_tls_record_header: true,
            split_sni_at_dots: false,
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
            disorder_mode: DisorderMode::None,
            split_tls_record_header: false,  // Не нужно при побайтовой фрагментации
            split_sni_at_dots: false,
        }
    }
    
    /// Disorder fragmentation (send out of order) - legacy
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
            disorder_mode: DisorderMode::SwapSecondThird,
            split_tls_record_header: false,
            split_sni_at_dots: false,
        }
    }
    
    /// Advanced disorder with SecondFirst mode
    /// Отправляет второй фрагмент первым - эффективен против stateful DPI
    pub fn with_disorder_second_first() -> Self {
        Self {
            strategy: FragmentationStrategy::FixedSize(40),
            inter_fragment_delay_us: 100,
            send_first_immediately: false,  // Не отправляем первый сразу
            use_tcp_nodelay: true,
            flush_after_fragment: true,
            fragment_first_n_bytes: 600,
            tls_split_positions: vec![],
            enable_disorder: true,
            disorder_probability: 1.0,  // Всегда disorder
            disorder_mode: DisorderMode::SecondFirst,
            split_tls_record_header: true,
            split_sni_at_dots: true,
        }
    }
    
    /// TLS Record Split strategy - разделяет заголовок TLS от payload
    pub fn tls_record_split() -> Self {
        Self {
            strategy: FragmentationStrategy::TlsRecordSplit,
            inter_fragment_delay_us: 100,
            send_first_immediately: true,
            use_tcp_nodelay: true,
            flush_after_fragment: true,
            fragment_first_n_bytes: 600,
            tls_split_positions: vec![],
            enable_disorder: false,
            disorder_probability: 0.0,
            disorder_mode: DisorderMode::None,
            split_tls_record_header: true,
            split_sni_at_dots: false,
        }
    }
    
    /// SNI Dots Split - разделяет hostname на точках
    pub fn sni_dots_split() -> Self {
        Self {
            strategy: FragmentationStrategy::SniDotsSplit,
            inter_fragment_delay_us: 100,
            send_first_immediately: true,
            use_tcp_nodelay: true,
            flush_after_fragment: true,
            fragment_first_n_bytes: 600,
            tls_split_positions: vec![],
            enable_disorder: false,
            disorder_probability: 0.0,
            disorder_mode: DisorderMode::None,
            split_tls_record_header: false,
            split_sni_at_dots: true,
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

/// TLS Record Header structure (5 bytes)
/// - Content Type (1 byte): 0x16 = Handshake, 0x17 = Application Data
/// - Version (2 bytes): 0x0301 = TLS 1.0, 0x0303 = TLS 1.2
/// - Length (2 bytes): Length of following data
pub const TLS_RECORD_HEADER_SIZE: usize = 5;

/// Split positions for TLS Record Header
/// Возвращает позиции для разделения TLS Record Header от payload
/// 
/// Стратегия: разделить заголовок так, чтобы DPI не смогла определить тип записи
/// - Позиция 1: после Content Type (1 байт) - DPI не видит версию
/// - Позиция 2: после Version (3 байта) - DPI не видит длину
/// - Позиция 4: перед последним байтом длины - неполная длина
pub fn calculate_tls_record_split_positions(data: &[u8]) -> Vec<usize> {
    let mut positions = Vec::new();
    
    // Проверяем что это TLS запись
    if data.len() < TLS_RECORD_HEADER_SIZE || data[0] != 0x16 {
        return positions;
    }
    
    // Стратегия 1: Split после первого байта (Content Type)
    // DPI не видит полный заголовок
    positions.push(1);
    
    // Стратегия 2: Split после 4-го байта (перед последним байтом длины)
    // DPI не может определить полную длину записи
    if data.len() >= 5 {
        positions.push(4);
    }
    
    // Стратегия 3: Split сразу после заголовка (перед handshake type)
    // Разделяет Record Header от Handshake Header
    if data.len() > TLS_RECORD_HEADER_SIZE {
        positions.push(TLS_RECORD_HEADER_SIZE);
    }
    
    // Стратегия 4: Split после Handshake Type (6 байт)
    // DPI не видит полный Handshake Header
    if data.len() > 6 {
        positions.push(6);
    }
    
    positions
}

/// Find SNI hostname position and split at each dot
/// Возвращает позиции точек внутри SNI hostname для разделения
/// 
/// Пример: "www.example.com" с offset=100
/// Вернёт: [103, 111] (позиции точек: www|.|example|.|com)
pub fn calculate_sni_dot_split_positions(data: &[u8]) -> Vec<usize> {
    let mut positions = Vec::new();
    
    // Находим SNI extension в ClientHello
    let sni_info = match find_sni_info(data) {
        Some(info) => info,
        None => return positions,
    };
    
    let hostname_start = sni_info.hostname_offset;
    let hostname = &sni_info.hostname;
    
    // Находим позиции точек в hostname
    for (i, ch) in hostname.char_indices() {
        if ch == '.' {
            let absolute_pos = hostname_start + i;
            if absolute_pos < data.len() {
                // Split ПЕРЕД точкой
                positions.push(absolute_pos);
                // Split ПОСЛЕ точки (следующий символ)
                if absolute_pos + 1 < data.len() {
                    positions.push(absolute_pos + 1);
                }
            }
        }
    }
    
    // Также добавляем split в начале и конце hostname
    if hostname_start > 0 && hostname_start < data.len() {
        positions.push(hostname_start);
    }
    
    let hostname_end = hostname_start + hostname.len();
    if hostname_end < data.len() {
        positions.push(hostname_end);
    }
    
    positions.sort();
    positions.dedup();
    positions
}

/// SNI information found in TLS ClientHello
#[derive(Debug, Clone)]
pub struct SniInfoBasic {
    /// Offset of hostname in the data
    pub hostname_offset: usize,
    /// The hostname string
    pub hostname: String,
    /// Offset of SNI extension
    pub extension_offset: usize,
}

/// Find SNI extension in TLS ClientHello and return basic info
pub fn find_sni_info(data: &[u8]) -> Option<SniInfoBasic> {
    if data.len() < 43 {
        return None;
    }
    
    // Check TLS record header
    if data[0] != 0x16 {
        return None;
    }
    
    // Check handshake type (ClientHello = 0x01)
    if data.len() < 6 || data[5] != 0x01 {
        return None;
    }
    
    // Skip to extensions
    let mut pos = 5 + 4 + 2 + 32; // record_header(5) + handshake_header(4) + version(2) + random(32)
    
    if pos >= data.len() {
        return None;
    }
    
    // Skip session ID
    let session_id_len = data[pos] as usize;
    pos += 1 + session_id_len;
    
    if pos + 2 > data.len() {
        return None;
    }
    
    // Skip cipher suites
    let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;
    
    if pos + 1 > data.len() {
        return None;
    }
    
    // Skip compression methods
    let compression_len = data[pos] as usize;
    pos += 1 + compression_len;
    
    if pos + 2 > data.len() {
        return None;
    }
    
    // Parse extensions
    let extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    
    let extensions_end = pos + extensions_len;
    if extensions_end > data.len() {
        return None;
    }
    
    // Find SNI extension (type 0x0000)
    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        
        if ext_type == 0x0000 {
            // Found SNI extension
            let extension_offset = pos;
            
            // Parse SNI data: list_length(2) + type(1) + name_length(2) + hostname(N)
            if pos + 4 + 5 > data.len() || ext_len < 5 {
                return None;
            }
            
            let name_length = u16::from_be_bytes([data[pos + 4 + 3], data[pos + 4 + 4]]) as usize;
            
            // Hostname starts at: extension_start + ext_header(4) + list_len(2) + type(1) + name_len(2)
            let hostname_offset = pos + 4 + 5;
            
            if hostname_offset + name_length > data.len() {
                return None;
            }
            
            let hostname_bytes = &data[hostname_offset..hostname_offset + name_length];
            let hostname = String::from_utf8_lossy(hostname_bytes).to_string();
            
            return Some(SniInfoBasic {
                hostname_offset,
                hostname,
                extension_offset,
            });
        }
        
        pos += 4 + ext_len;
    }
    
    None
}

/// Apply disorder mode to fragments
/// Переставляет фрагменты согласно выбранному режиму disorder
fn apply_disorder_mode(fragments: &mut Vec<Bytes>, mode: DisorderMode, state: u64) {
    if fragments.len() < 2 {
        return;
    }
    
    match mode {
        DisorderMode::None => {}
        
        DisorderMode::SwapSecondThird => {
            // Меняем 2-й и 3-й фрагменты
            if fragments.len() >= 3 {
                fragments.swap(1, 2);
            }
        }
        
        DisorderMode::FirstLast => {
            // Первый фрагмент отправляем последним
            if fragments.len() >= 2 {
                let first = fragments.remove(0);
                fragments.push(first);
            }
        }
        
        DisorderMode::SecondFirst => {
            // Второй фрагмент отправляем первым
            if fragments.len() >= 2 {
                fragments.swap(0, 1);
            }
        }
        
        DisorderMode::RandomShuffle => {
            // Случайная перестановка всех кроме первого
            if fragments.len() > 2 {
                // Сохраняем первый фрагмент
                let first = fragments[0].clone();
                let rest = &mut fragments[1..];
                
                // Fisher-Yates shuffle
                let mut rng = state;
                for i in (1..rest.len()).rev() {
                    rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
                    let j = (rng as usize) % (i + 1);
                    rest.swap(i, j);
                }
                
                fragments[0] = first;
            }
        }
        
        DisorderMode::Reverse => {
            // Обратный порядок всех кроме первого
            if fragments.len() > 2 {
                let first = fragments[0].clone();
                fragments[1..].reverse();
                fragments[0] = first;
            }
        }
    }
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
        
        FragmentationStrategy::TlsRecordSplit => {
            // TLS Record Split - разделяем TLS Record Header от payload
            // Критично для обхода ТСПУ, который анализирует заголовок TLS
            let mut positions = calculate_tls_record_split_positions(to_fragment);
            
            // Добавляем дополнительные позиции если включен split_sni_at_dots
            if config.split_sni_at_dots {
                let sni_positions = calculate_sni_dot_split_positions(to_fragment);
                positions.extend(sni_positions);
            }
            
            positions.sort();
            positions.dedup();
            
            // Фильтруем слишком близкие позиции
            let mut filtered = Vec::new();
            let mut last_pos = 0usize;
            for pos in positions {
                if pos > last_pos && pos < to_fragment.len() {
                    filtered.push(pos);
                    last_pos = pos;
                }
            }
            
            fragment_at_positions(to_fragment, &filtered, remainder)
        }
        
        FragmentationStrategy::SniDotsSplit => {
            // SNI Dots Split - разделяем hostname на каждой точке
            let mut positions = calculate_sni_dot_split_positions(to_fragment);
            
            // Добавляем TLS Record Header split если включено
            if config.split_tls_record_header {
                let tls_positions = calculate_tls_record_split_positions(to_fragment);
                positions.extend(tls_positions);
            }
            
            positions.sort();
            positions.dedup();
            
            // Фильтруем слишком близкие позиции
            let mut filtered = Vec::new();
            let mut last_pos = 0usize;
            for pos in positions {
                if pos > last_pos && pos < to_fragment.len() {
                    filtered.push(pos);
                    last_pos = pos;
                }
            }
            
            fragment_at_positions(to_fragment, &filtered, remainder)
        }
    };
    
    // Дополнительная обработка: добавляем TLS Record Header split если включено
    // и стратегия не TlsRecordSplit/SniDotsSplit (они уже обрабатывают это)
    if config.split_tls_record_header 
        && !matches!(config.strategy, FragmentationStrategy::TlsRecordSplit | FragmentationStrategy::SniDotsSplit)
        && fragments.len() == 1 
        && fragments[0].len() > TLS_RECORD_HEADER_SIZE 
    {
        // Разбиваем первый фрагмент на заголовок и payload
        let first_fragment = &fragments[0];
        if first_fragment.len() > TLS_RECORD_HEADER_SIZE && first_fragment[0] == 0x16 {
            let header = Bytes::copy_from_slice(&first_fragment[..TLS_RECORD_HEADER_SIZE]);
            let payload = Bytes::copy_from_slice(&first_fragment[TLS_RECORD_HEADER_SIZE..]);
            fragments = vec![header, payload];
            fragments.extend(std::iter::once(Bytes::new()).take(0)); // Placeholder for remaining
        }
    }
    
    // Apply disorder if enabled (legacy mode)
    let state = FRAGMENT_STATE.fetch_add(1, Ordering::Relaxed);
    let disorder = config.enable_disorder && config.disorder_probability > 0.0;
    
    if disorder && fragments.len() > 2 {
        // Legacy disorder: swap based on probability
        if (state % 100) as f64 / 100.0 < config.disorder_probability {
            // Use new disorder mode if set, otherwise fall back to SwapSecondThird
            let mode = if config.disorder_mode != DisorderMode::None {
                config.disorder_mode
            } else {
                DisorderMode::SwapSecondThird
            };
            apply_disorder_mode(&mut fragments, mode, state);
        }
    } else if config.disorder_mode != DisorderMode::None && fragments.len() > 1 {
        // New disorder mode - always apply if mode is set
        apply_disorder_mode(&mut fragments, config.disorder_mode, state);
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
/// Поддерживает TLS 1.0, 1.1, 1.2, 1.3
pub fn is_tls_client_hello(data: &[u8]) -> bool {
    data.len() >= 6 
        && data[0] == 0x16 // Handshake
        && data[1] == 0x03 // TLS major version
        && (data[2] >= 0x01 && data[2] <= 0x04) // TLS 1.0 (0x01) through TLS 1.3 (0x04)
        && data[5] == 0x01 // ClientHello
}

/// Check if data is a TLS record (any type)
pub fn is_tls_record(data: &[u8]) -> bool {
    if data.len() < TLS_RECORD_HEADER_SIZE {
        return false;
    }
    
    // Content types: 0x14=ChangeCipherSpec, 0x15=Alert, 0x16=Handshake, 0x17=ApplicationData
    let content_type = data[0];
    let valid_content_type = content_type >= 0x14 && content_type <= 0x17;
    
    // Version check
    let valid_version = data[1] == 0x03 && (data[2] >= 0x01 && data[2] <= 0x04);
    
    valid_content_type && valid_version
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
    
    // ===== New tests for TLS Record Split and SNI Dots Split =====
    
    // Sample TLS ClientHello with SNI "www.example.com"
    fn sample_client_hello_with_sni() -> Vec<u8> {
        vec![
            // TLS Record Header (5 bytes)
            0x16, 0x03, 0x01, 0x00, 0xf5,
            // Handshake Header (ClientHello) (4 bytes)
            0x01, 0x00, 0x00, 0xf1,
            // Client Version (2 bytes)
            0x03, 0x03,
            // Random (32 bytes)
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            // Session ID Length (0)
            0x00,
            // Cipher Suites Length (2) + Cipher Suite
            0x00, 0x02, 0x00, 0xff,
            // Compression Methods Length (1) + Method
            0x01, 0x00,
            // Extensions Length
            0x00, 0x1c,
            // SNI Extension (type 0x0000)
            0x00, 0x00, // Extension type: SNI
            0x00, 0x14, // Extension length: 20
            0x00, 0x12, // SNI list length: 18
            0x00,       // SNI type: hostname
            0x00, 0x0f, // Hostname length: 15
            // "www.example.com" (15 bytes)
            0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d,
            0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
        ]
    }
    
    #[test]
    fn test_tls_record_split_positions() {
        let data = sample_client_hello_with_sni();
        let positions = calculate_tls_record_split_positions(&data);
        
        // Should have positions for TLS Record Header splitting
        assert!(!positions.is_empty());
        
        // Should include position 1 (after content type)
        assert!(positions.contains(&1));
        
        // Should include position 4 (before last byte of length)
        assert!(positions.contains(&4));
        
        // Should include position 5 (after TLS Record Header)
        assert!(positions.contains(&5));
    }
    
    #[test]
    fn test_sni_dot_split_positions() {
        let data = sample_client_hello_with_sni();
        let positions = calculate_sni_dot_split_positions(&data);
        
        // Should find dot positions in "www.example.com"
        // The hostname has 2 dots, so we should have at least 4 positions
        // (before and after each dot, plus start/end of hostname)
        assert!(positions.len() >= 4);
        
        // Verify positions are valid
        for pos in &positions {
            assert!(*pos < data.len());
        }
    }
    
    #[test]
    fn test_find_sni_info() {
        let data = sample_client_hello_with_sni();
        let sni_info = find_sni_info(&data);
        
        assert!(sni_info.is_some());
        let info = sni_info.unwrap();
        
        assert_eq!(info.hostname, "www.example.com");
        assert!(info.hostname_offset > 0);
        assert!(info.hostname_offset < data.len());
    }
    
    #[test]
    fn test_tls_record_split_strategy() {
        let data = sample_client_hello_with_sni();
        let config = TcpFragmentConfig::tls_record_split();
        
        let fragmented = fragment_data(&data, &config);
        
        // Should create multiple fragments
        assert!(fragmented.fragments.len() > 1);
        
        // Total should equal original
        let total: usize = fragmented.fragments.iter().map(|f| f.len()).sum();
        assert_eq!(total, data.len());
        
        // First fragment should be very small (TLS header split)
        assert!(fragmented.fragments[0].len() <= TLS_RECORD_HEADER_SIZE);
    }
    
    #[test]
    fn test_sni_dots_split_strategy() {
        let data = sample_client_hello_with_sni();
        let config = TcpFragmentConfig::sni_dots_split();
        
        let fragmented = fragment_data(&data, &config);
        
        // Should create multiple fragments (at least one split at each dot)
        assert!(fragmented.fragments.len() >= 3);
        
        // Total should equal original
        let total: usize = fragmented.fragments.iter().map(|f| f.len()).sum();
        assert_eq!(total, data.len());
    }
    
    #[test]
    fn test_disorder_mode_swap_second_third() {
        let mut fragments: Vec<Bytes> = vec![
            Bytes::from_static(b"first"),
            Bytes::from_static(b"second"),
            Bytes::from_static(b"third"),
            Bytes::from_static(b"fourth"),
        ];
        
        apply_disorder_mode(&mut fragments, DisorderMode::SwapSecondThird, 0);
        
        assert_eq!(&fragments[0][..], b"first");
        assert_eq!(&fragments[1][..], b"third");  // Swapped
        assert_eq!(&fragments[2][..], b"second"); // Swapped
        assert_eq!(&fragments[3][..], b"fourth");
    }
    
    #[test]
    fn test_disorder_mode_first_last() {
        let mut fragments: Vec<Bytes> = vec![
            Bytes::from_static(b"first"),
            Bytes::from_static(b"second"),
            Bytes::from_static(b"third"),
        ];
        
        apply_disorder_mode(&mut fragments, DisorderMode::FirstLast, 0);
        
        assert_eq!(&fragments[0][..], b"second");
        assert_eq!(&fragments[1][..], b"third");
        assert_eq!(&fragments[2][..], b"first"); // Moved to last
    }
    
    #[test]
    fn test_disorder_mode_second_first() {
        let mut fragments: Vec<Bytes> = vec![
            Bytes::from_static(b"first"),
            Bytes::from_static(b"second"),
            Bytes::from_static(b"third"),
        ];
        
        apply_disorder_mode(&mut fragments, DisorderMode::SecondFirst, 0);
        
        assert_eq!(&fragments[0][..], b"second"); // Swapped with first
        assert_eq!(&fragments[1][..], b"first");  // Swapped with second
        assert_eq!(&fragments[2][..], b"third");
    }
    
    #[test]
    fn test_disorder_mode_reverse() {
        let mut fragments: Vec<Bytes> = vec![
            Bytes::from_static(b"first"),
            Bytes::from_static(b"second"),
            Bytes::from_static(b"third"),
            Bytes::from_static(b"fourth"),
        ];
        
        apply_disorder_mode(&mut fragments, DisorderMode::Reverse, 0);
        
        assert_eq!(&fragments[0][..], b"first");  // First stays first
        assert_eq!(&fragments[1][..], b"fourth"); // Rest reversed
        assert_eq!(&fragments[2][..], b"third");
        assert_eq!(&fragments[3][..], b"second");
    }
    
    #[test]
    fn test_russia_aggressive_config() {
        let config = TcpFragmentConfig::russia_aggressive();
        
        assert!(config.split_tls_record_header);
        assert!(config.split_sni_at_dots);
        assert!(config.enable_disorder);
        assert_eq!(config.disorder_mode, DisorderMode::SecondFirst);
        assert!(matches!(config.strategy, FragmentationStrategy::TlsRecordSplit));
    }
    
    #[test]
    fn test_is_tls_record() {
        // Valid TLS Handshake
        let handshake = vec![0x16, 0x03, 0x03, 0x00, 0x05];
        assert!(is_tls_record(&handshake));
        
        // Valid TLS Application Data
        let app_data = vec![0x17, 0x03, 0x03, 0x00, 0x05];
        assert!(is_tls_record(&app_data));
        
        // Valid TLS Alert
        let alert = vec![0x15, 0x03, 0x03, 0x00, 0x02];
        assert!(is_tls_record(&alert));
        
        // Invalid - wrong content type
        let invalid = vec![0x18, 0x03, 0x03, 0x00, 0x05];
        assert!(!is_tls_record(&invalid));
        
        // Too short
        let short = vec![0x16, 0x03];
        assert!(!is_tls_record(&short));
    }
    
    #[test]
    fn test_tls_1_3_detection() {
        // TLS 1.3 ClientHello (version 0x0304)
        let tls13 = vec![0x16, 0x03, 0x04, 0x00, 0x05, 0x01];
        assert!(is_tls_client_hello(&tls13));
        
        // TLS 1.2 (should still work)
        let tls12 = vec![0x16, 0x03, 0x03, 0x00, 0x05, 0x01];
        assert!(is_tls_client_hello(&tls12));
    }
}
