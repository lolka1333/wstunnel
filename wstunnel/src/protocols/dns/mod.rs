mod cache;
#[allow(dead_code)] // Ready for future EDNS padding integration
mod padding;
mod resolver;

pub use cache::DnsCache;
pub use resolver::DnsResolver;
