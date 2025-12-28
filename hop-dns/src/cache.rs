//! DNS response caching with TTL expiration
//!
//! Provides an LRU cache that stores DNS responses and automatically
//! expires them based on the TTL in the DNS response.

use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, Query};
use hickory_proto::rr::RecordType;
use lru::LruCache;

/// Default maximum number of cache entries
pub const DEFAULT_MAX_ENTRIES: usize = 1000;

/// Minimum TTL to use for caching (prevents cache churn)
pub const MIN_TTL_SECS: u64 = 30;

/// Maximum TTL to use for caching (prevents stale entries)
pub const MAX_TTL_SECS: u64 = 86400; // 24 hours

/// Cache key for DNS queries
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheKey {
    /// Domain name (lowercased)
    name: String,
    /// Record type (A, AAAA, etc.)
    record_type: RecordType,
}

impl Hash for CacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        u16::from(self.record_type).hash(state);
    }
}

impl CacheKey {
    /// Create a new cache key from a DNS query
    pub fn from_query(query: &Query) -> Self {
        Self {
            name: query.name().to_string().to_lowercase(),
            record_type: query.query_type(),
        }
    }
}

/// Cached DNS response
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// The DNS response message (serialized)
    pub response: Vec<u8>,
    /// When this entry expires
    pub expires_at: Instant,
    /// When this entry was inserted (for diagnostics)
    #[allow(dead_code)]
    pub inserted_at: Instant,
}

impl CacheEntry {
    /// Create a new cache entry
    pub fn new(response: Vec<u8>, ttl: Duration) -> Self {
        let now = Instant::now();
        Self {
            response,
            expires_at: now + ttl,
            inserted_at: now,
        }
    }

    /// Check if this entry has expired
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Get the remaining TTL (for diagnostics)
    #[allow(dead_code)]
    pub fn remaining_ttl(&self) -> Duration {
        self.expires_at.saturating_duration_since(Instant::now())
    }
}

/// DNS cache statistics
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Number of cache hits
    pub hits: u64,
    /// Number of cache misses
    pub misses: u64,
    /// Number of expired entries removed
    pub expired: u64,
    /// Current number of entries in cache
    pub entries: usize,
}

/// DNS response cache with TTL expiration
pub struct DnsCache {
    /// LRU cache storing entries
    cache: LruCache<CacheKey, CacheEntry>,
    /// Cache statistics
    stats: CacheStats,
}

impl DnsCache {
    /// Create a new DNS cache with the given maximum capacity
    pub fn new(max_entries: usize) -> Self {
        Self {
            cache: LruCache::new(
                std::num::NonZeroUsize::new(max_entries)
                    .unwrap_or(std::num::NonZeroUsize::new(DEFAULT_MAX_ENTRIES).unwrap()),
            ),
            stats: CacheStats::default(),
        }
    }

    /// Get a cached response for the given query
    ///
    /// Returns `None` if not found or expired
    pub fn get(&mut self, query: &Query) -> Option<Vec<u8>> {
        let key = CacheKey::from_query(query);

        if let Some(entry) = self.cache.get(&key) {
            if entry.is_expired() {
                // Remove expired entry
                self.cache.pop(&key);
                self.stats.expired += 1;
                self.stats.misses += 1;
                None
            } else {
                self.stats.hits += 1;
                Some(entry.response.clone())
            }
        } else {
            self.stats.misses += 1;
            None
        }
    }

    /// Insert a DNS response into the cache
    ///
    /// Extracts the TTL from the DNS response and uses it for expiration.
    /// If no TTL is found, the entry is not cached.
    pub fn insert(&mut self, query: &Query, response: &[u8]) {
        // Parse the response to extract TTL
        let ttl = match extract_min_ttl(response) {
            Some(ttl) => ttl,
            None => return, // Don't cache if we can't determine TTL
        };

        // Clamp TTL to reasonable bounds
        let ttl = ttl.clamp(MIN_TTL_SECS, MAX_TTL_SECS);

        let key = CacheKey::from_query(query);
        let entry = CacheEntry::new(response.to_vec(), Duration::from_secs(ttl));

        self.cache.put(key, entry);
        self.stats.entries = self.cache.len();
    }

    /// Clear all entries from the cache
    pub fn clear(&mut self) {
        self.cache.clear();
        self.stats.entries = 0;
    }

    /// Get current cache statistics
    pub fn stats(&self) -> &CacheStats {
        &self.stats
    }

    /// Get the number of entries in the cache
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Remove expired entries from the cache
    ///
    /// This is called periodically to clean up stale entries.
    pub fn cleanup_expired(&mut self) -> usize {
        let expired_keys: Vec<CacheKey> = self
            .cache
            .iter()
            .filter(|(_, entry)| entry.is_expired())
            .map(|(key, _)| key.clone())
            .collect();

        let count = expired_keys.len();
        for key in expired_keys {
            self.cache.pop(&key);
        }

        self.stats.expired += count as u64;
        self.stats.entries = self.cache.len();
        count
    }
}

/// Extract the minimum TTL from a DNS response
///
/// Returns `None` if the response cannot be parsed or contains no records.
fn extract_min_ttl(response: &[u8]) -> Option<u64> {
    let message = Message::from_vec(response).ok()?;

    let mut min_ttl: Option<u64> = None;

    // Check all answer records
    for record in message.answers() {
        let ttl = record.ttl() as u64;
        min_ttl = Some(min_ttl.map_or(ttl, |m| m.min(ttl)));
    }

    // Also check authority and additional sections
    for record in message.name_servers() {
        let ttl = record.ttl() as u64;
        min_ttl = Some(min_ttl.map_or(ttl, |m| m.min(ttl)));
    }

    // If no records found, use a default TTL for negative caching
    if min_ttl.is_none() && message.response_code() == hickory_proto::op::ResponseCode::NXDomain {
        // Negative cache for 60 seconds
        min_ttl = Some(60);
    }

    min_ttl
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::Name;
    use std::str::FromStr;

    fn make_query(name: &str, rtype: RecordType) -> Query {
        Query::query(Name::from_str(name).unwrap(), rtype)
    }

    #[test]
    fn test_cache_key_case_insensitive() {
        let q1 = make_query("Example.COM", RecordType::A);
        let q2 = make_query("example.com", RecordType::A);

        let key1 = CacheKey::from_query(&q1);
        let key2 = CacheKey::from_query(&q2);

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_cache_miss() {
        let mut cache = DnsCache::new(100);
        let query = make_query("example.com", RecordType::A);

        assert!(cache.get(&query).is_none());
        assert_eq!(cache.stats().misses, 1);
    }

    #[test]
    fn test_cache_entry_expiration() {
        let entry = CacheEntry::new(vec![1, 2, 3], Duration::from_millis(1));
        assert!(!entry.is_expired());

        std::thread::sleep(Duration::from_millis(10));
        assert!(entry.is_expired());
    }

    #[test]
    fn test_cache_lru_eviction() {
        let mut cache = DnsCache::new(2);

        let q1 = make_query("one.com", RecordType::A);
        let q2 = make_query("two.com", RecordType::A);
        let q3 = make_query("three.com", RecordType::A);

        // Insert dummy responses (won't be cached without proper TTL)
        // For this test, we manually insert entries
        cache.cache.put(
            CacheKey::from_query(&q1),
            CacheEntry::new(vec![1], Duration::from_secs(60)),
        );
        cache.cache.put(
            CacheKey::from_query(&q2),
            CacheEntry::new(vec![2], Duration::from_secs(60)),
        );

        assert_eq!(cache.len(), 2);

        // Insert third entry, should evict first (LRU)
        cache.cache.put(
            CacheKey::from_query(&q3),
            CacheEntry::new(vec![3], Duration::from_secs(60)),
        );

        assert_eq!(cache.len(), 2);
        assert!(cache.cache.get(&CacheKey::from_query(&q1)).is_none());
    }
}
