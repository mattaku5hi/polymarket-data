//! Small bounded in-process TTL cache for read-only adapter metadata lookups.
//!
//! The loader runs without the cache lock held, so an async HTTP lookup can use
//! this directly. Concurrent misses may load the same key more than once; the
//! cache is an optimization and deliberately does not turn a read into a
//! single-flight coordination point.

use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    hash::Hash,
    time::{Duration, Instant},
};

use tokio::sync::Mutex;

/// Reference-bot parity TTL for mutable market metadata.
pub const MARKET_METADATA_CACHE_TTL: Duration = Duration::from_secs(600);

/// A bounded, insertion-ordered TTL cache.
///
/// Expired entries are never returned. When full, insertion evicts the oldest
/// retained key, keeping memory bounded even if a caller sees unbounded keys.
pub struct TtlCache<K, V> {
    ttl: Duration,
    capacity: usize,
    state: Mutex<TtlCacheState<K, V>>,
}

struct TtlCacheState<K, V> {
    entries: HashMap<K, TtlCacheEntry<V>>,
    insertion_order: VecDeque<K>,
}

struct TtlCacheEntry<V> {
    value: V,
    inserted_at: Instant,
}

impl<K, V> TtlCache<K, V>
where
    K: Clone + Eq + Hash,
    V: Clone,
{
    /// Create a cache with `ttl` and a bounded number of retained entries.
    #[must_use]
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            ttl,
            capacity: capacity.max(1),
            state: Mutex::new(TtlCacheState {
                entries: HashMap::with_capacity(capacity.max(1)),
                insertion_order: VecDeque::with_capacity(capacity.max(1)),
            }),
        }
    }

    /// Return a fresh value, if present.
    pub async fn get(&self, key: &K) -> Option<V> {
        let mut state = self.state.lock().await;
        let expired = state
            .entries
            .get(key)
            .is_some_and(|entry| entry.inserted_at.elapsed() >= self.ttl);
        if expired {
            state.entries.remove(key);
            state.insertion_order.retain(|candidate| candidate != key);
            return None;
        }
        state.entries.get(key).map(|entry| entry.value.clone())
    }

    /// Insert a value, evicting the oldest retained key when at capacity.
    pub async fn insert(&self, key: K, value: V) {
        let mut state = self.state.lock().await;
        if state.entries.contains_key(&key) {
            state.insertion_order.retain(|candidate| candidate != &key);
        } else if state.entries.len() == self.capacity {
            if let Some(oldest) = state.insertion_order.pop_front() {
                state.entries.remove(&oldest);
            }
        }
        state.insertion_order.push_back(key.clone());
        state.entries.insert(
            key,
            TtlCacheEntry {
                value,
                inserted_at: Instant::now(),
            },
        );
    }

    /// Return a fresh cached value or load and retain one without holding the
    /// cache lock across the asynchronous loader.
    pub async fn get_or_insert_with<F, Fut>(&self, key: K, loader: F) -> V
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = V>,
    {
        if let Some(value) = self.get(&key).await {
            return value;
        }
        let value = loader().await;
        self.insert(key, value.clone()).await;
        value
    }

    /// Number of retained entries, including entries that have not yet been
    /// observed after expiring.
    pub async fn len(&self) -> usize {
        self.state.lock().await.entries.len()
    }

    /// Whether the cache has no retained entries.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    #[tokio::test]
    async fn reuses_a_fresh_value_without_running_the_loader_again() {
        let cache = TtlCache::new(Duration::from_secs(600), 2);
        let calls = Arc::new(AtomicUsize::new(0));
        for _ in 0..2 {
            let calls = calls.clone();
            assert_eq!(
                cache
                    .get_or_insert_with("market", move || async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        "metadata".to_owned()
                    })
                    .await,
                "metadata"
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn expired_value_runs_the_loader_again() {
        let cache = TtlCache::new(Duration::from_millis(1), 2);
        let calls = Arc::new(AtomicUsize::new(0));
        for (index, expected) in ["first", "second"].into_iter().enumerate() {
            if index == 1 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let calls = calls.clone();
            assert_eq!(
                cache
                    .get_or_insert_with("market", move || async move {
                        let call = calls.fetch_add(1, Ordering::SeqCst);
                        ["first", "second"][call].to_owned()
                    })
                    .await,
                expected
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn evicts_oldest_key_at_capacity() {
        let cache = TtlCache::new(Duration::from_secs(600), 2);
        cache.insert("first", 1).await;
        cache.insert("second", 2).await;
        cache.insert("third", 3).await;
        assert_eq!(cache.get(&"first").await, None);
        assert_eq!(cache.get(&"second").await, Some(2));
        assert_eq!(cache.get(&"third").await, Some(3));
        assert_eq!(cache.len().await, 2);
    }
}
