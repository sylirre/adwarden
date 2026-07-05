//! A capacity-bounded, LRU-evicting map keyed by the connection 5-tuple.
//!
//! P1-A caches the per-flow upstream socket here; P1-D caches the resolved UID
//! and firewall verdict so the (relatively expensive) `getConnectionOwnerUid`
//! upcall happens once per connection rather than per packet.

use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub proto: u8,
    pub src: IpAddr,
    pub src_port: u16,
    pub dst: IpAddr,
    pub dst_port: u16,
}

impl FlowKey {
    pub fn new(proto: u8, src: IpAddr, src_port: u16, dst: IpAddr, dst_port: u16) -> Self {
        FlowKey { proto, src, src_port, dst, dst_port }
    }
}

struct Entry<V> {
    value: V,
    last_used: u64,
}

/// LRU map. `tick` is a monotonic logical clock the caller advances; eviction
/// removes the least-recently-touched entry when `capacity` is exceeded.
pub struct FlowTable<V> {
    map: HashMap<FlowKey, Entry<V>>,
    capacity: usize,
    tick: u64,
}

impl<V> FlowTable<V> {
    pub fn new(capacity: usize) -> Self {
        FlowTable { map: HashMap::new(), capacity: capacity.max(1), tick: 0 }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    fn next_tick(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }

    /// Fetch a value, marking it most-recently-used.
    pub fn get(&mut self, key: &FlowKey) -> Option<&V> {
        let t = self.next_tick();
        let entry = self.map.get_mut(key)?;
        entry.last_used = t;
        Some(&entry.value)
    }

    pub fn contains(&self, key: &FlowKey) -> bool {
        self.map.contains_key(key)
    }

    /// Insert or replace, evicting the LRU entry first if at capacity.
    pub fn insert(&mut self, key: FlowKey, value: V) {
        let t = self.next_tick();
        if !self.map.contains_key(&key) && self.map.len() >= self.capacity {
            self.evict_lru();
        }
        self.map.insert(key, Entry { value, last_used: t });
    }

    pub fn remove(&mut self, key: &FlowKey) -> Option<V> {
        self.map.remove(key).map(|e| e.value)
    }

    /// Drop entries for which `keep` returns false.
    pub fn retain(&mut self, mut keep: impl FnMut(&FlowKey, &V) -> bool) {
        self.map.retain(|k, e| keep(k, &e.value));
    }

    fn evict_lru(&mut self) {
        if let Some(key) = self
            .map
            .iter()
            .min_by_key(|(_, e)| e.last_used)
            .map(|(k, _)| *k)
        {
            self.map.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(port: u16) -> FlowKey {
        FlowKey::new(6, "10.0.0.2".parse().unwrap(), port, "1.1.1.1".parse().unwrap(), 443)
    }

    #[test]
    fn insert_get_remove() {
        let mut t = FlowTable::new(8);
        t.insert(key(1), "a");
        assert_eq!(t.get(&key(1)), Some(&"a"));
        assert!(t.contains(&key(1)));
        assert_eq!(t.remove(&key(1)), Some("a"));
        assert!(t.is_empty());
    }

    #[test]
    fn evicts_least_recently_used() {
        let mut t = FlowTable::new(2);
        t.insert(key(1), 1);
        t.insert(key(2), 2);
        // Touch key(1) so key(2) becomes the LRU.
        let _ = t.get(&key(1));
        t.insert(key(3), 3); // over capacity -> evict key(2)
        assert!(t.contains(&key(1)));
        assert!(!t.contains(&key(2)));
        assert!(t.contains(&key(3)));
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn retain_drops_matching() {
        let mut t = FlowTable::new(8);
        t.insert(key(1), 1);
        t.insert(key(2), 2);
        t.retain(|_, v| *v != 1);
        assert!(!t.contains(&key(1)));
        assert!(t.contains(&key(2)));
    }
}
