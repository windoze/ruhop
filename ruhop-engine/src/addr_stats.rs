//! Address statistics tracking for packet loss detection
//!
//! This module tracks probe responses per server address to detect blocked or lossy
//! network paths. Addresses with high packet loss are temporarily blacklisted.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Statistics for a single server address
#[derive(Debug)]
struct AddrStats {
    /// Total probes sent to this address
    probes_sent: u32,
    /// Total probe responses received from this address
    probes_received: u32,
    /// Time of last probe sent
    last_probe_time: Option<Instant>,
    /// Time of last response received
    last_response_time: Option<Instant>,
    /// Blacklisted until this time (None = not blacklisted)
    blacklisted_until: Option<Instant>,
    /// Rolling window of RTT samples (for future use)
    rtt_samples: VecDeque<Duration>,
    /// Pending probes: probe_id -> (send_time, target_addr)
    pending_probes: HashMap<u32, Instant>,
}

impl AddrStats {
    fn new() -> Self {
        Self {
            probes_sent: 0,
            probes_received: 0,
            last_probe_time: None,
            last_response_time: None,
            blacklisted_until: None,
            rtt_samples: VecDeque::with_capacity(10),
            pending_probes: HashMap::new(),
        }
    }

    fn loss_rate(&self) -> f32 {
        if self.probes_sent == 0 {
            return 0.0;
        }
        1.0 - (self.probes_received as f32 / self.probes_sent as f32)
    }

    fn is_blacklisted(&self) -> bool {
        self.blacklisted_until
            .map(|t| Instant::now() < t)
            .unwrap_or(false)
    }

    fn add_rtt_sample(&mut self, rtt: Duration) {
        if self.rtt_samples.len() >= 10 {
            self.rtt_samples.pop_front();
        }
        self.rtt_samples.push_back(rtt);
    }
}

/// Callback for blacklist state changes
pub type BlacklistCallback = Box<dyn Fn(SocketAddr, bool, f32) + Send + Sync>;

/// Tracks probe statistics for all server addresses
pub struct AddrStatsTracker {
    /// Per-address statistics
    stats: HashMap<SocketAddr, AddrStats>,
    /// All known addresses (for round-robin probing)
    all_addrs: Vec<SocketAddr>,
    /// Next address index to probe
    next_probe_idx: usize,
    /// Minimum interval between probes to the same address
    probe_interval: Duration,
    /// Loss rate threshold for blacklisting (0.0 - 1.0)
    blacklist_threshold: f32,
    /// Duration to keep an address blacklisted
    blacklist_duration: Duration,
    /// Minimum probes before making blacklist decision
    min_probes: u32,
    /// Callback when blacklist state changes
    blacklist_callback: Option<BlacklistCallback>,
}

impl AddrStatsTracker {
    /// Create a new tracker with the given configuration
    pub fn new(
        addrs: Vec<SocketAddr>,
        probe_interval: Duration,
        blacklist_threshold: f32,
        blacklist_duration: Duration,
        min_probes: u32,
    ) -> Self {
        let mut stats = HashMap::new();
        for addr in &addrs {
            stats.insert(*addr, AddrStats::new());
        }

        Self {
            stats,
            all_addrs: addrs,
            next_probe_idx: 0,
            probe_interval,
            blacklist_threshold,
            blacklist_duration,
            min_probes,
            blacklist_callback: None,
        }
    }

    /// Set callback for blacklist state changes
    /// Callback receives: (addr, is_blacklisted, loss_rate)
    pub fn set_blacklist_callback(&mut self, callback: BlacklistCallback) {
        self.blacklist_callback = Some(callback);
    }

    /// Get addresses that are available for sending (not blacklisted)
    pub fn available_addrs(&self) -> Vec<SocketAddr> {
        self.all_addrs
            .iter()
            .filter(|addr| {
                self.stats
                    .get(*addr)
                    .map(|s| !s.is_blacklisted())
                    .unwrap_or(true)
            })
            .copied()
            .collect()
    }

    /// Check if any addresses are blacklisted
    pub fn has_blacklisted(&self) -> bool {
        self.stats.values().any(|s| s.is_blacklisted())
    }

    /// Get the next address to probe (round-robin through all addresses)
    /// Returns None if no address is ready to be probed (all recently probed)
    pub fn next_probe_target(&mut self) -> Option<SocketAddr> {
        if self.all_addrs.is_empty() {
            return None;
        }

        let now = Instant::now();
        let start_idx = self.next_probe_idx;

        // Round-robin through addresses to find one that's ready
        loop {
            let addr = self.all_addrs[self.next_probe_idx];
            self.next_probe_idx = (self.next_probe_idx + 1) % self.all_addrs.len();

            if let Some(stats) = self.stats.get(&addr) {
                let should_probe = stats
                    .last_probe_time
                    .map(|t| now.duration_since(t) >= self.probe_interval)
                    .unwrap_or(true);

                if should_probe {
                    return Some(addr);
                }
            }

            // Checked all addresses
            if self.next_probe_idx == start_idx {
                return None;
            }
        }
    }

    /// Record that a probe was sent to an address
    pub fn record_probe_sent(&mut self, addr: SocketAddr, probe_id: u32) {
        if let Some(stats) = self.stats.get_mut(&addr) {
            stats.probes_sent += 1;
            stats.last_probe_time = Some(Instant::now());
            stats.pending_probes.insert(probe_id, Instant::now());

            // Cleanup old pending probes (older than 30 seconds)
            let cutoff = Instant::now() - Duration::from_secs(30);
            stats.pending_probes.retain(|_, time| *time > cutoff);
        }
    }

    /// Record that a probe response was received
    /// Note: peer_addr may differ from the address we sent to (NAT, multi-homing)
    /// So we look up by probe_id across all addresses
    pub fn record_probe_received(&mut self, probe_id: u32, rtt: Duration) {
        // Find which address this probe was sent to
        let mut found_addr = None;
        for (addr, stats) in self.stats.iter() {
            if stats.pending_probes.contains_key(&probe_id) {
                found_addr = Some(*addr);
                break;
            }
        }

        if let Some(addr) = found_addr {
            let was_blacklisted = self
                .stats
                .get(&addr)
                .map(|s| s.is_blacklisted())
                .unwrap_or(false);

            if let Some(stats) = self.stats.get_mut(&addr) {
                stats.probes_received += 1;
                stats.last_response_time = Some(Instant::now());
                stats.pending_probes.remove(&probe_id);
                stats.add_rtt_sample(rtt);

                // Check if we should un-blacklist
                if was_blacklisted {
                    self.update_blacklist_status(addr);
                }
            }
        }
    }

    /// Update blacklist status for an address based on current loss rate
    fn update_blacklist_status(&mut self, addr: SocketAddr) {
        let (should_blacklist, loss_rate, was_blacklisted) = {
            let stats = match self.stats.get(&addr) {
                Some(s) => s,
                None => return,
            };

            let was_blacklisted = stats.is_blacklisted();
            let loss_rate = stats.loss_rate();

            // Don't make decisions until we have enough probes
            if stats.probes_sent < self.min_probes {
                return;
            }

            let should_blacklist = loss_rate >= self.blacklist_threshold;
            (should_blacklist, loss_rate, was_blacklisted)
        };

        // Apply blacklist change
        if let Some(stats) = self.stats.get_mut(&addr) {
            if should_blacklist && !was_blacklisted {
                stats.blacklisted_until = Some(Instant::now() + self.blacklist_duration);
                log::warn!(
                    "Blacklisting address {} (loss rate: {:.1}%)",
                    addr,
                    loss_rate * 100.0
                );
                if let Some(ref cb) = self.blacklist_callback {
                    cb(addr, true, loss_rate);
                }
            } else if !should_blacklist && was_blacklisted {
                stats.blacklisted_until = None;
                log::info!(
                    "Recovered address {} (loss rate: {:.1}%)",
                    addr,
                    loss_rate * 100.0
                );
                if let Some(ref cb) = self.blacklist_callback {
                    cb(addr, false, loss_rate);
                }
            }
        }
    }

    /// Periodically check and update blacklist status for all addresses
    /// Should be called after processing probe responses
    pub fn update_all_blacklist_status(&mut self) {
        let addrs: Vec<_> = self.all_addrs.clone();
        for addr in addrs {
            self.update_blacklist_status(addr);
        }
    }

    /// Get statistics summary for logging/debugging
    pub fn summary(&self) -> Vec<(SocketAddr, u32, u32, f32, bool)> {
        self.all_addrs
            .iter()
            .filter_map(|addr| {
                self.stats.get(addr).map(|s| {
                    (
                        *addr,
                        s.probes_sent,
                        s.probes_received,
                        s.loss_rate(),
                        s.is_blacklisted(),
                    )
                })
            })
            .collect()
    }

    /// Reset statistics (e.g., on reconnect)
    pub fn reset(&mut self) {
        for stats in self.stats.values_mut() {
            stats.probes_sent = 0;
            stats.probes_received = 0;
            stats.last_probe_time = None;
            stats.last_response_time = None;
            stats.blacklisted_until = None;
            stats.rtt_samples.clear();
            stats.pending_probes.clear();
        }
        self.next_probe_idx = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    #[test]
    fn test_basic_tracking() {
        let addrs = vec![make_addr(1000), make_addr(1001), make_addr(1002)];
        let mut tracker = AddrStatsTracker::new(
            addrs.clone(),
            Duration::from_millis(100),
            0.5,
            Duration::from_secs(60),
            3,
        );

        // Initially all addresses available
        assert_eq!(tracker.available_addrs().len(), 3);

        // Record probes
        tracker.record_probe_sent(addrs[0], 1);
        tracker.record_probe_sent(addrs[0], 2);
        tracker.record_probe_sent(addrs[0], 3);

        // Record one response
        tracker.record_probe_received(1, Duration::from_millis(10));

        // 1/3 received = 66% loss, should be blacklisted
        tracker.update_all_blacklist_status();
        assert_eq!(tracker.available_addrs().len(), 2);
        assert!(tracker.has_blacklisted());
    }

    #[test]
    fn test_no_blacklist_before_min_probes() {
        let addrs = vec![make_addr(2000)];
        let mut tracker = AddrStatsTracker::new(
            addrs.clone(),
            Duration::from_millis(100),
            0.5,
            Duration::from_secs(60),
            5, // Need 5 probes
        );

        // Send 3 probes, no responses (100% loss)
        tracker.record_probe_sent(addrs[0], 1);
        tracker.record_probe_sent(addrs[0], 2);
        tracker.record_probe_sent(addrs[0], 3);

        // Should NOT be blacklisted yet (only 3 < 5 min_probes)
        tracker.update_all_blacklist_status();
        assert_eq!(tracker.available_addrs().len(), 1);
    }

    #[test]
    fn test_round_robin_probing() {
        let addrs = vec![make_addr(3000), make_addr(3001), make_addr(3002)];
        let mut tracker = AddrStatsTracker::new(
            addrs.clone(),
            Duration::from_millis(0), // No delay for testing
            0.5,
            Duration::from_secs(60),
            3,
        );

        // Should cycle through addresses
        assert_eq!(tracker.next_probe_target(), Some(addrs[0]));
        assert_eq!(tracker.next_probe_target(), Some(addrs[1]));
        assert_eq!(tracker.next_probe_target(), Some(addrs[2]));
        assert_eq!(tracker.next_probe_target(), Some(addrs[0]));
    }

    #[test]
    fn test_probe_interval_respected() {
        let addrs = vec![make_addr(4000)];
        let mut tracker = AddrStatsTracker::new(
            addrs.clone(),
            Duration::from_secs(10), // Long interval
            0.5,
            Duration::from_secs(60),
            3,
        );

        // First probe should be available
        let target = tracker.next_probe_target();
        assert_eq!(target, Some(addrs[0]));
        tracker.record_probe_sent(addrs[0], 1);

        // Immediately after, should return None (interval not passed)
        assert_eq!(tracker.next_probe_target(), None);
    }

    #[test]
    fn test_loss_rate_calculation() {
        let addrs = vec![make_addr(5000)];
        let mut tracker = AddrStatsTracker::new(
            addrs.clone(),
            Duration::from_millis(0),
            0.5,
            Duration::from_secs(60),
            4,
        );

        // Send 4 probes
        for i in 0..4 {
            tracker.record_probe_sent(addrs[0], i);
        }

        // Receive 2 responses (50% loss)
        tracker.record_probe_received(0, Duration::from_millis(10));
        tracker.record_probe_received(1, Duration::from_millis(10));

        let summary = tracker.summary();
        assert_eq!(summary[0].1, 4); // probes_sent
        assert_eq!(summary[0].2, 2); // probes_received
        assert!((summary[0].3 - 0.5).abs() < 0.01); // loss_rate ~= 0.5
    }

    #[test]
    fn test_reset() {
        let addrs = vec![make_addr(6000)];
        let mut tracker = AddrStatsTracker::new(
            addrs.clone(),
            Duration::from_millis(0),
            0.5,
            Duration::from_secs(60),
            3,
        );

        // Add some data
        tracker.record_probe_sent(addrs[0], 1);
        tracker.record_probe_sent(addrs[0], 2);
        tracker.record_probe_sent(addrs[0], 3);

        // Reset
        tracker.reset();

        let summary = tracker.summary();
        assert_eq!(summary[0].1, 0); // probes_sent reset
        assert_eq!(summary[0].2, 0); // probes_received reset
    }
}
