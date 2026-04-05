use crate::config::L4Config;
use log::info;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub struct ConnectionTracker {
    max_tracked_ips: usize,
    total_connections: AtomicU64,
    peers: Mutex<HashMap<IpAddr, TrackedPeer>>,
}

#[derive(Debug, Clone)]
struct TrackedPeer {
    last_seen: Instant,
    recent_connections: VecDeque<Instant>,
    recent_ports: HashMap<u16, Instant>,
}

impl ConnectionTracker {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing Connection Tracker");
        Self {
            max_tracked_ips: config.max_tracked_ips.max(1),
            total_connections: AtomicU64::new(0),
            peers: Mutex::new(HashMap::new()),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("Connection Tracker started");
        Ok(())
    }

    pub fn track(&self, packet: &crate::core::PacketInfo) {
        let now = Instant::now();
        let mut peers = self.peers.lock().expect("peers mutex poisoned");
        self.ensure_capacity(&mut peers, packet.source_ip);

        let peer = peers
            .entry(packet.source_ip)
            .or_insert_with(|| TrackedPeer::new(now));
        peer.record(packet.dest_port, now);

        self.total_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_total_connections(&self) -> u64 {
        self.total_connections.load(Ordering::Relaxed)
    }

    pub fn get_active_connections(&self) -> u64 {
        self.peers.lock().expect("peers mutex poisoned").len() as u64
    }

    pub fn recent_connection_count(&self, ip: &IpAddr, window: Duration) -> usize {
        let now = Instant::now();
        let mut peers = self.peers.lock().expect("peers mutex poisoned");
        let Some(peer) = peers.get_mut(ip) else {
            return 0;
        };

        peer.prune(now, window);
        peer.recent_connections.len()
    }

    pub fn unique_destination_ports(&self, ip: &IpAddr, window: Duration) -> usize {
        let now = Instant::now();
        let mut peers = self.peers.lock().expect("peers mutex poisoned");
        let Some(peer) = peers.get_mut(ip) else {
            return 0;
        };

        peer.prune(now, window);
        peer.recent_ports.len()
    }

    pub fn cleanup_inactive(&self, timeout: Duration) {
        let now = Instant::now();
        let mut peers = self.peers.lock().expect("peers mutex poisoned");
        let old_active = peers.len();
        peers.retain(|_, peer| {
            peer.prune(now, timeout);
            now.duration_since(peer.last_seen) < timeout
        });

        let removed = old_active.saturating_sub(peers.len());
        if removed > 0 {
            info!("Cleaned up {} inactive connection peers", removed);
        }
    }

    fn ensure_capacity(&self, peers: &mut HashMap<IpAddr, TrackedPeer>, current_ip: IpAddr) {
        if peers.len() < self.max_tracked_ips || peers.contains_key(&current_ip) {
            return;
        }

        if let Some(stalest_ip) = peers
            .iter()
            .min_by_key(|(_, peer)| peer.last_seen)
            .map(|(ip, _)| *ip)
        {
            peers.remove(&stalest_ip);
        }
    }
}

impl TrackedPeer {
    fn new(now: Instant) -> Self {
        Self {
            last_seen: now,
            recent_connections: VecDeque::new(),
            recent_ports: HashMap::new(),
        }
    }

    fn record(&mut self, dest_port: u16, now: Instant) {
        self.last_seen = now;
        self.recent_connections.push_back(now);
        self.recent_ports.insert(dest_port, now);
    }

    fn prune(&mut self, now: Instant, window: Duration) {
        while let Some(ts) = self.recent_connections.front() {
            if now.duration_since(*ts) > window {
                self.recent_connections.pop_front();
            } else {
                break;
            }
        }

        self.recent_ports
            .retain(|_, seen_at| now.duration_since(*seen_at) <= window);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{PacketInfo, Protocol};
    use std::net::{IpAddr, Ipv4Addr};

    fn packet(source_octet: u8, dest_port: u16) -> PacketInfo {
        PacketInfo {
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, source_octet)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            source_port: 40_000,
            dest_port,
            protocol: Protocol::TCP,
            timestamp: 0,
        }
    }

    #[test]
    fn tracker_counts_recent_connections_and_ports() {
        let tracker = ConnectionTracker::new(L4Config {
            max_tracked_ips: 8,
            ..L4Config::default()
        });
        let packet = packet(10, 8080);

        tracker.track(&packet);
        tracker.track(&packet);

        assert_eq!(
            tracker.recent_connection_count(&packet.source_ip, Duration::from_secs(1)),
            2
        );
        assert_eq!(
            tracker.unique_destination_ports(&packet.source_ip, Duration::from_secs(30)),
            1
        );
    }

    #[test]
    fn tracker_evicts_stale_entries_when_capacity_is_reached() {
        let tracker = ConnectionTracker::new(L4Config {
            max_tracked_ips: 1,
            ..L4Config::default()
        });
        let first = packet(10, 8080);
        let second = packet(11, 8081);

        tracker.track(&first);
        tracker.track(&second);

        assert_eq!(tracker.get_active_connections(), 1);
        assert_eq!(
            tracker.recent_connection_count(&first.source_ip, Duration::from_secs(1)),
            0
        );
        assert_eq!(
            tracker.recent_connection_count(&second.source_ip, Duration::from_secs(1)),
            1
        );
    }

    #[test]
    fn tracker_keeps_existing_entry_when_capacity_is_full() {
        let tracker = ConnectionTracker::new(L4Config {
            max_tracked_ips: 1,
            ..L4Config::default()
        });
        let only = packet(10, 8080);

        tracker.track(&only);
        tracker.track(&only);

        assert_eq!(tracker.get_active_connections(), 1);
        assert_eq!(
            tracker.recent_connection_count(&only.source_ip, Duration::from_secs(1)),
            2
        );
    }
}
