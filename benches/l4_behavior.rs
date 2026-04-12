use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use waf::config::L4Config;
use waf::core::{PacketInfo, Protocol};
use waf::l4::behavior::L4BehaviorEngine;
use waf::protocol::{HttpVersion, UnifiedHttpRequest};

fn packet() -> PacketInfo {
    PacketInfo {
        source_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 24)),
        dest_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
        source_port: 41000,
        dest_port: 443,
        protocol: Protocol::TCP,
        timestamp: 1,
    }
}

fn request() -> UnifiedHttpRequest {
    let mut request = UnifiedHttpRequest::new(
        HttpVersion::Http2_0,
        "GET".to_string(),
        "/bench?mode=adaptive".to_string(),
    );
    request.add_header("host".to_string(), "bench.example".to_string());
    request.add_header("user-agent".to_string(), "criterion".to_string());
    request.add_metadata("tls.sni".to_string(), "bench.example".to_string());
    request.add_metadata("tls.alpn".to_string(), "h2".to_string());
    request.add_metadata("transport".to_string(), "tls".to_string());
    request
}

fn bench_l4_behavior(c: &mut Criterion) {
    let mut config = L4Config::default();
    config.max_tracked_ips = 8_192;
    config.behavior_event_channel_capacity = 16_384;
    let engine = L4BehaviorEngine::new(&config);
    let packet = packet();
    let counter = AtomicU64::new(0);

    for idx in 0..256 {
        let _ = engine.observe_connection_open(
            format!("warmup-{idx}"),
            &packet,
            Some("bench.example"),
            Some("h2"),
            "tls",
            "h2",
        );
    }

    c.bench_function("l4_behavior_apply_request_policy", |b| {
        b.iter(|| {
            let mut request = request();
            let policy = engine.apply_request_policy(&packet, &mut request);
            black_box(policy.suggested_delay_ms);
            black_box(request.metadata.len());
        });
    });

    c.bench_function("l4_behavior_observe_connection_open", |b| {
        b.iter(|| {
            let seq = counter.fetch_add(1, Ordering::Relaxed);
            let key = engine.observe_connection_open(
                format!("bench-{seq}"),
                &packet,
                Some("bench.example"),
                Some("h2"),
                "tls",
                "h2",
            );
            black_box(key);
        });
    });
}

criterion_group!(benches, bench_l4_behavior);
criterion_main!(benches);
