use super::*;
use serde_json::json;

#[test]
fn extract_sites_supports_nested_data_list() {
    let payload = json!({
        "data": {
            "list": [
                {
                    "uuid": "site-1",
                    "name": "portal",
                    "domain": "portal.example.com",
                    "status": "running"
                }
            ]
        }
    });

    let sites = extract_sites(&payload).unwrap();
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0].id, "site-1");
    assert_eq!(sites[0].name, "portal");
}

#[test]
fn extract_sites_supports_top_level_array() {
    let payload = json!([
        {
            "id": 1,
            "site_name": "api",
            "host": "api.example.com",
            "enabled": true,
            "ports": ["80", "443_ssl"],
            "upstreams": ["http://127.0.0.1:8080"],
            "cert_id": 9
        }
    ]);

    let sites = extract_sites(&payload).unwrap();
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0].id, "1");
    assert_eq!(sites[0].domain, "api.example.com");
    assert_eq!(sites[0].status, "enabled");
    assert_eq!(sites[0].ports, vec!["80", "443_ssl"]);
    assert_eq!(sites[0].ssl_ports, vec!["443_ssl"]);
    assert_eq!(sites[0].upstreams, vec!["http://127.0.0.1:8080"]);
    assert_eq!(sites[0].cert_id, Some(9));
    assert!(sites[0].ssl_enabled);
}

#[test]
fn extract_sites_supports_open_site_payload() {
    let payload = json!({
        "total": 1,
        "data": [
            {
                "id": 7,
                "title": "portal",
                "comment": "portal-comment",
                "server_names": ["portal.example.com", "www.example.com"],
                "ports": ["443_ssl"],
                "upstreams": ["https://127.0.0.1:9443"],
                "cert_type": 2,
                "cert_filename": "portal.crt",
                "key_filename": "portal.key",
                "health_check": true,
                "mode": 0
            }
        ]
    });

    let sites = extract_sites(&payload).unwrap();
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0].id, "7");
    assert_eq!(sites[0].name, "portal");
    assert_eq!(sites[0].domain, "portal.example.com");
    assert_eq!(sites[0].status, "0");
    assert_eq!(
        sites[0].server_names,
        vec!["portal.example.com", "www.example.com"]
    );
    assert_eq!(sites[0].ssl_ports, vec!["443_ssl"]);
    assert_eq!(sites[0].upstreams, vec!["https://127.0.0.1:9443"]);
    assert_eq!(sites[0].cert_type, Some(2));
    assert_eq!(sites[0].cert_filename.as_deref(), Some("portal.crt"));
    assert_eq!(sites[0].key_filename.as_deref(), Some("portal.key"));
    assert_eq!(sites[0].health_check, Some(true));
    assert!(sites[0].ssl_enabled);
}

#[test]
fn extract_sites_supports_nested_data_data_payload() {
    let payload = json!({
        "data": {
            "data": [
                {
                    "id": 13,
                    "title": "2tos",
                    "server_names": ["2tos.cn", "www.2tos.cn"],
                    "is_enabled": true
                }
            ],
            "total": 1
        },
        "err": null,
        "msg": ""
    });

    let sites = extract_sites(&payload).unwrap();
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0].id, "13");
    assert_eq!(sites[0].name, "2tos");
    assert_eq!(sites[0].domain, "2tos.cn");
    assert_eq!(sites[0].enabled, Some(true));
    assert_eq!(sites[0].status, "enabled");
}

#[test]
fn extract_security_events_supports_list_payload() {
    let payload = json!({
        "data": {
            "list": [
                {
                    "src_ip": "203.0.113.10",
                    "dst_ip": "10.0.0.10",
                    "action": "block",
                    "attack_type": "sqli",
                    "uri": "/login",
                    "method": "POST",
                    "created_at": 1710000000
                }
            ]
        }
    });

    let events = extract_security_events(&payload).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, "block");
    assert_eq!(events[0].source_ip, "203.0.113.10");
    assert_eq!(events[0].uri.as_deref(), Some("/login"));
    assert_eq!(events[0].reason, "safeline:sqli:sqli");
}

#[test]
fn extract_security_events_supports_open_records_payload() {
    let payload = json!({
        "total": 1,
        "data": [
            {
                "event_id": "evt-1",
                "src_ip": "2.2.2.2",
                "website": "https://portal.example.com/login",
                "reason": "sqli",
                "attack_type": 4,
                "timestamp": 1710000000,
                "site_id": 99,
                "site_title": "portal",
                "site_server_names": ["portal.example.com"]
            }
        ]
    });

    let events = extract_security_events(&payload).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].provider_site_id.as_deref(), Some("99"));
    assert_eq!(events[0].provider_site_name.as_deref(), Some("portal"));
    assert_eq!(
        events[0].provider_site_domain.as_deref(),
        Some("portal.example.com")
    );
    assert_eq!(events[0].source_ip, "2.2.2.2");
    assert_eq!(events[0].reason, "safeline:4:sqli");
}

#[test]
fn extract_blocked_ips_supports_open_ipgroup_nodes() {
    let payload = json!({
        "total": 1,
        "nodes": [
            {
                "id": 12,
                "reference": "manual",
                "comment": "ops",
                "ips": ["198.51.100.10"],
                "updated_at": "1710000000",
                "builtin": false
            }
        ]
    });

    let ips = extract_blocked_ips(&payload).unwrap();
    assert_eq!(ips.len(), 1);
    assert_eq!(ips[0].ip, "198.51.100.10");
    assert_eq!(ips[0].remote_id.as_deref(), Some("12"));
}

#[test]
fn extract_blocked_ips_supports_nested_open_ipgroup_payload_with_multiple_ips() {
    let payload = json!({
        "data": {
            "nodes": [
                {
                    "id": 7,
                    "comment": "manual",
                    "ips": ["198.51.100.10", "198.51.100.11"],
                    "updated_at": "2026-04-10T01:03:27.134874+08:00"
                }
            ],
            "total": 1
        },
        "err": null,
        "msg": ""
    });

    let ips = extract_blocked_ips(&payload).unwrap();
    assert_eq!(ips.len(), 2);
    assert_eq!(ips[0].ip, "198.51.100.10");
    assert_eq!(ips[1].ip, "198.51.100.11");
    assert_eq!(ips[0].remote_id.as_deref(), Some("7"));
    assert_eq!(ips[0].reason, "safeline:manual");
    assert_eq!(ips[0].blocked_at, 1775754207);
}

#[test]
fn extract_blocked_ips_supports_open_ipgroup_payload_with_empty_ips() {
    let payload = json!({
        "data": {
            "nodes": [
                {
                    "id": 1,
                    "comment": "雷池社区恶意 IP 情报",
                    "ips": [],
                    "reference": "",
                    "builtin": true,
                    "updated_at": "2026-04-10T01:03:27.134874+08:00",
                    "total": 0
                },
                {
                    "id": 2,
                    "comment": "搜索引擎爬虫 IP",
                    "ips": [],
                    "reference": "",
                    "builtin": true,
                    "updated_at": "2026-04-10T02:07:31.105448+08:00",
                    "total": 0
                }
            ],
            "total": 2
        },
        "err": null,
        "msg": ""
    });

    let ips = extract_blocked_ips(&payload).unwrap();
    assert!(ips.is_empty());
}
