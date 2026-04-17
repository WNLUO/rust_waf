use super::*;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;

pub(super) fn is_internal_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_private()
                || ipv4.is_loopback()
                || ipv4.is_link_local()
                || ipv4.is_broadcast()
                || ipv4.is_documentation()
                || ipv4.is_unspecified()
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback()
                || ipv6.is_unspecified()
                || ipv6.is_unique_local()
                || ipv6.is_unicast_link_local()
        }
    }
}

pub(super) fn pending_origin_node() -> TrafficMapNodeSnapshot {
    TrafficMapNodeSnapshot {
        id: "origin-cn".to_string(),
        name: "本服务器".to_string(),
        region: "后端正在获取物理位置中".to_string(),
        role: "origin".to_string(),
        lat: None,
        lng: None,
        traffic_weight: 1.0,
        request_count: 0,
        blocked_count: 0,
        bandwidth_mbps: 0.0,
        last_seen_at: unix_timestamp_ms(),
    }
}

pub(super) fn origin_node_from_geo_payload(
    payload: &IpWhoisResponse,
) -> Option<TrafficMapNodeSnapshot> {
    let country_code = payload
        .country_code
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    if !country_code.eq_ignore_ascii_case("CN") {
        return None;
    }

    let region = payload
        .region
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("中国");
    let city = payload
        .city
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let label = city
        .map(|city| format!("{region} {city}"))
        .unwrap_or_else(|| region.to_string());

    origin_node_snapshot(
        label,
        payload.latitude?,
        payload.longitude?,
        unix_timestamp_ms(),
    )
}

pub(super) fn origin_node_from_ipip_payload(
    payload: &IpipRegionResponse,
) -> Option<TrafficMapNodeSnapshot> {
    let country = payload
        .first()
        .map(String::as_str)
        .map(str::trim)
        .unwrap_or_default();
    if country != "中国" && !country.eq_ignore_ascii_case("CN") {
        return None;
    }

    let region = payload
        .get(1)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("中国");
    let city = payload
        .get(2)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let normalized = city
        .map(|city| format!("{region} {city}"))
        .unwrap_or_else(|| region.to_string());
    let geo_node = find_china_node(&normalized)?;
    let label = city
        .map(|city| format!("{region} {city}"))
        .unwrap_or_else(|| region.to_string());

    origin_node_snapshot(label, geo_node.lat, geo_node.lng, unix_timestamp_ms())
}

pub(super) fn origin_node_from_ip_sb_payload(
    payload: &IpSbGeoResponse,
) -> Option<TrafficMapNodeSnapshot> {
    let country_code = payload
        .country_code
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    if !country_code.eq_ignore_ascii_case("CN") {
        return None;
    }

    let region = payload
        .region
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("中国");
    let city = payload
        .city
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let label = city
        .map(|city| format!("{region} {city}"))
        .unwrap_or_else(|| region.to_string());

    origin_node_snapshot(
        label,
        payload.latitude?,
        payload.longitude?,
        unix_timestamp_ms(),
    )
}

pub(super) fn origin_node_snapshot(
    region: String,
    lat: f64,
    lng: f64,
    last_seen_at: i64,
) -> Option<TrafficMapNodeSnapshot> {
    Some(TrafficMapNodeSnapshot {
        id: "origin-cn".to_string(),
        name: "本服务器".to_string(),
        region,
        role: "origin".to_string(),
        lat: Some(lat),
        lng: Some(lng),
        traffic_weight: 1.0,
        request_count: 0,
        blocked_count: 0,
        bandwidth_mbps: 0.0,
        last_seen_at,
    })
}

pub(super) fn find_china_node(normalized: &str) -> Option<GeoNode> {
    let normalized = normalized.to_ascii_lowercase();
    for node in china_nodes() {
        if node_matches_region(node, &normalized) {
            return Some(node.clone());
        }
    }
    Some(fallback_mainland_node(normalized.as_str(), ""))
}

pub(super) fn internal_node() -> GeoNode {
    GeoNode {
        id: "cn-internal",
        name: "内网",
        region: "内网来源",
        lat: 30.95,
        lng: 121.22,
        traffic_weight: 0.48,
    }
}

pub(super) fn overseas_node() -> GeoNode {
    GeoNode {
        id: "cn-overseas",
        name: "境外",
        region: "境外来源",
        lat: 43.8,
        lng: 82.1,
        traffic_weight: 0.62,
    }
}

pub(super) fn map_remote_region_to_node(payload: &IpWhoisResponse) -> Option<GeoNode> {
    let country_code = payload
        .country_code
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    if !country_code.eq_ignore_ascii_case("CN") {
        return Some(overseas_node());
    }

    let region = payload.region.as_deref().unwrap_or_default();
    let city = payload.city.as_deref().unwrap_or_default();
    let normalized = format!("{region} {city}").to_ascii_lowercase();

    for node in china_nodes() {
        if node_matches_region(node, &normalized) {
            return Some(node.clone());
        }
    }

    Some(fallback_mainland_node(region, city))
}

pub(super) fn node_matches_region(node: &GeoNode, normalized: &str) -> bool {
    province_aliases(node.id)
        .iter()
        .any(|alias| normalized.contains(alias))
}

pub(super) fn province_aliases(node_id: &str) -> &'static [&'static str] {
    match node_id {
        "cn-110000" => &["beijing", "北京"],
        "cn-120000" => &["tianjin", "天津"],
        "cn-130000" => &["hebei", "河北"],
        "cn-140000" => &["shanxi", "山西"],
        "cn-150000" => &["inner mongolia", "neimenggu", "内蒙古"],
        "cn-210000" => &["liaoning", "辽宁"],
        "cn-220000" => &["jilin", "吉林"],
        "cn-230000" => &["heilongjiang", "黑龙江"],
        "cn-310000" => &["shanghai", "上海"],
        "cn-320000" => &["jiangsu", "江苏"],
        "cn-330000" => &["zhejiang", "浙江"],
        "cn-340000" => &["anhui", "安徽"],
        "cn-350000" => &["fujian", "福建"],
        "cn-360000" => &["jiangxi", "江西"],
        "cn-370000" => &["shandong", "山东"],
        "cn-410000" => &["henan", "河南"],
        "cn-420000" => &["hubei", "湖北"],
        "cn-430000" => &["hunan", "湖南"],
        "cn-440000" => &["guangdong", "广东"],
        "cn-450000" => &["guangxi", "广西"],
        "cn-460000" => &["hainan", "海南"],
        "cn-500000" => &["chongqing", "重庆"],
        "cn-510000" => &["sichuan", "四川"],
        "cn-520000" => &["guizhou", "贵州"],
        "cn-530000" => &["yunnan", "云南"],
        "cn-540000" => &["tibet", "xizang", "西藏"],
        "cn-610000" => &["shaanxi", "陕西"],
        "cn-620000" => &["gansu", "甘肃"],
        "cn-630000" => &["qinghai", "青海"],
        "cn-640000" => &["ningxia", "宁夏"],
        "cn-650000" => &["xinjiang", "新疆"],
        "cn-710000" => &["taiwan", "台湾"],
        "cn-810000" => &["hong kong", "香港"],
        "cn-820000" => &["macau", "macao", "澳门"],
        _ => &[],
    }
}

pub(super) fn fallback_mainland_node(region: &str, city: &str) -> GeoNode {
    let key = format!("{region}:{city}");
    let fallback_pool = [
        "cn-310000",
        "cn-320000",
        "cn-330000",
        "cn-370000",
        "cn-440000",
        "cn-510000",
        "cn-110000",
        "cn-420000",
    ];
    let index = stable_index(&key, fallback_pool.len());
    china_nodes()
        .iter()
        .find(|node| node.id == fallback_pool[index])
        .cloned()
        .unwrap_or_else(|| china_nodes()[0].clone())
}

pub(super) fn fallback_node(source_ip: &str) -> GeoNode {
    let parsed_ip = source_ip.parse::<IpAddr>().ok();
    if parsed_ip.map(is_internal_ip).unwrap_or(false) {
        return internal_node();
    }
    let pool = china_nodes();
    pool[stable_index(source_ip, pool.len())].clone()
}

pub(super) fn stable_index(value: &str, len: usize) -> usize {
    use std::collections::hash_map::DefaultHasher;

    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    (hasher.finish() as usize) % len.max(1)
}

pub(super) fn china_nodes() -> &'static [GeoNode] {
    &[
        GeoNode {
            id: "cn-110000",
            name: "北京",
            region: "北京市",
            lat: 40.18994,
            lng: 116.41995,
            traffic_weight: 0.90,
        },
        GeoNode {
            id: "cn-120000",
            name: "天津",
            region: "天津市",
            lat: 39.288036,
            lng: 117.347043,
            traffic_weight: 0.72,
        },
        GeoNode {
            id: "cn-130000",
            name: "河北",
            region: "河北省",
            lat: 38.045474,
            lng: 114.502461,
            traffic_weight: 0.64,
        },
        GeoNode {
            id: "cn-140000",
            name: "山西",
            region: "山西省",
            lat: 37.618179,
            lng: 112.304436,
            traffic_weight: 0.45,
        },
        GeoNode {
            id: "cn-150000",
            name: "内蒙古",
            region: "内蒙古自治区",
            lat: 44.331087,
            lng: 114.077429,
            traffic_weight: 0.34,
        },
        GeoNode {
            id: "cn-210000",
            name: "辽宁",
            region: "辽宁省",
            lat: 41.299712,
            lng: 122.604994,
            traffic_weight: 0.52,
        },
        GeoNode {
            id: "cn-220000",
            name: "吉林",
            region: "吉林省",
            lat: 43.703954,
            lng: 126.171208,
            traffic_weight: 0.31,
        },
        GeoNode {
            id: "cn-230000",
            name: "黑龙江",
            region: "黑龙江省",
            lat: 48.040465,
            lng: 127.693027,
            traffic_weight: 0.28,
        },
        GeoNode {
            id: "cn-310000",
            name: "上海",
            region: "上海市",
            lat: 31.072559,
            lng: 121.438737,
            traffic_weight: 1.0,
        },
        GeoNode {
            id: "cn-320000",
            name: "江苏",
            region: "江苏省",
            lat: 32.983991,
            lng: 119.486506,
            traffic_weight: 0.86,
        },
        GeoNode {
            id: "cn-330000",
            name: "浙江",
            region: "浙江省",
            lat: 29.181466,
            lng: 120.109913,
            traffic_weight: 0.84,
        },
        GeoNode {
            id: "cn-340000",
            name: "安徽",
            region: "安徽省",
            lat: 31.849254,
            lng: 117.226884,
            traffic_weight: 0.57,
        },
        GeoNode {
            id: "cn-350000",
            name: "福建",
            region: "福建省",
            lat: 26.069925,
            lng: 118.006468,
            traffic_weight: 0.67,
        },
        GeoNode {
            id: "cn-360000",
            name: "江西",
            region: "江西省",
            lat: 27.636112,
            lng: 115.732975,
            traffic_weight: 0.44,
        },
        GeoNode {
            id: "cn-370000",
            name: "山东",
            region: "山东省",
            lat: 36.376092,
            lng: 118.187759,
            traffic_weight: 0.76,
        },
        GeoNode {
            id: "cn-410000",
            name: "河南",
            region: "河南省",
            lat: 33.902648,
            lng: 113.619717,
            traffic_weight: 0.62,
        },
        GeoNode {
            id: "cn-420000",
            name: "湖北",
            region: "湖北省",
            lat: 30.987527,
            lng: 112.271301,
            traffic_weight: 0.59,
        },
        GeoNode {
            id: "cn-430000",
            name: "湖南",
            region: "湖南省",
            lat: 27.629216,
            lng: 111.711649,
            traffic_weight: 0.51,
        },
        GeoNode {
            id: "cn-440000",
            name: "广东",
            region: "广东省",
            lat: 23.334643,
            lng: 113.429919,
            traffic_weight: 0.92,
        },
        GeoNode {
            id: "cn-450000",
            name: "广西",
            region: "广西壮族自治区",
            lat: 23.833381,
            lng: 108.7944,
            traffic_weight: 0.38,
        },
        GeoNode {
            id: "cn-460000",
            name: "海南",
            region: "海南省",
            lat: 19.189767,
            lng: 109.754859,
            traffic_weight: 0.29,
        },
        GeoNode {
            id: "cn-500000",
            name: "重庆",
            region: "重庆市",
            lat: 30.067297,
            lng: 107.8839,
            traffic_weight: 0.50,
        },
        GeoNode {
            id: "cn-510000",
            name: "四川",
            region: "四川省",
            lat: 30.674545,
            lng: 102.693453,
            traffic_weight: 0.56,
        },
        GeoNode {
            id: "cn-520000",
            name: "贵州",
            region: "贵州省",
            lat: 26.826368,
            lng: 106.880455,
            traffic_weight: 0.36,
        },
        GeoNode {
            id: "cn-530000",
            name: "云南",
            region: "云南省",
            lat: 25.008643,
            lng: 101.485106,
            traffic_weight: 0.33,
        },
        GeoNode {
            id: "cn-540000",
            name: "西藏",
            region: "西藏自治区",
            lat: 31.56375,
            lng: 88.388277,
            traffic_weight: 0.16,
        },
        GeoNode {
            id: "cn-610000",
            name: "陕西",
            region: "陕西省",
            lat: 35.263661,
            lng: 108.887114,
            traffic_weight: 0.48,
        },
        GeoNode {
            id: "cn-620000",
            name: "甘肃",
            region: "甘肃省",
            lat: 36.058039,
            lng: 103.823557,
            traffic_weight: 0.24,
        },
        GeoNode {
            id: "cn-630000",
            name: "青海",
            region: "青海省",
            lat: 35.726403,
            lng: 96.043533,
            traffic_weight: 0.18,
        },
        GeoNode {
            id: "cn-640000",
            name: "宁夏",
            region: "宁夏回族自治区",
            lat: 37.291332,
            lng: 106.169866,
            traffic_weight: 0.22,
        },
        GeoNode {
            id: "cn-650000",
            name: "新疆",
            region: "新疆维吾尔自治区",
            lat: 41.371801,
            lng: 85.294711,
            traffic_weight: 0.20,
        },
        GeoNode {
            id: "cn-710000",
            name: "台湾",
            region: "台湾省",
            lat: 23.749452,
            lng: 120.971485,
            traffic_weight: 0.54,
        },
        GeoNode {
            id: "cn-810000",
            name: "香港",
            region: "香港特别行政区",
            lat: 22.377366,
            lng: 114.134357,
            traffic_weight: 0.60,
        },
        GeoNode {
            id: "cn-820000",
            name: "澳门",
            region: "澳门特别行政区",
            lat: 22.159307,
            lng: 113.566988,
            traffic_weight: 0.32,
        },
    ]
}
