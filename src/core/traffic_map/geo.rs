use super::*;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::OnceLock;

static CHINA_NODES: OnceLock<Vec<GeoNode>> = OnceLock::new();
static GLOBAL_FALLBACK_NODES: OnceLock<Vec<GeoNode>> = OnceLock::new();

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
        id: "origin-pending".to_string(),
        name: "本服务器".to_string(),
        region: "后端正在获取物理位置中".to_string(),
        role: "origin".to_string(),
        lat: None,
        lng: None,
        country_code: None,
        country_name: None,
        geo_scope: "unknown".to_string(),
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
        optional_country_code(payload.country_code.as_deref()),
        optional_label(payload.country.as_deref()),
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
    if !is_china_country(country) {
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

    origin_node_snapshot(
        label,
        geo_node.lat,
        geo_node.lng,
        Some("CN".to_string()),
        Some("中国".to_string()),
        unix_timestamp_ms(),
    )
}

pub(super) fn origin_node_from_ip_sb_payload(
    payload: &IpSbGeoResponse,
) -> Option<TrafficMapNodeSnapshot> {
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
        optional_country_code(payload.country_code.as_deref()),
        optional_label(payload.country.as_deref()),
        unix_timestamp_ms(),
    )
}

pub(super) fn origin_node_snapshot(
    region: String,
    lat: f64,
    lng: f64,
    country_code: Option<String>,
    country_name: Option<String>,
    last_seen_at: i64,
) -> Option<TrafficMapNodeSnapshot> {
    let country_code = country_code.filter(|value| !value.is_empty());
    let geo_scope = if country_code
        .as_deref()
        .is_some_and(|value| value.eq_ignore_ascii_case("CN"))
    {
        "domestic"
    } else {
        "global"
    };
    Some(TrafficMapNodeSnapshot {
        id: "origin".to_string(),
        name: "本服务器".to_string(),
        region,
        role: "origin".to_string(),
        lat: Some(lat),
        lng: Some(lng),
        country_code,
        country_name,
        geo_scope: geo_scope.to_string(),
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
        id: "internal".to_string(),
        name: "内网".to_string(),
        region: "内网来源".to_string(),
        lat: 30.95,
        lng: 121.22,
        country_code: Some("CN".to_string()),
        country_name: Some("中国".to_string()),
        geo_scope: "internal".to_string(),
        traffic_weight: 0.48,
    }
}

pub(super) fn map_remote_region_to_node(
    source_ip: &str,
    payload: &IpWhoisResponse,
) -> Option<GeoNode> {
    let country_code = payload
        .country_code
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    if !country_code.eq_ignore_ascii_case("CN") {
        return Some(global_node_from_ipwhois(source_ip, payload));
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
    province_aliases(&node.id)
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
    let pool = global_fallback_nodes();
    pool[stable_index(source_ip, pool.len())].clone()
}

fn global_node_from_ipwhois(source_ip: &str, payload: &IpWhoisResponse) -> GeoNode {
    let country_code = optional_country_code(payload.country_code.as_deref());
    let country_name = optional_label(payload.country.as_deref());
    let region = optional_label(payload.region.as_deref());
    let city = optional_label(payload.city.as_deref());

    if let (Some(lat), Some(lng)) = (payload.latitude, payload.longitude) {
        if valid_coordinate(lat, lng) {
            let label = match (region.as_deref(), city.as_deref()) {
                (Some(region), Some(city)) if region != city => format!("{region} {city}"),
                (_, Some(city)) => city.to_string(),
                (Some(region), _) => region.to_string(),
                _ => country_name
                    .clone()
                    .or_else(|| country_code.clone())
                    .unwrap_or_else(|| "境外来源".to_string()),
            };
            let id_suffix = country_code
                .as_deref()
                .unwrap_or("global")
                .to_ascii_lowercase();
            let source_bucket = stable_index(source_ip, 64);
            return GeoNode {
                id: format!("global-{id_suffix}-{source_bucket}"),
                name: country_name
                    .clone()
                    .or_else(|| country_code.clone())
                    .unwrap_or_else(|| "境外".to_string()),
                region: label,
                lat,
                lng,
                country_code,
                country_name,
                geo_scope: "global".to_string(),
                traffic_weight: 0.62,
            };
        }
    }

    fallback_global_node(
        source_ip,
        country_code.as_deref(),
        country_name.as_deref(),
        region.as_deref(),
    )
}

fn fallback_global_node(
    source_ip: &str,
    country_code: Option<&str>,
    country_name: Option<&str>,
    region: Option<&str>,
) -> GeoNode {
    let pool = global_fallback_nodes();
    let mut node = pool[stable_index(
        country_code
            .filter(|value| !value.is_empty())
            .unwrap_or(source_ip),
        pool.len(),
    )]
    .clone();

    if let Some(country_code) = optional_country_code(country_code) {
        node.id = format!("global-{}", country_code.to_ascii_lowercase());
        node.country_code = Some(country_code);
    }
    if let Some(country_name) = optional_label(country_name) {
        node.name = country_name.clone();
        node.country_name = Some(country_name);
    }
    if let Some(region) = optional_label(region) {
        node.region = region;
    }
    node
}

fn valid_coordinate(lat: f64, lng: f64) -> bool {
    (-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lng) && (lat != 0.0 || lng != 0.0)
}

fn optional_country_code(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_uppercase())
}

fn optional_label(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn is_china_country(value: &str) -> bool {
    value == "中国" || value.eq_ignore_ascii_case("CN") || value.eq_ignore_ascii_case("China")
}

pub(super) fn stable_index(value: &str, len: usize) -> usize {
    use std::collections::hash_map::DefaultHasher;

    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    (hasher.finish() as usize) % len.max(1)
}

fn global_fallback_nodes() -> &'static [GeoNode] {
    GLOBAL_FALLBACK_NODES
        .get_or_init(|| {
            vec![
                global_node("global-us", "美国", "北美", 39.5, -98.35, "US", 0.72),
                global_node("global-ca", "加拿大", "北美", 56.13, -106.35, "CA", 0.46),
                global_node("global-br", "巴西", "南美", -14.24, -51.93, "BR", 0.44),
                global_node("global-gb", "英国", "欧洲", 55.38, -3.44, "GB", 0.58),
                global_node("global-de", "德国", "欧洲", 51.17, 10.45, "DE", 0.58),
                global_node("global-fr", "法国", "欧洲", 46.23, 2.21, "FR", 0.52),
                global_node("global-ru", "俄罗斯", "欧亚", 61.52, 105.32, "RU", 0.48),
                global_node("global-in", "印度", "南亚", 20.59, 78.96, "IN", 0.56),
                global_node("global-jp", "日本", "东亚", 36.2, 138.25, "JP", 0.62),
                global_node("global-sg", "新加坡", "东南亚", 1.35, 103.82, "SG", 0.64),
                global_node(
                    "global-au",
                    "澳大利亚",
                    "大洋洲",
                    -25.27,
                    133.78,
                    "AU",
                    0.42,
                ),
                global_node("global-za", "南非", "非洲", -30.56, 22.94, "ZA", 0.38),
            ]
        })
        .as_slice()
}

fn global_node(
    id: &str,
    name: &str,
    region: &str,
    lat: f64,
    lng: f64,
    country_code: &str,
    traffic_weight: f64,
) -> GeoNode {
    GeoNode {
        id: id.to_string(),
        name: name.to_string(),
        region: region.to_string(),
        lat,
        lng,
        country_code: Some(country_code.to_string()),
        country_name: Some(name.to_string()),
        geo_scope: "global".to_string(),
        traffic_weight,
    }
}

fn china_geo_node(
    id: &str,
    name: &str,
    region: &str,
    lat: f64,
    lng: f64,
    traffic_weight: f64,
) -> GeoNode {
    GeoNode {
        id: id.to_string(),
        name: name.to_string(),
        region: region.to_string(),
        lat,
        lng,
        country_code: Some("CN".to_string()),
        country_name: Some("中国".to_string()),
        geo_scope: "domestic".to_string(),
        traffic_weight,
    }
}

pub(super) fn china_nodes() -> &'static [GeoNode] {
    CHINA_NODES
        .get_or_init(|| {
            vec![
                china_geo_node("cn-110000", "北京", "北京市", 40.18994, 116.41995, 0.90),
                china_geo_node("cn-120000", "天津", "天津市", 39.288036, 117.347043, 0.72),
                china_geo_node("cn-130000", "河北", "河北省", 38.045474, 114.502461, 0.64),
                china_geo_node("cn-140000", "山西", "山西省", 37.618179, 112.304436, 0.45),
                china_geo_node(
                    "cn-150000",
                    "内蒙古",
                    "内蒙古自治区",
                    44.331087,
                    114.077429,
                    0.34,
                ),
                china_geo_node("cn-210000", "辽宁", "辽宁省", 41.299712, 122.604994, 0.52),
                china_geo_node("cn-220000", "吉林", "吉林省", 43.703954, 126.171208, 0.31),
                china_geo_node(
                    "cn-230000",
                    "黑龙江",
                    "黑龙江省",
                    48.040465,
                    127.693027,
                    0.28,
                ),
                china_geo_node("cn-310000", "上海", "上海市", 31.072559, 121.438737, 1.0),
                china_geo_node("cn-320000", "江苏", "江苏省", 32.983991, 119.486506, 0.86),
                china_geo_node("cn-330000", "浙江", "浙江省", 29.181466, 120.109913, 0.84),
                china_geo_node("cn-340000", "安徽", "安徽省", 31.849254, 117.226884, 0.57),
                china_geo_node("cn-350000", "福建", "福建省", 26.069925, 118.006468, 0.67),
                china_geo_node("cn-360000", "江西", "江西省", 27.636112, 115.732975, 0.44),
                china_geo_node("cn-370000", "山东", "山东省", 36.376092, 118.187759, 0.76),
                china_geo_node("cn-410000", "河南", "河南省", 33.902648, 113.619717, 0.62),
                china_geo_node("cn-420000", "湖北", "湖北省", 30.987527, 112.271301, 0.59),
                china_geo_node("cn-430000", "湖南", "湖南省", 27.629216, 111.711649, 0.51),
                china_geo_node("cn-440000", "广东", "广东省", 23.334643, 113.429919, 0.92),
                china_geo_node(
                    "cn-450000",
                    "广西",
                    "广西壮族自治区",
                    23.833381,
                    108.7944,
                    0.38,
                ),
                china_geo_node("cn-460000", "海南", "海南省", 19.189767, 109.754859, 0.29),
                china_geo_node("cn-500000", "重庆", "重庆市", 30.067297, 107.8839, 0.50),
                china_geo_node("cn-510000", "四川", "四川省", 30.674545, 102.693453, 0.56),
                china_geo_node("cn-520000", "贵州", "贵州省", 26.826368, 106.880455, 0.36),
                china_geo_node("cn-530000", "云南", "云南省", 25.008643, 101.485106, 0.33),
                china_geo_node("cn-540000", "西藏", "西藏自治区", 31.56375, 88.388277, 0.16),
                china_geo_node("cn-610000", "陕西", "陕西省", 35.263661, 108.887114, 0.48),
                china_geo_node("cn-620000", "甘肃", "甘肃省", 36.058039, 103.823557, 0.24),
                china_geo_node("cn-630000", "青海", "青海省", 35.726403, 96.043533, 0.18),
                china_geo_node(
                    "cn-640000",
                    "宁夏",
                    "宁夏回族自治区",
                    37.291332,
                    106.169866,
                    0.22,
                ),
                china_geo_node(
                    "cn-650000",
                    "新疆",
                    "新疆维吾尔自治区",
                    41.371801,
                    85.294711,
                    0.20,
                ),
                china_geo_node("cn-710000", "台湾", "台湾省", 23.749452, 120.971485, 0.54),
                china_geo_node(
                    "cn-810000",
                    "香港",
                    "香港特别行政区",
                    22.377366,
                    114.134357,
                    0.60,
                ),
                china_geo_node(
                    "cn-820000",
                    "澳门",
                    "澳门特别行政区",
                    22.159307,
                    113.566988,
                    0.32,
                ),
            ]
        })
        .as_slice()
}
