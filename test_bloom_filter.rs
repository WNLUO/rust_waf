// 测试文件：验证布隆过滤器功能
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};

fn main() {
    // 模拟 L4 层布隆过滤器测试
    println!("=== L4 布隆过滤器测试 ===");

    // 测试 IPv4 地址
    let ip_v4: Ipv4Addr = "192.168.1.1".parse().unwrap();
    println!("测试 IPv4 地址: {}", ip_v4);

    // 测试 IPv6 地址
    let ip_v6: Ipv6Addr = "::1".parse().unwrap();
    println!("测试 IPv6 地址: {}", ip_v6);

    // 测试 IP:Port 组合
    let ip_addr: IpAddr = IpAddr::V4(ip_v4);
    let port = 8080;
    println!("测试 IP:Port 组合: {}:{}", ip_addr, port);

    println!("\n=== L7 布隆过滤器测试 ===");

    // 测试 URL
    let url = "http://example.com/malicious/path";
    println!("测试 URL: {}", url);

    // 测试 HTTP 方法
    let method = "GET";
    println!("测试 HTTP 方法: {}", method);

    // 测试 User-Agent
    let user_agent = "Mozilla/5.0 (compatible; Bot/1.0)";
    println!("测试 User-Agent: {}", user_agent);

    // 测试 Payload
    let payload = "SELECT * FROM users WHERE '1'='1'";
    println!("测试 Payload: {}", payload);

    // 测试 Cookie
    let cookie = "session=abc123; user=test";
    println!("测试 Cookie: {}", cookie);

    println!("\n=== 配置说明 ===");
    println!("启用布隆过滤器：设置 bloom_enabled = true");
    println!("启用假阳性验证：设置 l4_bloom_false_positive_verification = true");
    println!("                     设置 l7_bloom_false_positive_verification = true");
    println!("\n示例配置文件：config/bloom_filter_demo.json");
}
