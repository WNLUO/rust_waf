use crate::core::WafContext;
use crate::protocol::UnifiedHttpRequest;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy)]
struct KnownCrawler {
    name: &'static str,
    category: &'static str,
    policy: &'static str,
    tokens: &'static [&'static str],
}

const KNOWN_CRAWLERS: &[KnownCrawler] = &[
    KnownCrawler {
        name: "Googlebot",
        category: "search",
        policy: "reduce_friction",
        tokens: &["googlebot", "adsbot-google", "google-inspectiontool"],
    },
    KnownCrawler {
        name: "Bingbot",
        category: "search",
        policy: "reduce_friction",
        tokens: &["bingbot", "msnbot"],
    },
    KnownCrawler {
        name: "Baiduspider",
        category: "search",
        policy: "reduce_friction",
        tokens: &["baiduspider"],
    },
    KnownCrawler {
        name: "Sogou Spider",
        category: "search",
        policy: "reduce_friction",
        tokens: &["sogou web spider", "sogou spider"],
    },
    KnownCrawler {
        name: "YandexBot",
        category: "search",
        policy: "reduce_friction",
        tokens: &["yandexbot"],
    },
    KnownCrawler {
        name: "DuckDuckBot",
        category: "search",
        policy: "reduce_friction",
        tokens: &["duckduckbot"],
    },
    KnownCrawler {
        name: "Applebot",
        category: "search",
        policy: "reduce_friction",
        tokens: &["applebot"],
    },
    KnownCrawler {
        name: "GPTBot",
        category: "ai",
        policy: "observe",
        tokens: &["gptbot", "chatgpt-user", "oai-searchbot"],
    },
    KnownCrawler {
        name: "ClaudeBot",
        category: "ai",
        policy: "observe",
        tokens: &["claudebot", "anthropic-ai"],
    },
    KnownCrawler {
        name: "PerplexityBot",
        category: "ai",
        policy: "observe",
        tokens: &["perplexitybot"],
    },
    KnownCrawler {
        name: "Bytespider",
        category: "ai",
        policy: "observe",
        tokens: &["bytespider"],
    },
    KnownCrawler {
        name: "AhrefsBot",
        category: "seo",
        policy: "observe",
        tokens: &["ahrefsbot"],
    },
    KnownCrawler {
        name: "SemrushBot",
        category: "seo",
        policy: "observe",
        tokens: &["semrushbot"],
    },
];

pub(crate) fn annotate_request(context: &WafContext, request: &mut UnifiedHttpRequest) {
    let path = request.uri.split('?').next().unwrap_or("/").to_string();
    if is_internal_task(context, request, &path) {
        request.add_metadata("client.trust_class".to_string(), "internal".to_string());
        request.add_metadata("client.policy".to_string(), "bypass_l7_noise".to_string());
        request.add_metadata(
            "client.trust_reason".to_string(),
            "internal_task".to_string(),
        );
        request.add_metadata(
            "internal.task".to_string(),
            internal_task_name(&path).to_string(),
        );
        return;
    }

    let Some(user_agent) = request.get_header("user-agent") else {
        request.add_metadata("client.trust_class".to_string(), "unknown".to_string());
        request.add_metadata("client.policy".to_string(), "standard".to_string());
        return;
    };
    let lower_ua = user_agent.to_ascii_lowercase();
    let Some(crawler) = KNOWN_CRAWLERS
        .iter()
        .find(|crawler| crawler.tokens.iter().any(|token| lower_ua.contains(token)))
    else {
        request.add_metadata("client.trust_class".to_string(), "unknown".to_string());
        request.add_metadata("client.policy".to_string(), "standard".to_string());
        return;
    };

    request.add_metadata("bot.known".to_string(), "true".to_string());
    request.add_metadata("bot.name".to_string(), crawler.name.to_string());
    request.add_metadata("bot.category".to_string(), crawler.category.to_string());
    request.add_metadata("bot.policy".to_string(), crawler.policy.to_string());
    request.add_metadata("bot.verification".to_string(), "claimed".to_string());
    request.add_metadata(
        "client.trust_class".to_string(),
        "claimed_good_bot".to_string(),
    );
    request.add_metadata("client.policy".to_string(), crawler.policy.to_string());
    request.add_metadata(
        "client.trust_reason".to_string(),
        "known_crawler_ua".to_string(),
    );
}

fn is_internal_task(context: &WafContext, request: &UnifiedHttpRequest, path: &str) -> bool {
    if request
        .get_metadata("network.server_public_ip_exempt")
        .is_some_and(|value| value == "true")
        && matches!(path, "/wp-cron.php" | "/xmlrpc.php")
    {
        return true;
    }

    let local_client = request
        .client_ip
        .as_deref()
        .and_then(|value| value.parse::<IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback() || context.is_server_public_ip(ip));
    let local_peer = request
        .get_metadata("network.peer_ip")
        .and_then(|value| value.parse::<IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback() || context.is_server_public_ip(ip));

    (local_client || local_peer) && matches!(path, "/health" | "/wp-cron.php")
}

fn internal_task_name(path: &str) -> &'static str {
    match path {
        "/wp-cron.php" => "wordpress_cron",
        "/xmlrpc.php" => "wordpress_xmlrpc_self_call",
        "/health" => "health_check",
        _ => "internal",
    }
}
