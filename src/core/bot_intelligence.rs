use crate::core::bot_verifier::BotVerificationStatus;
use crate::core::WafContext;
use crate::protocol::UnifiedHttpRequest;
use std::net::IpAddr;

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
    let bot_detection = context.config_snapshot().bot_detection;
    if !bot_detection.enabled {
        request.add_metadata("client.trust_class".to_string(), "unknown".to_string());
        request.add_metadata("client.policy".to_string(), "standard".to_string());
        return;
    }
    let Some(crawler) = bot_detection
        .crawlers
        .iter()
        .filter(|crawler| crawler.enabled)
        .find(|crawler| crawler.tokens.iter().any(|token| lower_ua.contains(token)))
    else {
        request.add_metadata("client.trust_class".to_string(), "unknown".to_string());
        request.add_metadata("client.policy".to_string(), "standard".to_string());
        return;
    };

    request.add_metadata("bot.known".to_string(), "true".to_string());
    request.add_metadata("bot.name".to_string(), crawler.name.clone());
    request.add_metadata("bot.category".to_string(), crawler.category.clone());
    request.add_metadata("bot.policy".to_string(), crawler.policy.clone());
    if let Some(provider) = crawler.provider.as_deref() {
        request.add_metadata("bot.provider".to_string(), provider.to_string());
    }

    let client_ip = request
        .client_ip
        .as_deref()
        .and_then(|value| value.parse::<IpAddr>().ok());
    let verification = match (crawler.provider.as_deref(), client_ip) {
        (Some(provider), Some(ip)) => context.bot_ip_verifier().verify(provider, ip),
        _ => BotVerificationStatus::Unavailable,
    };
    if !matches!(
        verification,
        BotVerificationStatus::Verified | BotVerificationStatus::VerifiedReverseDns
    ) {
        if let (Some(provider), Some(ip)) = (crawler.provider.as_deref(), client_ip) {
            if let Some(suffixes) =
                crate::core::bot_verifier::bot_dns_provider(&bot_detection.providers, provider)
            {
                context
                    .bot_ip_verifier()
                    .enqueue_dns_verification(provider, ip, &suffixes);
                request.add_metadata("bot.reverse_dns_queued".to_string(), "true".to_string());
            }
        }
    }

    match verification {
        BotVerificationStatus::Verified => {
            request.add_metadata("bot.verification".to_string(), "official_ip".to_string());
            request.add_metadata(
                "client.trust_class".to_string(),
                "verified_good_bot".to_string(),
            );
            request.add_metadata("client.policy".to_string(), crawler.policy.clone());
            request.add_metadata(
                "client.trust_reason".to_string(),
                "known_crawler_official_ip".to_string(),
            );
        }
        BotVerificationStatus::VerifiedReverseDns => {
            request.add_metadata("bot.verification".to_string(), "reverse_dns".to_string());
            request.add_metadata(
                "client.trust_class".to_string(),
                "verified_good_bot".to_string(),
            );
            request.add_metadata("client.policy".to_string(), crawler.policy.clone());
            request.add_metadata(
                "client.trust_reason".to_string(),
                "known_crawler_reverse_dns".to_string(),
            );
        }
        BotVerificationStatus::NotVerified => {
            request.add_metadata(
                "bot.verification".to_string(),
                "official_ip_mismatch".to_string(),
            );
            request.add_metadata("client.trust_class".to_string(), "suspect_bot".to_string());
            request.add_metadata("client.policy".to_string(), "strict".to_string());
            request.add_metadata(
                "client.trust_reason".to_string(),
                "crawler_ua_official_ip_mismatch".to_string(),
            );
        }
        BotVerificationStatus::Unavailable => {
            request.add_metadata("bot.verification".to_string(), "claimed".to_string());
            request.add_metadata(
                "client.trust_class".to_string(),
                "claimed_good_bot".to_string(),
            );
            request.add_metadata("client.policy".to_string(), crawler.policy.clone());
            request.add_metadata(
                "client.trust_reason".to_string(),
                "known_crawler_ua".to_string(),
            );
        }
    }
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
