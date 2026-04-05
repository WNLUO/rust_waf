pub mod url;
pub mod http_method;
pub mod user_agent;
pub mod cookie;
pub mod payload;
pub mod headers;

pub use url::UrlBloomFilter;
pub use http_method::HttpMethodBloomFilter;
pub use user_agent::UserAgentBloomFilter;
pub use cookie::CookieBloomFilter;
pub use payload::PayloadBloomFilter;
pub use headers::HeadersBloomFilter;

use crate::config::L7Config;
use log::info;

pub struct L7BloomFilterManager {
    config: L7Config,
    url_filter: UrlBloomFilter,
    http_method_filter: HttpMethodBloomFilter,
    user_agent_filter: UserAgentBloomFilter,
    cookie_filter: CookieBloomFilter,
    payload_filter: PayloadBloomFilter,
    headers_filter: HeadersBloomFilter,
    enabled: bool,
    false_positive_verification: bool,
    exact_set_url: std::collections::HashSet<String>,
    exact_set_http_method: std::collections::HashSet<String>,
    exact_set_user_agent: std::collections::HashSet<String>,
    exact_set_cookie: std::collections::HashSet<String>,
    exact_set_payload: std::collections::HashSet<String>,
    exact_set_headers: std::collections::HashSet<String>,
}

impl L7BloomFilterManager {
    pub fn new(config: L7Config, enabled: bool, false_positive_verification: bool) -> Self {
        info!("Initializing L7 Bloom Filter Manager (enabled: {}, false_positive_verification: {})",
              enabled, false_positive_verification);
        Self {
            config: config.clone(),
            url_filter: UrlBloomFilter::new(config.clone()),
            http_method_filter: HttpMethodBloomFilter::new(config.clone()),
            user_agent_filter: UserAgentBloomFilter::new(config.clone()),
            cookie_filter: CookieBloomFilter::new(config.clone()),
            payload_filter: PayloadBloomFilter::new(config.clone()),
            headers_filter: HeadersBloomFilter::new(config.clone()),
            enabled,
            false_positive_verification,
            exact_set_url: std::collections::HashSet::new(),
            exact_set_http_method: std::collections::HashSet::new(),
            exact_set_user_agent: std::collections::HashSet::new(),
            exact_set_cookie: std::collections::HashSet::new(),
            exact_set_payload: std::collections::HashSet::new(),
            exact_set_headers: std::collections::HashSet::new(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        log::info!("L7 Bloom filter enabled: {}", enabled);
    }

    pub fn set_false_positive_verification(&mut self, verification: bool) {
        self.false_positive_verification = verification;
        log::info!("L7 Bloom filter false positive verification: {}", verification);
    }

    pub fn check_url(&self, url: &str) -> bool {
        if !self.enabled {
            return false;
        }

        let bloom_result = self.url_filter.contains(url);

        if !bloom_result {
            return false;
        }

        if self.false_positive_verification {
            let exact_result = self.exact_set_url.contains(url);
            log::debug!("URL Bloom filter hit for {}, exact verification: {}", url, exact_result);
            exact_result
        } else {
            bloom_result
        }
    }

    pub fn add_url(&mut self, url: String) {
        self.url_filter.insert(url.clone());
        if self.false_positive_verification {
            self.exact_set_url.insert(url);
        }
    }

    pub fn check_http_method(&self, method: &str) -> bool {
        if !self.enabled {
            return false;
        }

        let bloom_result = self.http_method_filter.contains(method);

        if !bloom_result {
            return false;
        }

        if self.false_positive_verification {
            let exact_result = self.exact_set_http_method.contains(method);
            log::debug!("HTTP Method Bloom filter hit for {}, exact verification: {}", method, exact_result);
            exact_result
        } else {
            bloom_result
        }
    }

    pub fn add_http_method(&mut self, method: String) {
        self.http_method_filter.insert(method.clone());
        if self.false_positive_verification {
            self.exact_set_http_method.insert(method);
        }
    }

    pub fn check_user_agent(&self, user_agent: &str) -> bool {
        if !self.enabled {
            return false;
        }

        let bloom_result = self.user_agent_filter.contains(user_agent);

        if !bloom_result {
            return false;
        }

        if self.false_positive_verification {
            let exact_result = self.exact_set_user_agent.contains(user_agent);
            log::debug!("User-Agent Bloom filter hit for {}, exact verification: {}", user_agent, exact_result);
            exact_result
        } else {
            bloom_result
        }
    }

    pub fn add_user_agent(&mut self, user_agent: String) {
        self.user_agent_filter.insert(user_agent.clone());
        if self.false_positive_verification {
            self.exact_set_user_agent.insert(user_agent);
        }
    }

    pub fn check_cookie(&self, cookie: &str) -> bool {
        if !self.enabled {
            return false;
        }

        let bloom_result = self.cookie_filter.contains(cookie);

        if !bloom_result {
            return false;
        }

        if self.false_positive_verification {
            let exact_result = self.exact_set_cookie.contains(cookie);
            log::debug!("Cookie Bloom filter hit for {}, exact verification: {}", cookie, exact_result);
            exact_result
        } else {
            bloom_result
        }
    }

    pub fn add_cookie(&mut self, cookie: String) {
        self.cookie_filter.insert(cookie.clone());
        if self.false_positive_verification {
            self.exact_set_cookie.insert(cookie);
        }
    }

    pub fn check_payload(&self, payload: &str) -> bool {
        if !self.enabled {
            return false;
        }

        let bloom_result = self.payload_filter.contains(payload);

        if !bloom_result {
            return false;
        }

        if self.false_positive_verification {
            let exact_result = self.exact_set_payload.contains(payload);
            log::debug!("Payload Bloom filter hit for {}, exact verification: {}", payload, exact_result);
            exact_result
        } else {
            bloom_result
        }
    }

    pub fn add_payload(&mut self, payload: String) {
        self.payload_filter.insert(payload.clone());
        if self.false_positive_verification {
            self.exact_set_payload.insert(payload);
        }
    }

    pub fn check_headers(&self, headers: &[(String, String)]) -> bool {
        if !self.enabled {
            return false;
        }

        let bloom_result = self.headers_filter.contains(headers);

        if !bloom_result {
            return false;
        }

        if self.false_positive_verification {
            // Convert headers to a string for exact matching
            let headers_str = headers.iter()
                .map(|(k, v)| format!("{}: {}", k, v))
                .collect::<Vec<_>>()
                .join(",");
            let exact_result = self.exact_set_headers.contains(&headers_str);
            log::debug!("Headers Bloom filter hit, exact verification: {}", exact_result);
            exact_result
        } else {
            bloom_result
        }
    }

    pub fn add_headers(&mut self, headers: Vec<(String, String)>) {
        self.headers_filter.insert(headers.clone());
        if self.false_positive_verification {
            let headers_str = headers.iter()
                .map(|(k, v)| format!("{}: {}", k, v))
                .collect::<Vec<_>>()
                .join(",");
            self.exact_set_headers.insert(headers_str);
        }
    }

    pub fn get_statistics(&self) -> L7BloomStats {
        L7BloomStats {
            url_filter: self.url_filter.get_stats(),
            http_method_filter: self.http_method_filter.get_stats(),
            user_agent_filter: self.user_agent_filter.get_stats(),
            cookie_filter: self.cookie_filter.get_stats(),
            payload_filter: self.payload_filter.get_stats(),
            headers_filter: self.headers_filter.get_stats(),
            enabled: self.enabled,
            false_positive_verification: self.false_positive_verification,
        }
    }

    pub fn get_false_positive_stats(&self) -> L7FalsePositiveStats {
        L7FalsePositiveStats {
            url_exact_size: self.exact_set_url.len(),
            http_method_exact_size: self.exact_set_http_method.len(),
            user_agent_exact_size: self.exact_set_user_agent.len(),
            cookie_exact_size: self.exact_set_cookie.len(),
            payload_exact_size: self.exact_set_payload.len(),
            headers_exact_size: self.exact_set_headers.len(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct L7BloomStats {
    pub url_filter: url::UrlBloomStats,
    pub http_method_filter: http_method::HttpMethodBloomStats,
    pub user_agent_filter: user_agent::UserAgentBloomStats,
    pub cookie_filter: cookie::CookieBloomStats,
    pub payload_filter: payload::PayloadBloomStats,
    pub headers_filter: headers::HeadersBloomStats,
    pub enabled: bool,
    pub false_positive_verification: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct L7FalsePositiveStats {
    pub url_exact_size: usize,
    pub http_method_exact_size: usize,
    pub user_agent_exact_size: usize,
    pub cookie_exact_size: usize,
    pub payload_exact_size: usize,
    pub headers_exact_size: usize,
}
