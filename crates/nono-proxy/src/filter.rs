//! Async host filtering wrapping the library's [`HostFilter`](nono::HostFilter).
//!
//! Performs DNS resolution via `tokio::net::lookup_host()` and checks
//! the hostname against the cloud metadata deny list and allowlist.

use crate::error::Result;
use nono::net_filter::{FilterResult, HostFilter};
use std::net::SocketAddr;
use tracing::debug;

/// Result of a filter check including resolved socket addresses.
///
/// When the filter allows a host, `resolved_addrs` contains the DNS-resolved
/// addresses. Callers MUST connect to these addresses (not re-resolve the
/// hostname) to prevent DNS rebinding TOCTOU attacks.
pub struct CheckResult {
    /// The filter decision
    pub result: FilterResult,
    /// DNS-resolved addresses (empty if denied or DNS failed)
    pub resolved_addrs: Vec<SocketAddr>,
}

/// Async wrapper around `HostFilter` that performs DNS resolution.
#[derive(Debug, Clone)]
pub struct ProxyFilter {
    inner: HostFilter,
}

impl ProxyFilter {
    /// Create a new proxy filter with the given allowed hosts.
    #[must_use]
    pub fn new(allowed_hosts: &[String]) -> Self {
        Self {
            inner: HostFilter::new(allowed_hosts),
        }
    }

    /// Create a filter that allows all hosts (except cloud metadata).
    #[must_use]
    pub fn allow_all() -> Self {
        Self {
            inner: HostFilter::allow_all(),
        }
    }

    /// Check a host against the filter with async DNS resolution.
    ///
    /// Resolves the hostname to IP addresses, checks the hostname against
    /// the cloud metadata deny list and allowlist.
    ///
    /// On success, returns both the filter result and the resolved socket
    /// addresses. Callers MUST use `resolved_addrs` to connect to the upstream
    /// instead of re-resolving the hostname, eliminating the DNS rebinding
    /// TOCTOU window.
    pub async fn check_host(&self, host: &str, port: u16) -> Result<CheckResult> {
        // Check hostname against deny list and allowlist first
        let result = self.inner.check_host(host);

        if !result.is_allowed() {
            return Ok(CheckResult {
                result,
                resolved_addrs: Vec::new(),
            });
        }

        // Resolve DNS only for allowed hosts
        let addr_str = format!("{}:{}", host, port);
        let resolved: Vec<SocketAddr> = match tokio::net::lookup_host(&addr_str).await {
            Ok(addrs) => addrs.collect(),
            Err(e) => {
                debug!("DNS resolution failed for {}: {}", host, e);
                Vec::new()
            }
        };

        Ok(CheckResult {
            result,
            resolved_addrs: resolved,
        })
    }

    /// Check a host synchronously (no DNS lookup).
    #[must_use]
    pub fn check_host_sync(&self, host: &str) -> FilterResult {
        self.inner.check_host(host)
    }

    /// Number of allowed hosts configured.
    #[must_use]
    pub fn allowed_count(&self) -> usize {
        self.inner.allowed_count()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_filter_delegates_to_host_filter() {
        let filter = ProxyFilter::new(&["api.openai.com".to_string()]);

        let result = filter.check_host_sync("api.openai.com");
        assert!(result.is_allowed());

        let result = filter.check_host_sync("evil.com");
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_proxy_filter_allow_all() {
        let filter = ProxyFilter::allow_all();
        let result = filter.check_host_sync("anything.com");
        assert!(result.is_allowed());
    }

    #[test]
    fn test_proxy_filter_allows_private_networks() {
        let filter = ProxyFilter::allow_all();
        let result = filter.check_host_sync("corp.internal");
        assert!(result.is_allowed());
    }
}
