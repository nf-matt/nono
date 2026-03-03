//! Network host filtering for proxy-level domain matching.
//!
//! This module provides application-layer host filtering that complements
//! the OS-level port restrictions from [`CapabilitySet`](crate::CapabilitySet).
//! The proxy uses [`HostFilter`] to decide whether to allow or deny CONNECT
//! requests based on hostname allowlists and a cloud metadata deny list.
//!
//! # Security Properties
//!
//! - **Cloud metadata endpoints are hardcoded and non-overridable**: Instance
//!   metadata services (169.254.169.254, metadata.google.internal, etc.) are
//!   always denied regardless of allowlist configuration.
//! - **Wildcard subdomain matching**: `*.googleapis.com` matches
//!   `storage.googleapis.com` but not `googleapis.com` itself.

/// Result of a host filter check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterResult {
    /// Host is allowed by the allowlist
    Allow,
    /// Host is denied because a specific hostname is in the deny list
    DenyHost {
        /// The hostname that was denied
        host: String,
    },
    /// Host is not in the allowlist (default deny)
    DenyNotAllowed {
        /// The hostname that was not found in any allowlist
        host: String,
    },
}

impl FilterResult {
    /// Whether the result is an allow decision
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, FilterResult::Allow)
    }

    /// A human-readable reason for the decision
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            FilterResult::Allow => "allowed by host filter".to_string(),
            FilterResult::DenyHost { host } => {
                format!("host {} is in the deny list", host)
            }
            FilterResult::DenyNotAllowed { host } => {
                format!("host {} is not in the allowlist", host)
            }
        }
    }
}

/// Hosts that are always denied regardless of allowlist configuration.
/// These are cloud metadata endpoints commonly targeted for SSRF attacks.
const DENY_HOSTS: &[&str] = &[
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.azure.internal",
];

/// A filter for host-based network access control.
///
/// Supports exact domain match and wildcard subdomains (`*.googleapis.com`).
///
/// Cloud metadata endpoints are always denied and cannot be overridden.
/// The allowlist determines which hosts are permitted; everything else
/// is denied by default.
#[derive(Debug, Clone)]
pub struct HostFilter {
    /// Allowed exact hosts (lowercased)
    allowed_hosts: Vec<String>,
    /// Allowed wildcard suffixes (e.g., ".googleapis.com", lowercased)
    allowed_suffixes: Vec<String>,
    /// Hostnames that are always denied
    deny_hosts: Vec<String>,
}

impl HostFilter {
    /// Create a new host filter with the given allowed hosts.
    ///
    /// Cloud metadata endpoints are automatically denied and cannot be removed.
    ///
    /// Hosts starting with `*.` are treated as wildcard subdomain patterns.
    /// All other entries are exact matches. Matching is case-insensitive.
    #[must_use]
    pub fn new(allowed_hosts: &[String]) -> Self {
        let mut exact = Vec::new();
        let mut suffixes = Vec::new();

        for host in allowed_hosts {
            let lower = host.to_lowercase();
            if let Some(suffix) = lower.strip_prefix('*') {
                // *.example.com -> .example.com
                suffixes.push(suffix.to_string());
            } else {
                exact.push(lower);
            }
        }

        Self {
            allowed_hosts: exact,
            allowed_suffixes: suffixes,
            deny_hosts: DENY_HOSTS.iter().map(|s| s.to_lowercase()).collect(),
        }
    }

    /// Create a host filter that allows everything (no filtering).
    ///
    /// Cloud metadata endpoints are still blocked.
    #[must_use]
    pub fn allow_all() -> Self {
        Self {
            allowed_hosts: Vec::new(),
            allowed_suffixes: Vec::new(),
            deny_hosts: DENY_HOSTS.iter().map(|s| s.to_lowercase()).collect(),
        }
    }

    /// Check a host against the filter.
    ///
    /// # Check Order
    ///
    /// 1. Deny hosts (exact match against cloud metadata hostnames)
    /// 2. Allowlist (exact host match, then wildcard subdomain match)
    /// 3. Default deny (if not in allowlist and allowlist is non-empty)
    #[must_use]
    pub fn check_host(&self, host: &str) -> FilterResult {
        let lower_host = host.to_lowercase();

        // 1. Check deny hosts
        if self.deny_hosts.contains(&lower_host) {
            return FilterResult::DenyHost {
                host: host.to_string(),
            };
        }

        // 2. If no allowlist is configured (allow_all mode), allow
        if self.allowed_hosts.is_empty() && self.allowed_suffixes.is_empty() {
            return FilterResult::Allow;
        }

        // 3. Check exact host match
        if self.allowed_hosts.contains(&lower_host) {
            return FilterResult::Allow;
        }

        // 4. Check wildcard subdomain match
        for suffix in &self.allowed_suffixes {
            if lower_host.ends_with(suffix.as_str()) && lower_host.len() > suffix.len() {
                return FilterResult::Allow;
            }
        }

        // 5. Not in allowlist
        FilterResult::DenyNotAllowed {
            host: host.to_string(),
        }
    }

    /// Number of allowed hosts (exact + wildcard)
    #[must_use]
    pub fn allowed_count(&self) -> usize {
        self.allowed_hosts
            .len()
            .saturating_add(self.allowed_suffixes.len())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_host_allowed() {
        let filter = HostFilter::new(&["api.openai.com".to_string()]);
        let result = filter.check_host("api.openai.com");
        assert!(result.is_allowed());
    }

    #[test]
    fn test_exact_host_case_insensitive() {
        let filter = HostFilter::new(&["API.OpenAI.COM".to_string()]);
        let result = filter.check_host("api.openai.com");
        assert!(result.is_allowed());
    }

    #[test]
    fn test_host_not_in_allowlist() {
        let filter = HostFilter::new(&["api.openai.com".to_string()]);
        let result = filter.check_host("evil.com");
        assert!(!result.is_allowed());
        assert!(matches!(result, FilterResult::DenyNotAllowed { .. }));
    }

    #[test]
    fn test_wildcard_subdomain_match() {
        let filter = HostFilter::new(&["*.googleapis.com".to_string()]);

        // Subdomain should match
        let result = filter.check_host("storage.googleapis.com");
        assert!(result.is_allowed());

        // Deep subdomain should match
        let result = filter.check_host("us-central1-aiplatform.googleapis.com");
        assert!(result.is_allowed());
    }

    #[test]
    fn test_wildcard_does_not_match_bare_domain() {
        let filter = HostFilter::new(&["*.googleapis.com".to_string()]);

        // Bare domain should NOT match wildcard
        let result = filter.check_host("googleapis.com");
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_deny_cloud_metadata_hostname() {
        let filter = HostFilter::new(&["169.254.169.254".to_string()]);

        // Should be denied even if in allowlist
        let result = filter.check_host("169.254.169.254");
        assert!(!result.is_allowed());
        assert!(matches!(result, FilterResult::DenyHost { .. }));
    }

    #[test]
    fn test_deny_google_metadata() {
        let filter = HostFilter::new(&["metadata.google.internal".to_string()]);
        let result = filter.check_host("metadata.google.internal");
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_allow_all_mode() {
        // No allowlist = allow all (except deny list)
        let filter = HostFilter::allow_all();
        let result = filter.check_host("any-host.example.com");
        assert!(result.is_allowed());
    }

    #[test]
    fn test_allow_all_allows_private_networks() {
        let filter = HostFilter::allow_all();
        let result = filter.check_host("internal.corp.com");
        assert!(result.is_allowed());
    }

    #[test]
    fn test_allowed_count() {
        let filter = HostFilter::new(&[
            "api.openai.com".to_string(),
            "*.googleapis.com".to_string(),
            "github.com".to_string(),
        ]);
        assert_eq!(filter.allowed_count(), 3);
    }

    #[test]
    fn test_filter_result_reason() {
        let allow = FilterResult::Allow;
        assert!(allow.reason().contains("allowed"));

        let deny = FilterResult::DenyNotAllowed {
            host: "evil.com".to_string(),
        };
        assert!(deny.reason().contains("evil.com"));
    }
}
