//! Registry client for package hosting.

use crate::package::{PackageRef, PackageSearchResponse, PackageSearchResult, PullResponse};
use nono::{NonoError, Result};
use serde::de::DeserializeOwned;

pub const DEFAULT_REGISTRY_URL: &str = "https://registry.nono.sh";

pub struct RegistryClient {
    base_url: String,
    http: ureq::Agent,
}

impl RegistryClient {
    #[must_use]
    pub fn new(base_url: String) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            http: ureq::Agent::new_with_defaults(),
        }
    }

    pub fn fetch_pull_response(
        &self,
        package_ref: &PackageRef,
        version: &str,
    ) -> Result<PullResponse> {
        self.get_json(&format!(
            "/api/v1/packages/{}/{}/versions/{version}/pull",
            package_ref.namespace, package_ref.name
        ))
    }

    pub fn search_packages(&self, query: &str) -> Result<Vec<PackageSearchResult>> {
        let response: PackageSearchResponse =
            self.get_json(&format!("/api/v1/packages?q={query}"))?;
        Ok(response.packages)
    }

    pub fn download_bytes(&self, url: &str) -> Result<Vec<u8>> {
        let resolved_url = self.resolve_url(url);
        let mut response = self
            .http
            .get(&resolved_url)
            .call()
            .map_err(map_ureq_error)?;
        response
            .body_mut()
            .read_to_vec()
            .map_err(|e| NonoError::RegistryError(format!("failed to read registry response: {e}")))
    }

    pub fn download_text(&self, url: &str) -> Result<String> {
        let resolved_url = self.resolve_url(url);
        let mut response = self
            .http
            .get(&resolved_url)
            .call()
            .map_err(map_ureq_error)?;
        response
            .body_mut()
            .read_to_string()
            .map_err(|e| NonoError::RegistryError(format!("failed to read registry response: {e}")))
    }

    fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);
        let mut response = self.http.get(&url).call().map_err(map_ureq_error)?;
        let body = response.body_mut().read_to_string().map_err(|e| {
            NonoError::RegistryError(format!("failed to read registry response: {e}"))
        })?;
        serde_json::from_str(&body).map_err(|e| {
            NonoError::RegistryError(format!("failed to decode registry response: {e}"))
        })
    }

    fn resolve_url(&self, url: &str) -> String {
        if url.starts_with("http://") || url.starts_with("https://") {
            url.to_string()
        } else {
            format!("{}{}", self.base_url, url)
        }
    }
}

pub fn resolve_registry_url(override_url: Option<&str>) -> String {
    override_url
        .map(ToOwned::to_owned)
        .or_else(|| std::env::var("NONO_REGISTRY").ok())
        .unwrap_or_else(|| DEFAULT_REGISTRY_URL.to_string())
}

fn map_ureq_error(error: ureq::Error) -> NonoError {
    NonoError::RegistryError(error.to_string())
}
