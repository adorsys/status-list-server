use std::collections::{HashMap, hash_map::Entry};

use async_trait::async_trait;
use color_eyre::eyre::{Report, eyre};
use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use tracing::info;

use super::{DnsProvider, http_client};
use crate::cert_manager::challenge::ChallengeError;

const PROVIDER: &str = "acmedns";

#[derive(Clone)]
pub struct AcmeDnsCredentials {
    pub username: String,
    pub password: SecretString,
    pub subdomain: String,
}

/// Needs pre-registered accounts and a CNAME from `_acme-challenge.<domain>` to each subdomain.
/// An account holds only two TXT values, so 3+ domains need an account each.
pub struct AcmeDnsProvider {
    client: Client,
    server_url: String,
    default_account: Option<AcmeDnsCredentials>,
    accounts: HashMap<String, AcmeDnsCredentials>,
}

fn dns_err(source: impl Into<Report>) -> ChallengeError {
    ChallengeError::Dns {
        provider: PROVIDER,
        source: source.into(),
    }
}

/// No IDNA mapping: a config key written as a Unicode label (münchen) never matches.
fn normalize_domain(domain: &str) -> String {
    let domain = domain.trim().trim_end_matches('.');
    domain
        .strip_prefix("*.")
        .unwrap_or(domain)
        .to_ascii_lowercase()
}

fn same_account(a: &AcmeDnsCredentials, b: &AcmeDnsCredentials) -> bool {
    a.username == b.username
        && a.subdomain == b.subdomain
        && a.password.expose_secret() == b.password.expose_secret()
}

impl AcmeDnsProvider {
    /// Rejects two entries that normalize to one domain with different credentials.
    pub fn new(
        server_url: impl Into<String>,
        default_account: Option<AcmeDnsCredentials>,
        accounts: HashMap<String, AcmeDnsCredentials>,
    ) -> Result<Self, ChallengeError> {
        let mut normalized: HashMap<String, (String, AcmeDnsCredentials)> =
            HashMap::with_capacity(accounts.len());
        for (domain, account) in accounts {
            match normalized.entry(normalize_domain(&domain)) {
                Entry::Occupied(entry) => {
                    let (other, existing) = entry.get();
                    // Same account twice is fine, e.g. an apex and its wildcard.
                    if !same_account(existing, &account) {
                        return Err(dns_err(eyre!(
                            "Conflicting ACME-DNS accounts: entries {other} and {domain} \
                             both normalize to {} but hold different credentials",
                            entry.key(),
                        )));
                    }
                }
                Entry::Vacant(slot) => {
                    slot.insert((domain, account));
                }
            }
        }

        Ok(Self {
            client: http_client(),
            server_url: server_url.into().trim_end_matches('/').to_string(),
            default_account,
            accounts: normalized
                .into_iter()
                .map(|(key, (_, account))| (key, account))
                .collect(),
        })
    }

    pub fn has_credentials_for(&self, domain: &str) -> bool {
        self.credentials_for(domain).is_ok()
    }

    /// A third domain on one account would rotate the first digest out before the CA checks it.
    /// Startup-only; it doesn't guard orders whose identifiers differ from config.
    pub fn check_order_domains(&self, domains: &[&str]) -> Result<(), ChallengeError> {
        let mut by_account: HashMap<&str, Vec<&str>> = HashMap::new();
        for domain in domains {
            let account = self.credentials_for(domain)?;
            by_account
                .entry(account.subdomain.as_str())
                .or_default()
                .push(domain);
        }
        if let Some((subdomain, domains)) = by_account.iter().find(|(_, d)| d.len() > 2) {
            return Err(dns_err(eyre!(
                "The ACME-DNS account with subdomain {subdomain} would serve {} identifiers \
                 ({}), but ACME-DNS keeps only the two most recent TXT values; register a \
                 separate account per domain in the accounts map",
                domains.len(),
                domains.join(", "),
            )));
        }
        Ok(())
    }

    fn credentials_for(&self, domain: &str) -> Result<&AcmeDnsCredentials, ChallengeError> {
        self.accounts
            .get(&normalize_domain(domain))
            .or(self.default_account.as_ref())
            .ok_or_else(|| {
                dns_err(eyre!(
                    "No ACME-DNS account configured for {domain} and no default account is set"
                ))
            })
    }
}

#[async_trait]
impl DnsProvider for AcmeDnsProvider {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<(), ChallengeError> {
        let account = self.credentials_for(domain)?;
        let url = format!("{}/update", self.server_url);
        let body = json!({"subdomain": account.subdomain, "txt": value});

        let response = self
            .client
            .post(&url)
            .header("X-Api-User", &account.username)
            .header("X-Api-Key", account.password.expose_secret())
            .json(&body)
            .send()
            .await
            .map_err(dns_err)?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(dns_err(eyre!(
                "Failed to update TXT record (status {status}): {body}"
            )));
        }

        // Log the subdomain so a typoed key falling back to the default shows up.
        info!(
            "ACME-DNS TXT record updated for {domain} via subdomain {}",
            account.subdomain
        );
        Ok(())
    }

    async fn delete_txt_record(&self, _domain: &str, _value: &str) -> Result<(), ChallengeError> {
        // ACME-DNS has no delete endpoint; it rotates the two most recent TXT values
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn account(name: &str) -> AcmeDnsCredentials {
        AcmeDnsCredentials {
            username: format!("user-{name}"),
            password: format!("key-{name}").into(),
            subdomain: format!("sub-{name}"),
        }
    }

    fn single_account_provider(server: &MockServer) -> AcmeDnsProvider {
        AcmeDnsProvider::new(
            server.uri(),
            Some(AcmeDnsCredentials {
                username: "user-uuid".into(),
                password: "api-key".into(),
                subdomain: "subdomain-uuid".into(),
            }),
            HashMap::new(),
        )
        .expect("no account entries to conflict")
    }

    async fn expect_update(server: &MockServer, account: &AcmeDnsCredentials, txt: &str) {
        Mock::given(method("POST"))
            .and(path("/update"))
            .and(header("x-api-user", account.username.as_str()))
            .and(header("x-api-key", account.password.expose_secret()))
            .and(body_json(json!({
                "subdomain": account.subdomain,
                "txt": txt,
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"txt": txt})))
            .expect(1)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn updates_txt_record_with_credentials() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/update"))
            .and(header("x-api-user", "user-uuid"))
            .and(header("x-api-key", "api-key"))
            .and(body_json(json!({
                "subdomain": "subdomain-uuid",
                "txt": "digest-value",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "txt": "digest-value",
            })))
            .expect(1)
            .mount(&server)
            .await;

        single_account_provider(&server)
            .create_txt_record("status.example.com", "digest-value")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn surfaces_update_failures_with_provider_name() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/update"))
            .respond_with(
                ResponseTemplate::new(401).set_body_json(json!({"error": "bad credentials"})),
            )
            .mount(&server)
            .await;

        let err = single_account_provider(&server)
            .create_txt_record("status.example.com", "digest-value")
            .await
            .unwrap_err();
        match err {
            ChallengeError::Dns { provider, source } => {
                assert_eq!(provider, "acmedns");
                assert!(source.to_string().contains("bad credentials"));
            }
            other => panic!("Unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn delete_is_a_no_op() {
        let server = MockServer::start().await;

        single_account_provider(&server)
            .delete_txt_record("status.example.com", "digest-value")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn selects_account_by_identifier() {
        let server = MockServer::start().await;
        let (a, b) = (account("a"), account("b"));
        expect_update(&server, &a, "digest-a").await;
        expect_update(&server, &b, "digest-b").await;

        let provider = AcmeDnsProvider::new(
            server.uri(),
            None,
            HashMap::from([
                ("a.example.com".to_string(), a),
                ("b.example.com".to_string(), b),
            ]),
        )
        .unwrap();

        provider
            .create_txt_record("a.example.com", "digest-a")
            .await
            .unwrap();
        provider
            .create_txt_record("b.example.com", "digest-b")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn three_identifiers_update_three_distinct_subdomains() {
        let server = MockServer::start().await;
        let domains = ["a.example.com", "b.example.com", "c.example.com"];
        let mut accounts = HashMap::new();
        for domain in domains {
            let acct = account(domain);
            expect_update(&server, &acct, &format!("digest-{domain}")).await;
            accounts.insert(domain.to_string(), acct);
        }

        let provider = AcmeDnsProvider::new(server.uri(), None, accounts).unwrap();
        for domain in domains {
            provider
                .create_txt_record(domain, &format!("digest-{domain}"))
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn falls_back_to_default_account_for_unmapped_domain() {
        let server = MockServer::start().await;
        let default = account("default");
        expect_update(&server, &default, "digest-value").await;

        let provider = AcmeDnsProvider::new(
            server.uri(),
            Some(default),
            HashMap::from([("mapped.example.com".to_string(), account("mapped"))]),
        )
        .unwrap();

        provider
            .create_txt_record("other.example.com", "digest-value")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn mapped_account_wins_over_the_default() {
        let server = MockServer::start().await;
        let (default, mapped) = (account("default"), account("mapped"));
        expect_update(&server, &mapped, "digest-value").await;

        let provider = AcmeDnsProvider::new(
            server.uri(),
            Some(default),
            HashMap::from([("mapped.example.com".to_string(), mapped)]),
        )
        .unwrap();

        provider
            .create_txt_record("mapped.example.com", "digest-value")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn check_order_domains_rejects_three_identifiers_on_one_account() {
        let server = MockServer::start().await;
        let provider =
            AcmeDnsProvider::new(server.uri(), Some(account("default")), HashMap::new()).unwrap();

        provider
            .check_order_domains(&["example.com", "*.example.com"])
            .unwrap();

        let err = provider
            .check_order_domains(&["a.example.com", "b.example.com", "c.example.com"])
            .unwrap_err();
        match err {
            ChallengeError::Dns { provider, source } => {
                assert_eq!(provider, "acmedns");
                let message = source.to_string();
                assert!(message.contains("sub-default"));
                assert!(message.contains("a.example.com, b.example.com, c.example.com"));
            }
            other => panic!("Unexpected error: {other:?}"),
        }
    }

    #[test]
    fn check_order_domains_passes_when_identifiers_spread_across_accounts() {
        let provider = AcmeDnsProvider::new(
            "https://auth.example.org",
            Some(account("default")),
            HashMap::from([("c.example.com".to_string(), account("c"))]),
        )
        .unwrap();

        provider
            .check_order_domains(&["a.example.com", "b.example.com", "c.example.com"])
            .unwrap();
    }

    #[test]
    fn check_order_domains_reports_the_uncovered_domain() {
        let provider = AcmeDnsProvider::new(
            "https://auth.example.org",
            None,
            HashMap::from([("mapped.example.com".to_string(), account("mapped"))]),
        )
        .unwrap();

        let err = provider
            .check_order_domains(&["other.example.com"])
            .unwrap_err();
        match err {
            ChallengeError::Dns { source, .. } => {
                assert!(source.to_string().contains("other.example.com"));
            }
            other => panic!("Unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn errors_when_domain_has_no_account_and_no_default() {
        let server = MockServer::start().await;

        let provider = AcmeDnsProvider::new(
            server.uri(),
            None,
            HashMap::from([("mapped.example.com".to_string(), account("mapped"))]),
        )
        .unwrap();

        let err = provider
            .create_txt_record("other.example.com", "digest-value")
            .await
            .unwrap_err();
        match err {
            ChallengeError::Dns { provider, source } => {
                assert_eq!(provider, "acmedns");
                assert!(source.to_string().contains("other.example.com"));
            }
            other => panic!("Unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn normalizes_domains_for_account_lookup() {
        let server = MockServer::start().await;
        let acct = account("norm");
        Mock::given(method("POST"))
            .and(path("/update"))
            .and(header("x-api-user", acct.username.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"txt": "digest-value"})))
            .expect(2)
            .mount(&server)
            .await;

        let provider = AcmeDnsProvider::new(
            server.uri(),
            None,
            HashMap::from([("Status.Example.COM.".to_string(), acct)]),
        )
        .unwrap();

        provider
            .create_txt_record("status.example.com", "digest-value")
            .await
            .unwrap();
        provider
            .create_txt_record("*.status.example.com", "digest-value")
            .await
            .unwrap();
    }

    #[test]
    fn rejects_conflicting_accounts_for_the_same_normalized_domain() {
        let err = AcmeDnsProvider::new(
            "https://auth.example.org",
            None,
            HashMap::from([
                ("A.Example.com".to_string(), account("first")),
                ("a.example.com.".to_string(), account("second")),
            ]),
        )
        .err()
        .expect("conflicting entries must be rejected");

        match err {
            ChallengeError::Dns { provider, source } => {
                assert_eq!(provider, "acmedns");
                let message = source.to_string();
                assert!(message.contains("A.Example.com"));
                assert!(message.contains("a.example.com."));
            }
            other => panic!("Unexpected error: {other:?}"),
        }
    }

    #[test]
    fn allows_duplicate_entries_with_identical_accounts() {
        let acct = account("shared");
        let provider = AcmeDnsProvider::new(
            "https://auth.example.org",
            None,
            HashMap::from([
                ("example.com".to_string(), acct.clone()),
                ("*.example.com".to_string(), acct),
            ]),
        )
        .unwrap();

        assert!(provider.has_credentials_for("example.com"));
        assert!(provider.has_credentials_for("*.example.com"));
    }
}
