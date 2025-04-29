use instant_acme::{
    Account, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus,
};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyUsagePurpose,
};
use std::{fs, path::Path, time::Duration};

const WELL_KNOWN_PATH: &str = ".well-known/acme-challenge";

/// The data needed to generate the CA certificate
pub struct CertOptions {
    /// The server domain names
    pub domains: Vec<String>,
    /// The company email
    pub email: String,
    /// The web root directory path
    pub web_root: String,
    /// The company name
    pub company_name: String,
    /// The account credentials file path
    pub acc_cred_path: String,
    /// The key usage extensions code
    pub eku: Vec<u64>,
}

// Generate a certificate signing request with EKU for Status List Token signing
fn generate_csr(
    domains: &[String],
    company_name: &str,
    eku: &[u64],
    server_key_pem: &str,
) -> Result<(String, String), anyhow::Error> {
    if domains.is_empty() {
        return Err(anyhow::anyhow!("No domain(s) provided"));
    }
    // Build certificate request parameters
    let mut params = CertificateParams::new(domains)?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, domains.first().unwrap());
    dn.push(DnType::OrganizationName, company_name);
    params.distinguished_name = dn;
    // Add Extended Key Usage for Status List Token signing
    // https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-10.html#section-10.1
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::Other(eku.to_vec())];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];

    // Generate certificate signing request
    let keypair = rcgen::KeyPair::from_pem(server_key_pem)?;
    let csr = params.serialize_request(&keypair)?;
    Ok((csr.pem()?, keypair.serialize_pem()))
}

/// Request a certificate from the certificate authority
///
/// Returns a tuple containing the server certificate and private key
pub async fn req_certificate(
    cert_options: &CertOptions,
    server_key_pem: &str,
) -> Result<(String, String), anyhow::Error> {
    let web_root = if !cert_options.web_root.ends_with('/') {
        format!("{}/", cert_options.web_root)
    } else {
        cert_options.web_root.clone()
    };
    // try to load account credentials or create a new one if it doesn't exist
    let credentials = if let Ok(file) = fs::read_to_string(&cert_options.acc_cred_path) {
        serde_json::from_str(&file)?
    } else {
        let (_, credentials) = Account::create(
            &NewAccount {
                contact: &[&format!("mailto:{}", cert_options.email)],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            // TODO : Replace staging with production
            // We use staging to avoid rate limits
            LetsEncrypt::Staging.url(),
            None,
        )
        .await?;
        fs::write(
            &cert_options.acc_cred_path,
            serde_json::to_string_pretty(&credentials)?,
        )?;
        credentials
    };
    let account = Account::from_credentials(credentials).await?;

    // Create the ACME order based on the given domain names.
    let identifiers = cert_options
        .domains
        .iter()
        .map(|ident| Identifier::Dns(ident.clone()))
        .collect::<Vec<_>>();
    let mut order = account
        .new_order(&NewOrder {
            identifiers: &identifiers,
        })
        .await?;

    let authorizations = order.authorizations().await?;
    for auth in authorizations {
        let challenge = auth
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Http01)
            .ok_or_else(|| anyhow::anyhow!("no http01 challenge found"))?;
        let token = &challenge.token;
        let key_auth = order.key_authorization(&challenge);
        let challenge_dir = format!("{}{}", web_root, WELL_KNOWN_PATH);
        let challenge_dir_path = Path::new(&challenge_dir);
        if !challenge_dir_path.try_exists()? {
            fs::create_dir_all(challenge_dir_path)?;
        }
        let challenge_path = format!("{}/{}", challenge_dir, token);
        fs::write(&challenge_path, key_auth.as_str())?;
        order.set_challenge_ready(&challenge.url).await?;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            let auth_status = order.state().status;
            if auth_status == OrderStatus::Ready {
                break;
            } else if auth_status == OrderStatus::Invalid {
                return Err(anyhow::anyhow!("Authorization failed"));
            }
        }
    }

    let (csr, private_key_pem) = generate_csr(
        &cert_options.domains,
        &cert_options.company_name,
        &cert_options.eku,
        server_key_pem,
    )?;
    order.finalize(csr.as_bytes()).await?;

    let cert_chain_pem = loop {
        match order.certificate().await? {
            Some(cert_chain_pem) => break cert_chain_pem,
            None => tokio::time::sleep(Duration::from_secs(1)).await,
        }
    };

    Ok((cert_chain_pem, private_key_pem))
}
