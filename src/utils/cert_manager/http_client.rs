use std::{future::Future, pin::Pin};

use axum::body::Bytes;
use http_body_util::Full;
use hyper::Request;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use instant_acme::{BytesResponse, Error, HttpClient};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{pem::PemObject, CertificateDer};

use crate::cert_manager::CertError;

/// Default HTTP client used for ACME flow
#[derive(Clone)]
pub struct DefaultHttpClient(ClientInner);

impl DefaultHttpClient {
    /// Create a new instance of [DefaultHttpClient] with optional root certificate chain pem
    pub fn new(root_cert_pem: Option<&[u8]>) -> Result<Self, CertError> {
        Ok(Self(ClientInner::try_new(root_cert_pem)?))
    }
}

impl HttpClient for DefaultHttpClient {
    fn request(
        &self,
        req: Request<Full<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, Error>> + Send>> {
        let future = self.0.client.request(req);
        Box::pin(async move {
            match future.await {
                Ok(resp) => Ok(BytesResponse::from(resp)),
                Err(err) => Err(err.into()),
            }
        })
    }
}

#[derive(Clone)]
struct ClientInner {
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
}

impl ClientInner {
    pub fn try_new(root_cert_pem: Option<&[u8]>) -> Result<Self, CertError> {
        let mut root_store = RootCertStore::empty();
        if let Some(root_pem) = root_cert_pem {
            let certs_der: Vec<_> = CertificateDer::pem_slice_iter(root_pem)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| CertError::Parsing(e.to_string()))?;
            root_store.add_parsable_certificates(certs_der);
        }
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.to_vec());
        let tls_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let http_builder = HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_only()
            .enable_all_versions()
            .build();

        Ok(Self {
            client: Client::builder(TokioExecutor::new()).build(http_builder),
        })
    }
}
