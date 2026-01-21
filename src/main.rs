use anyhow::Context;
use axum::{
    BoxError, Router,
    extract::FromRef,
    handler::HandlerWithoutStateExt,
    http::{HeaderMap, HeaderValue, StatusCode, Uri},
    response::Redirect,
    routing::{get, post},
};

use axum_server::tls_rustls::RustlsConfig;

use std::{env, net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::sync::RwLock;
use tower_default_headers::DefaultHeadersLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::{dbsc::routes::*, routes::*, session_store::SessionManager};

pub mod dbsc;
pub mod routes;
pub mod session_store;

#[allow(dead_code)]
#[derive(Clone, Copy)]
struct Ports {
    http: u16,
    https: u16,
}

pub type SharedSessionManager = Arc<RwLock<SessionManager>>;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub session_cookie_name: String,
    pub domain: String,
    pub tls_certificate: PathBuf,
    pub tls_private_key: PathBuf,
}

#[derive(Debug, Clone)]
pub struct AppState {
    config: AppConfig,
    dbsc_config: dbsc::Config,
    session_manager: SharedSessionManager,
}

impl FromRef<AppState> for AppConfig {
    fn from_ref(app_state: &AppState) -> Self {
        app_state.config.clone()
    }
}

impl FromRef<AppState> for dbsc::Config {
    fn from_ref(app_state: &AppState) -> Self {
        app_state.dbsc_config.clone()
    }
}

impl FromRef<AppState> for SharedSessionManager {
    fn from_ref(app_state: &AppState) -> Self {
        app_state.session_manager.clone()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let dbsc_config = dbsc::Config {
        start_session_route: String::from("/StartSession"),
        refresh_session_route: String::from("/RefreshSession"),
    };
    let app_config = AppConfig {
        session_cookie_name: String::from("ticket"),
        domain: String::from("slowteetoe.info"),
        tls_certificate: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("self_signed_certs")
            .join("slowteetoe.info+1.pem"),
        tls_private_key: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("self_signed_certs")
            .join("slowteetoe.info+1-key.pem"),
    };
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!(
                    "info,tower_http=debug,axum::rejection=trace,{}=debug",
                    env!("CARGO_CRATE_NAME")
                )
                .into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let origin_trial = env::var("ORIGIN_TRIAL").context("missing ORIGIN_TRIAL env variable")?;

    let mut default_headers = HeaderMap::new();
    default_headers.insert(
        "Origin-Trial",
        HeaderValue::from_str(origin_trial.as_str())?,
    );

    let ports = Ports {
        http: 7878,
        https: 3000,
    };
    // optional: spawn a second server to redirect http requests to this server
    tokio::spawn(redirect_http_to_https(ports));

    // configure certificate and private key used by https
    let config =
        RustlsConfig::from_pem_file(&app_config.tls_certificate, &app_config.tls_private_key)
            .await?;

    let session_manager: SharedSessionManager = Arc::new(RwLock::new(SessionManager::new()));

    let app_state = AppState {
        config: app_config,
        dbsc_config: dbsc_config.clone(),
        session_manager,
    };

    let app = Router::new()
        .route("/", get(index))
        .with_state(app_state.clone())
        .route("/login", get(login))
        .with_state(app_state.clone())
        .route("/protected", get(protected_path))
        .with_state(app_state.clone())
        .route(
            &dbsc_config.clone().start_session_route,
            post(dbsc_start_session),
        )
        .with_state(app_state.clone())
        .route(
            &dbsc_config.clone().refresh_session_route,
            post(dbsc_refresh_session),
        )
        .with_state(app_state.clone())
        .layer(DefaultHeadersLayer::new(default_headers))
        .layer(TraceLayer::new_for_http());

    // run https server
    let addr = SocketAddr::from(([127, 0, 0, 1], ports.https));
    tracing::debug!("listening on {}", addr);
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

#[allow(dead_code, unused_results, unused_must_use, clippy::unwrap_used)]
async fn redirect_http_to_https(ports: Ports) {
    fn make_https(uri: Uri, https_port: u16) -> Result<Uri, BoxError> {
        let mut parts = uri.into_parts();

        parts.scheme = Some(axum::http::uri::Scheme::HTTPS);
        parts.authority = Some(format!("localhost:{https_port}").parse()?);

        if parts.path_and_query.is_none() {
            parts.path_and_query = Some("/".parse()?);
        }

        Ok(Uri::from_parts(parts)?)
    }

    let redirect = move |uri: Uri| async move {
        match make_https(uri, ports.https) {
            Ok(uri) => Ok(Redirect::permanent(&uri.to_string())),
            Err(error) => {
                tracing::warn!(%error, "failed to convert URI to HTTPS");
                Err(StatusCode::BAD_REQUEST)
            }
        }
    };

    let addr = SocketAddr::from(([127, 0, 0, 1], ports.http));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, redirect.into_make_service()).await;
}
