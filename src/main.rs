use axum::{
    BoxError, Router,
    extract::State,
    handler::HandlerWithoutStateExt,
    http::{HeaderMap, HeaderValue, StatusCode, Uri, uri::Authority},
    response::{IntoResponse, Redirect},
    routing::{get, post},
};
use axum_extra::extract::{CookieJar, cookie::Cookie};
use axum_server::tls_rustls::RustlsConfig;
use chrono::{DateTime, TimeDelta, Utc};
use rustls::ContentType;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    env,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
};
use tokio::sync::RwLock;
use tower_default_headers::DefaultHeadersLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

#[allow(dead_code)]
#[derive(Clone, Copy)]
struct Ports {
    http: u16,
    https: u16,
}

pub struct AppConfig {
    pub origin_trial: String,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: Uuid,
    pub expiry: DateTime<Utc>,
    pub jwk: Option<Claims>,
}

#[derive(Debug, Clone)]
pub struct Datastore {
    pub data: BTreeMap<String, Session>,
}

type SharedDatastore = Arc<RwLock<Datastore>>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!(
                    "debug,tower_http=debug,axum::rejection=trace,{}=debug",
                    env!("CARGO_CRATE_NAME")
                )
                .into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let origin_trial = env::var("ORIGIN_TRIAL").expect("missing ORIGIN_TRIAL env var");
    let app_config = Arc::new(AppConfig { origin_trial });

    let mut default_headers = HeaderMap::new();
    default_headers.insert(
        "Origin-Trial",
        HeaderValue::from_str(app_config.origin_trial.as_str())?,
    );

    let ports = Ports {
        http: 7878,
        https: 3000,
    };
    // optional: spawn a second server to redirect http requests to this server
    tokio::spawn(redirect_http_to_https(ports));

    // configure certificate and private key used by https
    let config = RustlsConfig::from_pem_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("self_signed_certs")
            .join("slowteetoe.info+1.pem"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("self_signed_certs")
            .join("slowteetoe.info+1-key.pem"),
    )
    .await
    .unwrap();

    let datastore = Arc::new(RwLock::new(Datastore {
        data: BTreeMap::new(),
    }));

    let app = Router::new()
        .route("/", get(hello))
        .with_state(datastore.clone())
        .route("/login", get(login))
        .with_state(datastore.clone())
        .route("/protected", get(protected_path))
        .with_state(datastore.clone())
        .route("/StartSession", post(dbsc_start_session))
        .with_state(datastore.clone())
        .route("/RefreshSession", post(dbsc_refresh_session))
        .with_state(datastore.clone())
        .layer(DefaultHeadersLayer::new(default_headers))
        .layer(TraceLayer::new_for_http());

    // run https server
    let addr = SocketAddr::from(([127, 0, 0, 1], ports.https));
    tracing::debug!("listening on {}", addr);
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
    Ok(())
}

async fn protected_path(State(ds): State<SharedDatastore>, jar: CookieJar) -> impl IntoResponse {
    let ds = ds.read().await;
    dbg!(&ds.data, &jar);
    ()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Claims {
    jwk: HashMap<String, String>,
}

async fn dbsc_start_session(
    State(ds): State<SharedDatastore>,
    headers: HeaderMap,
    jar: CookieJar,
    body: String,
) -> impl IntoResponse {
    let ticket = jar.get("ticket").expect("missing ticket cookie").value();
    println!("start_session::{}", ticket);
    dbg!(&headers);
    if let Some(jwt) = headers.get("secure-session-response") {
        // TODO verify the JWT and extract claims
        let jwt = jwt.to_str().unwrap();

        let mut jwk = HashMap::new();
        jwk.insert("crv".to_owned(), "P-256".to_owned());
        jwk.insert("kty".to_owned(), "EC".to_owned());
        jwk.insert(
            "x".to_owned(),
            "hHJEy1kbDMn9Lh9BqaDkhPoxhKC63lwrY6pfGBHeWdQ".to_owned(),
        );
        jwk.insert(
            "y".to_owned(),
            "2yIhpLLAQUIVXEW8twdck7mKKKsZCwC9sHaEen3Xkj0".to_owned(),
        );
        let claims = Claims { jwk };
        dbg!(&jwt, &claims);

        {
            let mut ds = ds.write().await;
            if let Some(session) = ds.data.get_mut(ticket) {
                println!("session found");
                session.jwk = Some(claims)
            }
        }

        // what is session_id?
        // return expected response
        (
            StatusCode::OK,
            r#"{
      "session_identifier": "session_id",
      "refresh_url": "/RefreshSession",

      "scope": {
        "origin": "https://slowteetoe.info",
        "include_site": true,
        "scope_specification" : []
      },

      "credentials": [{
        "type": "cookie",
        "name": "ticket",
        "attributes": "Domain=slowteetoe.info; Path=/; Secure; HttpOnly; SameSite=None"
      }]
      }"#,
        )
    } else {
        (StatusCode::BAD_REQUEST, "Invalid DBSC request")
    }
}

async fn dbsc_refresh_session(
    State(ds): State<SharedDatastore>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    println!("refresh_session::Received body: {}", body);
    dbg!(&headers);
    StatusCode::OK
}

#[allow(dead_code)]
async fn hello(State(ds): State<SharedDatastore>) -> impl IntoResponse {
    dbg!(&ds);
    "hello world"
}

async fn login(State(ds): State<SharedDatastore>, jar: CookieJar) -> impl IntoResponse {
    let id = Uuid::new_v4();
    let session = Session {
        id,
        expiry: Utc::now() + TimeDelta::seconds(60),
        jwk: None,
    };
    ds.write().await.data.insert(id.to_string(), session);
    let cookie = Cookie::new("ticket", id.to_string());

    // direct browser to initiate DBSC if supported
    (
        StatusCode::OK,
        [(
            "Secure-Session-Registration",
            r#"(ES256);path="/StartSession";challenge="Y2hhbGxlbmdlCg==""#,
        )],
        jar.add(cookie),
        format!("you logged in! ticket={}", id.to_string()),
    )
}

#[allow(dead_code, unused_results, unused_must_use)]
async fn redirect_http_to_https(ports: Ports) {
    fn make_https(uri: Uri, https_port: u16) -> Result<Uri, BoxError> {
        let mut parts = uri.into_parts();

        parts.scheme = Some(axum::http::uri::Scheme::HTTPS);
        parts.authority = Some(format!("localhost:{https_port}").parse()?);

        if parts.path_and_query.is_none() {
            parts.path_and_query = Some("/".parse().unwrap());
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
