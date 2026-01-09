use axum::{
    BoxError, Router,
    extract::State,
    handler::HandlerWithoutStateExt,
    http::{HeaderMap, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::{CookieJar, cookie::Cookie};
use axum_server::tls_rustls::RustlsConfig;
use chrono::{DateTime, TimeDelta, Utc};
use cookie::time::Duration;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::Jwk};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub refresh_token: String,
    pub expiry: DateTime<Utc>,
    pub jwk: Option<Jwk>,
    // probably need to keep track of this, should be part of the refresh I would think..?
    pub challenge: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Claims {
    jti: String,
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
        .route("/terminate", post(dbsc_terminate_session))
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
        let header = decode_header(jwt).unwrap();
        dbg!(&header);

        let mut validation = Validation::new(header.alg);
        // exp is not in the DBSC claims
        validation.required_spec_claims = HashSet::new();
        validation.validate_exp = false;

        let jwk = header.jwk.unwrap();

        let claims = match decode::<Claims>(jwt, &DecodingKey::from_jwk(&jwk).unwrap(), &validation)
        {
            Ok(data) => data.claims,
            Err(e) => panic!("{}", e),
        };
        dbg!(&claims);

        let mut refresh_token = None;

        {
            let mut ds = ds.write().await;
            if let Some(session) = ds.data.get_mut(ticket) {
                if claims.jti != session.challenge {
                    println!(
                        "challenge failed: claims={} vs session={}",
                        claims.jti, session.challenge
                    );
                    return (StatusCode::FORBIDDEN, "challenge failed".to_owned());
                }
                println!("session found");
                session.jwk = Some(jwk);
                refresh_token = Some(session.refresh_token.clone());
            }
        }

        // TODO make this a struct so we don't do this nasty escaping
        (
            StatusCode::OK,
            format!(
                r#"{{
      "session_identifier": "{}",
      "refresh_url": "/RefreshSession",

      "scope": {{
        "origin": "https://slowteetoe.info",
        "include_site": true,
        "scope_specification" : []
      }},

      "credentials": [{{
        "type": "cookie",
        "name": "ticket",
        "attributes": "Domain=slowteetoe.info; Path=/; Secure; HttpOnly; SameSite=None"
      }}]
      }}"#,
                refresh_token.unwrap()
            ),
        )
    } else {
        (StatusCode::BAD_REQUEST, "Invalid DBSC request".to_owned())
    }
}

async fn dbsc_refresh_session(
    State(ds): State<SharedDatastore>,
    headers: HeaderMap,
    jar: CookieJar,
    body: String,
) -> Response {
    let session_id = headers.get("Sec-Secure-Session-Id");
    if session_id.is_none() {
        println!("invalid refresh request, no session id present. terminating");
        return (StatusCode::OK, "{\"continue\": false}").into_response();
    }

    let session_id = session_id
        .unwrap()
        .to_str()
        .expect("session_id should have been a valid string");

    if let Some(session) = ds.write().await.data.get_mut(session_id) {
        let secure_session_response = headers.get("Secure-Session-Response");
        // there are two valid paths at this point:

        if secure_session_response.is_none() {
            // 1. browser is attempting to refresh the session, but we haven't challenged them yet - we respond back with a
            // HTTP 403 and a new Secure-Session-Challenge: "challenge_value";id="session_id"
            let new_challenge = format!("challenge-{}", Uuid::new_v4().to_string());
            session.challenge = new_challenge.clone();
            return (
                StatusCode::FORBIDDEN,
                [(
                    "Secure-Session-Registration",
                    format!(
                        r#"(ES256);path="/StartSession";challenge="{}""#,
                        new_challenge
                    ),
                )],
                "",
            )
                .into_response();
        } else {
            // 2. browser has completed the challenge
            // in which case there will be a 'Secure-Session-Response' header with a JWT proof we need to validate
            let jwt = secure_session_response
                .unwrap()
                .to_str()
                .expect("ssr should have been a valid string");

            // use the session JWK to validate the refresh request challenge
            if session.jwk.is_none() {
                println!("should have been a JWK associated with the session. terminating");
                return (StatusCode::OK, "{\"continue\": false}").into_response();
            }
            let jwk = session.jwk.as_ref().unwrap();
            let alg: Algorithm = Algorithm::ES256;
            dbg!(&alg);

            let mut validation = Validation::new(alg);
            validation.required_spec_claims = HashSet::new();
            validation.validate_exp = false;

            let claims =
                match decode::<Claims>(jwt, &DecodingKey::from_jwk(&jwk).unwrap(), &validation) {
                    Ok(data) => data.claims,
                    Err(e) => panic!("{}", e),
                };
            dbg!(&claims.jti);
            if claims.jti != session.challenge {
                println!(
                    "failed challenge, submitted={}, expected={}. terminating",
                    claims.jti, session.challenge
                );
                return (StatusCode::OK, "{\"continue\": false}").into_response();
            }

            let id = Uuid::new_v4();
            let session = Session {
                id,
                refresh_token: format!("RT-{}", id.clone()),
                expiry: Utc::now() + TimeDelta::seconds(30),
                jwk: Some(jwk.clone()),
                challenge: Uuid::new_v4().to_string(),
            };
            ds.write()
                .await
                .data
                .insert(id.to_string(), session.clone());
            let mut cookie = Cookie::new("ticket", id.to_string());
            cookie.set_max_age(Duration::seconds(30));

            println!("Successful refresh challenge, rotating session to {id}");
            // TODO return the session registration JSON here, which allows us to change the session_identifier
            return (StatusCode::OK, jar.add(cookie), "").into_response();
        }
    } else {
        println!("unknown session id={session_id}, cannot refresh. terminating");
        return (StatusCode::OK, "{\"continue\": false}").into_response();
    }
}

async fn dbsc_terminate_session(
    State(ds): State<SharedDatastore>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    println!(
        "terminating session (body={}, headers={:?})",
        body, &headers,
    );
    // sec-secure-session-id
    (StatusCode::OK, "{\"continue\": false}")
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
        refresh_token: String::from("RT1234-5678"),
        expiry: Utc::now() + TimeDelta::seconds(30),
        jwk: None,
        challenge: Uuid::new_v4().to_string(),
    };
    ds.write()
        .await
        .data
        .insert(id.to_string(), session.clone());
    let mut cookie = Cookie::new("ticket", id.to_string());
    cookie.set_max_age(Duration::seconds(30));

    // direct browser to initiate DBSC if supported
    (
        StatusCode::OK,
        [(
            "Secure-Session-Registration",
            format!(
                r#"(ES256);path="/StartSession";challenge="{}""#,
                session.challenge
            ),
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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};

    use crate::Claims;

    #[test]
    fn it_should_decode_jwt() {
        let jwt = "eyJhbGciOiJFUzI1NiIsImp3ayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImhISkV5MWtiRE1uOUxoOUJxYURraFBveGhLQzYzbHdyWTZwZkdCSGVXZFEiLCJ5IjoiMnlJaHBMTEFRVUlWWEVXOHR3ZGNrN21LS0tzWkN3QzlzSGFFZW4zWGtqMCJ9LCJ0eXAiOiJkYnNjK2p3dCJ9.eyJqdGkiOiJZMmhoYkd4bGJtZGxDZz09In0.mKqV-VmLWGBBmrYKPSb7AJeyk4iP9kFN8VlfBc-qT9gNaBQDtUhXUwLgGfeIzagPPWEwcTrgcJ7dJEyVqmIi6w";
        let header = decode_header(jwt).unwrap();
        dbg!(&header);

        let mut validation = Validation::new(header.alg);
        // exp is not in the DBSC claims
        validation.required_spec_claims = HashSet::new();
        validation.validate_exp = false;

        let claims = match decode::<Claims>(
            jwt,
            &DecodingKey::from_jwk(&header.jwk.unwrap()).unwrap(),
            &validation,
        ) {
            Ok(claims) => claims,
            Err(e) => panic!("{}", e),
        };
        dbg!(&claims);
    }
}
