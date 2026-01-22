use std::{collections::HashSet, panic};

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

use anyhow::{Context, Result};
use cookie::time::Duration;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};

use crate::{
    AppConfig, AppState, SharedSessionManager,
    dbsc::{self, Claims, Credential, RegistrationResponse, Scope},
};
use axum_extra::extract::{CookieJar, cookie::Cookie};

pub struct DbscError(anyhow::Error);

// tell axum how to convert our error into a response
impl IntoResponse for DbscError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {}", self.0),
        )
            .into_response()
    }
}

impl<E> From<E> for DbscError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

#[axum::debug_handler(state=AppState)]
pub async fn dbsc_start_session(
    State(config): State<AppConfig>,
    State(dbsc_config): State<dbsc::Config>,
    State(session_manager): State<SharedSessionManager>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<Response, DbscError> {
    dbg!(&headers, &jar);
    let mut session_manager = session_manager.lock().await;
    if let Some(ticket) = jar.get(&config.session_cookie_name) {
        let ticket = ticket.value();
        tracing::debug!("start_session -> existing ticket={}", ticket);
        if let Some(jwt) = headers.get("secure-session-response") {
            tracing::debug!("start_session -> secure-session-response header found");
            let jwt = jwt.to_str()?;
            let jwt_header = decode_header(jwt)?;

            let mut validation = Validation::new(jwt_header.alg);
            // exp is not in the DBSC claims
            validation.required_spec_claims = HashSet::new();
            validation.validate_exp = false;

            let jwk = match jwt_header.jwk {
                Some(jwk) => jwk,
                None => {
                    tracing::error!("start_session -> JWK could not be validated.");
                    return Ok(
                        (StatusCode::FORBIDDEN, "challenge failed".to_owned()).into_response()
                    );
                }
            };

            let decoding_key = DecodingKey::from_jwk(&jwk)?;

            let claims = decode::<Claims>(jwt, &decoding_key, &validation)?.claims;

            if let Some(session) = session_manager.get_session(ticket).await {
                // we had a session, check the challenge
                if claims.jti != session.last_challenge {
                    tracing::error!(
                        "start_session -> challenge failed: claims={} vs session={}",
                        claims.jti,
                        session.last_challenge
                    );
                    return Ok(
                        (StatusCode::FORBIDDEN, "challenge failed".to_owned()).into_response()
                    );
                }
                tracing::info!("start_session -> session found, upgrading...");
                if let Ok((access_token, _refresh_token)) = session_manager
                    .upgrade_session_to_refreshable(ticket, jwk)
                    .await
                {
                    let registration = RegistrationResponse {
                        session_identifier: session.id.to_string(),
                        refresh_url: dbsc_config.refresh_session_route.to_string(),
                        scope: Scope {
                            origin: format!("https://{}", config.domain),
                            include_site: true,
                            scope_specification: vec![],
                        },
                        credentials: vec![Credential {
                            cred_type: String::from("cookie"),
                            name: config.session_cookie_name.to_owned(),
                            attributes: format!(
                                "Domain={}; Path=/; Secure; HttpOnly; SameSite=None",
                                config.domain
                            ),
                        }],
                    };
                    tracing::debug!("writing registration response: {:?}", registration);
                    // write out the new session cookie, it will be short-lived
                    let mut cookie =
                        Cookie::new(config.session_cookie_name, access_token.id.to_string());
                    cookie.set_max_age(Duration::seconds(60));

                    tracing::info!("wrote cookie using: {}", &access_token.id.to_string());
                    return Ok((StatusCode::OK, Json(registration)).into_response());
                } else {
                    tracing::error!("session not found, used {}", ticket);
                    return Ok((StatusCode::BAD_REQUEST, "Invalid DBSC request".to_owned())
                        .into_response());
                }
            } else {
                tracing::error!("failed to upgrade session");
                return Ok(
                    (StatusCode::BAD_REQUEST, "Invalid DBSC request".to_owned()).into_response()
                );
            }
        } else {
            tracing::error!("No jwt present.");
        }
    } else {
        // Is this really a problem? Shouldn't we just use the session ID?
        tracing::error!("No ticket cookie present");
    }

    tracing::error!("FAIL::start_session -> fell through...");
    Ok((StatusCode::BAD_REQUEST, "Invalid DBSC request".to_owned()).into_response())
}

pub async fn dbsc_refresh_session(
    State(session_manager): State<SharedSessionManager>,
    State(config): State<AppConfig>,
    State(_dbsc_config): State<dbsc::Config>,
    headers: HeaderMap,
    jar: CookieJar,
    body: String,
) -> Result<Response, DbscError> {
    let mut session_manager = session_manager.lock().await;
    if let Some(session_id_header) = headers.get("sec-secure-session-id") {
        let session_id = session_id_header.to_str()?;
        tracing::debug!("session id from header: {}", session_id);

        if !session_manager.session_exists(session_id).await {
            tracing::error!("unknown session id={session_id}, cannot refresh. terminating");
            return Ok((StatusCode::OK, "{\"continue\": false}").into_response());
        }

        match headers.get("secure-session-response") {
            Some(secure_session_response) => {
                // 1. browser has completed the challenge
                // in which case there will be a 'Secure-Session-Response' header with a JWT proof we need to validate
                if let Some(session) = session_manager.get_session_by_id(session_id).await {
                    let jwt = secure_session_response.to_str()?;

                    // use the session JWK to validate the refresh request challenge
                    let mut validation = Validation::new(Algorithm::ES256);
                    validation.required_spec_claims = HashSet::new();
                    validation.validate_exp = false;

                    if let Some(refresh_token) = &session.refresh_token {
                        if let Some(decoding_key) = &refresh_token.decoding_key()? {
                            let claims = decode::<Claims>(jwt, decoding_key, &validation)
                                .context("reading claims")?
                                .claims;

                            if claims.jti != session.last_challenge {
                                tracing::error!(
                                    "failed challenge, submitted={}, expected={}. terminating",
                                    claims.jti,
                                    session.last_challenge
                                );
                                return Ok(
                                    (StatusCode::OK, "{\"continue\": false}").into_response()
                                );
                            }
                        } else {
                            tracing::error!("no decoding key from refresh token, terminating");
                            return Ok((StatusCode::OK, "{\"continue\": false}").into_response());
                        }
                    } else {
                        tracing::error!("no refresh token on session");
                        return Ok((StatusCode::OK, "{\"continue\": false}").into_response());
                    }

                    let access_token = jar.get(&config.session_cookie_name);

                    tracing::debug!("Existing access token from cookie = {:?}", access_token);

                    let new_access_token = session_manager
                        .refresh_session(&session.id.to_string())
                        .await
                        .with_context(|| "failed during refresh session")?;

                    let mut cookie =
                        Cookie::new(config.session_cookie_name, new_access_token.id.to_string());
                    cookie.set_max_age(Duration::seconds(30));

                    tracing::info!(
                        "Successful refresh challenge, rotating short-lived session to {}",
                        new_access_token.id
                    );
                    // TODO return the session registration JSON here, which allows us to change the session_identifier (if we need to)
                    Ok((StatusCode::OK, jar.add(cookie), "").into_response())
                } else {
                    tracing::error!(
                        "invalid refresh request, no session found for {}",
                        session_id
                    );
                    Ok((StatusCode::OK, "{\"continue\": false}").into_response())
                }
            }
            None => {
                // 2. browser is attempting to refresh the session, but we haven't challenged them yet
                // we respond back with a HTTP 403 and a new Secure-Session-Challenge: "challenge_value";id="session_id"
                if let Some(session) = session_manager.get_session_by_id(session_id).await {
                    let challenge_header_value =
                        format!(r#""{}";id="{}""#, &session.last_challenge, session_id);

                    tracing::info!("Issuing challenge -> {}", &challenge_header_value);
                    Ok((
                        StatusCode::FORBIDDEN,
                        [("Secure-Session-Challenge", challenge_header_value)],
                        "",
                    )
                        .into_response())
                } else {
                    unimplemented!()
                }
            }
        }
    } else {
        dbg!(&headers, &jar, &body);
        tracing::error!("invalid refresh request, no session id present. terminating");
        Ok((StatusCode::OK, "{\"continue\": false}").into_response())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

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
