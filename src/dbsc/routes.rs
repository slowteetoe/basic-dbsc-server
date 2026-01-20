use std::collections::HashSet;

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

use cookie::time::Duration;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use uuid::Uuid;

use crate::{
    AppConfig, AppState, SharedSessionManager,
    dbsc::{self, Claims, Credential, RegistrationResponse, Scope},
};
use axum_extra::extract::{CookieJar, cookie::Cookie};

#[axum::debug_handler]
pub async fn dbsc_start_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Response {
    dbg!(&headers, &jar);
    if let Some(ticket) = jar.get(&state.config.session_cookie_name) {
        let ticket = ticket.value();
        tracing::info!("start_session -> existing ticket={}", ticket);
        if let Some(jwt) = headers.get("secure-session-response") {
            let jwt = jwt.to_str().unwrap();
            let header = decode_header(jwt).unwrap();

            let mut validation = Validation::new(header.alg);
            // exp is not in the DBSC claims
            validation.required_spec_claims = HashSet::new();
            validation.validate_exp = false;

            let jwk = header.jwk.unwrap();

            let claims =
                match decode::<Claims>(jwt, &DecodingKey::from_jwk(&jwk).unwrap(), &validation) {
                    Ok(data) => data.claims,
                    Err(e) => panic!("{}", e),
                };

            let mut session_manager = state.session_manager.write().await;

            if let Some(session) = session_manager.clone().sessions.get_mut(ticket) {
                // we had a session, check the challenge
                if claims.jti != session.last_challenge {
                    tracing::error!(
                        "challenge failed: claims={} vs session={}",
                        claims.jti,
                        session.last_challenge
                    );
                    return (StatusCode::FORBIDDEN, "challenge failed".to_owned()).into_response();
                }
                tracing::info!("session found, upgrading...");
                let result = session_manager.upgrade_session_to_refreshable(ticket, jwk);
                if result.is_err() {
                    tracing::error!("failed to upgrade session: {:?}", result.err());
                    return (StatusCode::BAD_REQUEST, "Invalid DBSC request".to_owned())
                        .into_response();
                }

                let (access_token, _refresh_token) = result.unwrap();

                let registration = RegistrationResponse {
                    session_identifier: session.id.to_string(),
                    refresh_url: state.dbsc_config.refresh_session_route.to_string(),
                    scope: Scope {
                        origin: format!("https://{}", state.config.domain),
                        include_site: true,
                        scope_specification: vec![],
                    },
                    credentials: vec![Credential {
                        cred_type: String::from("cookie"),
                        name: state.config.session_cookie_name.to_owned(),
                        attributes: format!(
                            "Domain={}; Path=/; Secure; HttpOnly; SameSite=None",
                            state.config.domain
                        ),
                    }],
                };
                tracing::debug!("writing registration response: {:?}", registration);
                // write out the new session cookie, it will be short-lived
                let mut cookie = Cookie::new(
                    state.config.session_cookie_name,
                    access_token.id.to_string(),
                );
                cookie.set_max_age(Duration::seconds(60));

                tracing::info!("wrote cookie using: {}", &access_token.id.to_string());
                return (StatusCode::OK, Json(registration)).into_response();
            }
        }
    }
    tracing::error!("FAIL::start_session -> fell through...");
    (StatusCode::BAD_REQUEST, "Invalid DBSC request".to_owned()).into_response()
}

pub async fn dbsc_refresh_session(
    State(session_manager): State<SharedSessionManager>,
    State(config): State<AppConfig>,
    State(_dbsc_config): State<dbsc::Config>,
    headers: HeaderMap,
    jar: CookieJar,
    body: String,
) -> Response {
    // FIXME - test this, seems like we're missing the Sec-Secure-Session-Id header?
    let session_id = headers.get("sec-secure-session-id");
    if session_id.is_none() {
        dbg!(&headers, &jar, &body);
        tracing::error!("invalid refresh request, no session id present. terminating");
        return (StatusCode::OK, "{\"continue\": false}").into_response();
    }

    let session_id = session_id
        .unwrap()
        .to_str()
        .expect("session_id should have been a valid string");

    if session_manager
        .read()
        .await
        .sessions
        .contains_key(session_id)
    {
        let secure_session_response = headers.get("Secure-Session-Response");

        // there are two valid paths at this point:
        if secure_session_response.is_none() {
            if let Some(session) = session_manager.write().await.sessions.get_mut(session_id) {
                // 1. browser is attempting to refresh the session, but we haven't challenged them yet - we respond back with a
                // HTTP 403 and a new Secure-Session-Challenge: "challenge_value";id="session_id"
                session.last_challenge = format!("refresh-challenge-{}", Uuid::new_v4());

                let challenge_header_value =
                    format!(r#""{}";id="{}""#, &session.last_challenge, session_id);

                tracing::info!("Issuing challenge -> {}", &challenge_header_value);
                (
                    StatusCode::FORBIDDEN,
                    [("Secure-Session-Challenge", challenge_header_value)],
                    "",
                )
                    .into_response()
            } else {
                unimplemented!()
            }
        } else {
            let session = session_manager
                .read()
                .await
                .sessions
                .get(session_id)
                .expect("should have retrieved refreshable session")
                .clone();
            // 2. browser has completed the challenge
            // in which case there will be a 'Secure-Session-Response' header with a JWT proof we need to validate
            let jwt = secure_session_response
                .unwrap()
                .to_str()
                .expect("ssr should have been a valid string");

            // use the session JWK to validate the refresh request challenge
            let mut validation = Validation::new(Algorithm::ES256);
            validation.required_spec_claims = HashSet::new();
            validation.validate_exp = false;

            let claims = match decode::<Claims>(
                jwt,
                &DecodingKey::from_jwk(&session.refresh_token.unwrap().jwk.unwrap()).unwrap(),
                &validation,
            ) {
                Ok(data) => data.claims,
                Err(e) => panic!("{}", e),
            };
            if claims.jti != session.last_challenge {
                tracing::error!(
                    "failed challenge, submitted={}, expected={}. terminating",
                    claims.jti,
                    session.last_challenge
                );
                return (StatusCode::OK, "{\"continue\": false}").into_response();
            }

            let access_token = jar.get(&config.session_cookie_name);

            tracing::debug!("Existing access token from cookie = {:?}", access_token);

            let new_access_token = session_manager
                .write()
                .await
                .refresh_session(&session.id.to_string());

            let mut cookie =
                Cookie::new(config.session_cookie_name, new_access_token.id.to_string());
            cookie.set_max_age(Duration::seconds(30));

            tracing::info!(
                "Successful refresh challenge, rotating short-lived session to {}",
                new_access_token.id
            );
            // TODO return the session registration JSON here, which allows us to change the session_identifier if we need
            (StatusCode::OK, jar.add(cookie), "").into_response()
        }
    } else {
        tracing::error!("unknown session id={session_id}, cannot refresh. terminating");
        (StatusCode::OK, "{\"continue\": false}").into_response()
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
