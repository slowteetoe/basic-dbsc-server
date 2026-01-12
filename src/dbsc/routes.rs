use std::collections::HashSet;

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{TimeDelta, Utc};
use cookie::time::Duration;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use uuid::Uuid;

use crate::{
    AppConfig, AppState, SharedSessionManager,
    dbsc::{Claims, Credential, RegistrationResponse, Scope},
    session_store::Session,
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
        println!("start_session -> existing ticket={}", ticket);
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
                if claims.jti != session.challenge {
                    println!(
                        "challenge failed: claims={} vs session={}",
                        claims.jti, session.challenge
                    );
                    return (StatusCode::FORBIDDEN, "challenge failed".to_owned()).into_response();
                }
                println!("session found, upgrading...");
                let (new_session, refreshable_session) =
                    session_manager.upgrade_session_to_refreshable(session.clone(), jwk);

                let registration = RegistrationResponse {
                    session_identifier: refreshable_session.id.to_string(),
                    refresh_url: "/RefreshSession".to_owned(),
                    scope: Scope {
                        origin: format!("https://{}", state.config.domain),
                        include_site: true,
                        scope_specification: vec![],
                    },
                    credentials: vec![Credential {
                        cred_type: "cookie".to_owned(),
                        name: state.config.session_cookie_name.to_owned(),
                        attributes: format!(
                            "Domain={}; Path=/; Secure; HttpOnly; SameSite=None",
                            state.config.domain
                        ),
                    }],
                };
                // write out the new session cookie
                let mut cookie =
                    Cookie::new(state.config.session_cookie_name, new_session.id.to_string());
                cookie.set_max_age(new_session.expiry_from_now());

                return (StatusCode::OK, Json(registration)).into_response();
            }
        }
    }
    println!("start_session -> fell through...");
    (StatusCode::BAD_REQUEST, "Invalid DBSC request".to_owned()).into_response()
}

pub async fn dbsc_refresh_session(
    State(ds): State<SharedSessionManager>,
    State(config): State<AppConfig>,
    headers: HeaderMap,
    jar: CookieJar,
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

    let mut session_manager = ds.write().await;

    if let Some(session) = session_manager.sessions.get_mut(session_id) {
        let secure_session_response = headers.get("Secure-Session-Response");
        // there are two valid paths at this point:

        if secure_session_response.is_none() {
            // 1. browser is attempting to refresh the session, but we haven't challenged them yet - we respond back with a
            // HTTP 403 and a new Secure-Session-Challenge: "challenge_value";id="session_id"
            let new_challenge = format!("challenge-{}", Uuid::new_v4());
            session.challenge = new_challenge.clone();
            (
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
                .into_response()
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

            let mut validation = Validation::new(Algorithm::ES256);
            validation.required_spec_claims = HashSet::new();
            validation.validate_exp = false;

            let claims =
                match decode::<Claims>(jwt, &DecodingKey::from_jwk(jwk).unwrap(), &validation) {
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
                .sessions
                .insert(id.to_string(), session.clone());
            let mut cookie = Cookie::new(config.session_cookie_name, id.to_string());
            cookie.set_max_age(Duration::seconds(30));

            println!("Successful refresh challenge, rotating session to {id}");
            // TODO return the session registration JSON here, which allows us to change the session_identifier
            (StatusCode::OK, jar.add(cookie), "").into_response()
        }
    } else {
        println!("unknown session id={session_id}, cannot refresh. terminating");
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
