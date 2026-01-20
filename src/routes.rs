use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse},
};
use axum_extra::extract::{CookieJar, cookie::Cookie};

use crate::{AppState, SharedSessionManager};

#[axum::debug_handler]
pub async fn index(State(session_manager): State<SharedSessionManager>) -> impl IntoResponse {
    dbg!(&session_manager);
    Html(format!(
        "(debug) known sessions: {}<br><a href=\"/login\">Login</a> | <a href=\"/protected\">Protected page</a>",
        &session_manager
            .read()
            .await
            .sessions
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(", "),
    ))
}

#[axum::debug_handler]
pub async fn login(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    // insert the session using the regular session id (we'll switch to refreshable in the /StartSession call)
    let (session, access_token) = state
        .session_manager
        .write()
        .await
        .create_short_lived_session();

    let mut cookie = Cookie::new(
        state.config.session_cookie_name,
        access_token.id.to_string(),
    );
    cookie.set_max_age(access_token.expiry_from_now());

    // direct browser to initiate DBSC if supported
    (
        StatusCode::OK,
        [(
            "Secure-Session-Registration",
            format!(
                r#"(ES256);path="/StartSession";challenge="{}""#,
                &session.last_challenge
            ),
        )],
        jar.add(cookie),
        Html(format!(
            "you logged in! ticket={} (attached to session={})<br><a href='/'>Home</a>",
            &access_token.id, &session.id
        )),
    )
}

#[axum::debug_handler]
pub async fn protected_path(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    if let Some(ticket) = jar.get(&state.config.session_cookie_name) {
        let ticket = ticket.value();
        let ds = state.session_manager.read().await;
        if let Some(session) = ds.sessions.get(ticket) {
            dbg!(session);
            return (
                StatusCode::OK,
                Html(
                    "You are logged in as {ticket} and can access this page/data<br><a href=\"/\">Home</a>",
                ),
            );
        } else {
            println!("protected::unauthorized: no session for {ticket} (from cookie)");
        }
    }

    println!("protected::unauthorized: no ticket");
    (
        StatusCode::UNAUTHORIZED,
        Html("Please login to access this resource"),
    )
}
