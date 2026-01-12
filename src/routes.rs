use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse},
};
use axum_extra::extract::{CookieJar, cookie::Cookie};

use crate::{AppConfig, AppState, SharedSessionManager, session_store::Session};

#[axum::debug_handler]
pub async fn index(State(session_manager): State<SharedSessionManager>) -> impl IntoResponse {
    dbg!(&session_manager);
    Html(format!(
        "(debug) known sessions: {}<br>refreshable sessions: {}",
        &session_manager
            .read()
            .await
            .sessions
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(", "),
        &session_manager
            .read()
            .await
            .refreshable_sessions
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

#[axum::debug_handler]
pub async fn login(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    // insert the session using the regular session id (we'll switch to refreshable in the /StartSession call)
    let session: Session = state
        .session_manager
        .write()
        .await
        .create_short_lived_session();

    let mut cookie = Cookie::new(state.config.session_cookie_name, session.id.to_string());
    cookie.set_max_age(session.expiry_from_now());

    // direct browser to initiate DBSC if supported
    (
        StatusCode::OK,
        [(
            "Secure-Session-Registration",
            format!(
                r#"(ES256);path="/StartSession";challenge="{}""#,
                &session.challenge
            ),
        )],
        jar.add(cookie),
        format!("you logged in! ticket={}", &session.id),
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
                "You are logged in as {ticket} and can access this page/data",
            );
        } else {
            println!("protected::unauthorized: no session for {ticket} (from cookie)");
        }
    }

    println!("protected::unauthorized: no ticket");
    (
        StatusCode::UNAUTHORIZED,
        "Please login to access this resource",
    )
}
