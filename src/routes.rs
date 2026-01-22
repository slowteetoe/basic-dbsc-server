use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse},
};
use axum_extra::extract::{CookieJar, cookie::Cookie};

use crate::{AppConfig, AppState, SharedSessionManager, dbsc};

#[axum::debug_handler]
pub async fn index(State(session_manager): State<SharedSessionManager>) -> impl IntoResponse {
    dbg!(&session_manager);
    Html(format!(
        "(debug) known sessions: {}<br><a href=\"/login\">Login</a> | <a href=\"/protected\">Protected page</a>",
        session_manager
            .lock()
            .await
            .list_known_session_ids()
            .await
            .join(", "),
    ))
}

#[axum::debug_handler(state=AppState)]
pub async fn login(
    State(session_manager): State<SharedSessionManager>,
    State(config): State<AppConfig>,
    State(dbsc_config): State<dbsc::Config>,
    jar: CookieJar,
) -> impl IntoResponse {
    // insert the session using the regular session id (we'll switch to refreshable in the /StartSession call)
    let (session, access_token) = session_manager
        .lock()
        .await
        .create_short_lived_session()
        .await;

    let mut cookie = Cookie::new(config.session_cookie_name, access_token.id.to_string());
    cookie.set_max_age(access_token.expiry_from_now());

    // direct browser to initiate DBSC if supported
    (
        StatusCode::OK,
        [(
            "Secure-Session-Registration",
            format!(
                r#"(ES256);path="{}";challenge="{}""#,
                &dbsc_config.start_session_route, &session.last_challenge
            ),
        )],
        jar.add(cookie),
        Html(format!(
            "you logged in! ticket={} (attached to session={})<br><a href='/'>Home</a>",
            &access_token.id, &session.id
        )),
    )
}

#[axum::debug_handler(state=AppState)]
pub async fn protected_path(
    State(session_manager): State<SharedSessionManager>,
    State(app_config): State<AppConfig>,
    jar: CookieJar,
) -> impl IntoResponse {
    if let Some(ticket) = jar.get(&app_config.session_cookie_name) {
        let ticket = ticket.value();
        if let Some(session) = session_manager.lock().await.get_session(ticket).await {
            dbg!(session);
            return (
                StatusCode::OK,
                Html(format!(
                    "You are logged in as {ticket} and can access this page/data<br><a href=\"/\">Home</a>"
                )),
            );
        } else {
            tracing::info!("protected::unauthorized: no session for {ticket} (from cookie)");
        }
    }

    tracing::info!("protected::unauthorized: no ticket");
    (
        StatusCode::UNAUTHORIZED,
        Html(String::from(
            "Please login to access this resource.<br><a href=\"/\">Home</a>",
        )),
    )
}
