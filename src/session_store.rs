use std::collections::BTreeMap;

use chrono::{DateTime, TimeDelta, Utc};
use cookie::time::Duration;
use jsonwebtoken::{DecodingKey, jwk::Jwk};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::dbsc::routes::DbscError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub expiry: DateTime<Utc>,
    pub last_challenge: String,
    pub refresh_token: Option<RefreshToken>,
    // more state that makes this backing session useful...
}

/// Even though this naming sounds like OAuth, it is not. Do not expect the same constraints / behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    pub id: Uuid,
    pub expiry: DateTime<Utc>,
    pub jwk: Option<Jwk>,
}

impl RefreshToken {
    pub fn decoding_key(&self) -> Result<Option<DecodingKey>, anyhow::Error> {
        match &self.jwk {
            Some(key) => Ok(Some(DecodingKey::from_jwk(key)?)),
            None => Ok(None),
        }
    }
}

/// Even though this naming sounds like OAuth, it is not. Do not expect the same constraints / behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken {
    pub id: Uuid,
    pub session_id: Uuid,
    pub expiry: DateTime<Utc>,
    pub jwk: Option<Jwk>,
    pub challenge: String,
}

impl AccessToken {
    pub fn new(session: &Session) -> Self {
        Self {
            id: Uuid::new_v4(),
            session_id: session.id,
            expiry: Utc::now() + TimeDelta::hours(24),
            jwk: None,
            challenge: format!("challenge-{}", Uuid::new_v4()),
        }
    }

    pub fn expiry_from_now(&self) -> Duration {
        Duration::seconds((self.expiry - Utc::now()).num_seconds())
    }

    pub fn is_refreshable(&self) -> bool {
        self.jwk.is_some() && self.expiry_from_now() >= Duration::seconds(1)
    }
}

#[derive(Debug)]
pub struct SessionManager {
    /// base session id -> Session
    sessions: BTreeMap<String, Session>,
    access_tokens: BTreeMap<String, AccessToken>,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            access_tokens: BTreeMap::new(),
            sessions: BTreeMap::new(),
        }
    }

    pub async fn session_exists(&self, session_id: &str) -> bool {
        self.sessions.contains_key(session_id)
    }

    pub async fn get_session_by_id(&self, session_id: &str) -> Option<Session> {
        self.sessions.get(session_id).map(|it| it.clone())
    }

    pub async fn list_known_session_ids(&self) -> Vec<String> {
        self.sessions.keys().map(|k| k.clone()).collect()
    }

    pub async fn get_session(&self, access_token: &str) -> Option<Session> {
        if let Some(token) = self.access_tokens.get(access_token) {
            self.sessions
                .get(&token.session_id.to_string())
                .map(|it| it.clone())
        } else {
            None
        }
    }

    pub async fn rotate_challenge(&mut self, session_id: &str) -> Result<String, DbscError> {
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.last_challenge = format!("rot-{}", Uuid::new_v4());
            Ok(session.last_challenge.clone())
        } else {
            Err(anyhow::format_err!("session id {session_id} not found").into())
        }
    }

    pub async fn create_short_lived_session(&mut self) -> (Session, AccessToken) {
        let session = Session {
            id: Uuid::new_v4(),
            expiry: Utc::now() + TimeDelta::hours(24),
            last_challenge: format!("initial-{}", Uuid::new_v4()),
            refresh_token: None,
        };
        {
            self.sessions
                .insert(session.id.to_string(), session.clone());
        }

        let access_token = AccessToken::new(&session);
        {
            self.access_tokens
                .insert(access_token.id.to_string(), access_token.clone());
        }
        (session, access_token)
    }

    pub async fn upgrade_session_to_refreshable(
        &mut self,
        access_token_id: &str,
        jwk: Jwk,
    ) -> Result<(AccessToken, RefreshToken), String> {
        if let Some(access_token) = self.access_tokens.get(access_token_id) {
            if let Some(session) = self.sessions.get_mut(&access_token.session_id.to_string()) {
                let refresh_token = RefreshToken {
                    id: Uuid::new_v4(),
                    expiry: session.expiry,
                    jwk: Some(jwk),
                };
                session.last_challenge = format!("refresh-challenge-{}", Uuid::new_v4());
                session.refresh_token = Some(refresh_token.clone());

                // invalidate the existing short-lived access_token
                self.access_tokens.remove(access_token_id);
                // insert the new short-lived session access_token
                let new_access_token = AccessToken::new(session);
                self.access_tokens
                    .insert(new_access_token.id.to_string(), new_access_token.clone());
                // return the new access token
                tracing::info!(
                    "Upgraded session={} to refreshable and rotated access_token from {} to {}",
                    session.id,
                    access_token_id,
                    new_access_token.id
                );
                Ok((new_access_token, refresh_token))
            } else {
                Err(String::from("session id was invalid"))
            }
        } else {
            Err(String::from("invalid access token, not found."))
        }
    }

    pub async fn refresh_session(
        &mut self,
        session_id: &str,
    ) -> Result<AccessToken, anyhow::Error> {
        if let Some(refreshable) = self.sessions.get_mut(session_id) {
            refreshable.last_challenge = format!("refreshed-challenge-{}", Uuid::new_v4());
            let new_access_token = AccessToken::new(refreshable);

            // TODO invalidate any existing short-lived session(s)
            // since we don't seem to get the ticket cookie (expired already?)
            // let removed = self.sessions.remove(refresh_token);

            self.access_tokens
                .insert(new_access_token.id.to_string(), new_access_token.clone());

            tracing::info!(
                "invalidated short-lived access_token (TODO) and issued new short-lived access_token: {:?}",
                new_access_token
            );
            Ok(new_access_token)
        } else {
            Err(anyhow::anyhow!(format!(
                "session not found: {}",
                session_id
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::jwk::Jwk;

    use crate::session_store::SessionManager;

    #[tokio::test]
    async fn exercise_lifecycle() {
        let mut manager = SessionManager::new();
        let (_session, access_token) = manager.create_short_lived_session().await;

        let result = manager
            .upgrade_session_to_refreshable(
                &access_token.id.to_string(),
                Jwk {
                    common: todo!(),
                    algorithm: todo!(),
                },
            )
            .await;
        assert!(result.is_ok());
    }
}
