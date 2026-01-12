use std::collections::BTreeMap;

use chrono::{DateTime, TimeDelta, Utc};
use cookie::time::Duration;
use jsonwebtoken::jwk::Jwk;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub refresh_token: String,
    pub expiry: DateTime<Utc>,
    pub jwk: Option<Jwk>,
    // probably need to keep track of this, should be part of the refresh I would think..?
    pub challenge: String,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    pub fn new() -> Self {
        Self {
            id: Uuid::new_v4(),
            refresh_token: "fake".to_owned(),
            expiry: Utc::now() + TimeDelta::seconds(30),
            jwk: None,
            challenge: "fake".to_owned(),
        }
    }

    pub fn expiry_from_now(&self) -> Duration {
        Duration::seconds((self.expiry - Utc::now()).num_seconds())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshableSession {
    pub id: Uuid,
    pub expiry: DateTime<Utc>,
    pub jwk: Jwk,
    pub challenge: String,
}

#[derive(Debug, Clone)]
pub struct SessionManager {
    /// base session id -> Session
    pub refreshable_sessions: BTreeMap<String, RefreshableSession>,
    pub sessions: BTreeMap<String, Session>,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            refreshable_sessions: BTreeMap::new(),
            sessions: BTreeMap::new(),
        }
    }

    pub fn create_short_lived_session(&mut self) -> Session {
        let session = Session::new();
        self.sessions
            .insert(session.id.to_string(), session.clone());
        session
    }

    pub fn upgrade_session_to_refreshable(
        &mut self,
        session: Session,
        jwk: Jwk,
    ) -> (Session, RefreshableSession) {
        let refreshable = RefreshableSession {
            id: Uuid::new_v4(),
            expiry: Utc::now() + TimeDelta::days(30),
            jwk,
            challenge: format!("challenge-{}", Uuid::new_v4()),
        };
        // invalidate the short-lived session
        self.sessions.remove(&session.id.to_string());
        let session = Session::new();

        // insert the new refreshable session
        self.refreshable_sessions
            .insert(refreshable.id.to_string(), refreshable.clone());

        // return the short-lived and refreshable sessions
        (session, refreshable)
    }
}
