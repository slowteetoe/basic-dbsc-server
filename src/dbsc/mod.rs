pub mod routes;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub start_session_route: String,
    pub refresh_session_route: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Claims {
    pub jti: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationResponse {
    pub session_identifier: String,
    pub refresh_url: String,
    pub scope: Scope,
    pub credentials: Vec<Credential>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    pub origin: String,
    pub include_site: bool,
    pub scope_specification: Vec<ScopeSpecification>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeSpecification {
    #[serde(rename = "type")]
    pub scope_type: String,
    pub domain: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub name: String,
    pub attributes: String,
}
