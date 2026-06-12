use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use axum::body::Body;
use serde::Deserialize;
use serde_json::Value;
use tower_oauth2_resource_server::layer::OAuth2ResourceServerLayer;
use tower_oauth2_resource_server::server::OAuth2ResourceServer;
use tower_oauth2_resource_server::tenant::TenantConfiguration;

use crate::config::{OAuthAdminConfig, OAuthClaimsConfig, OAuthConfig};

#[derive(Clone)]
pub struct AuthState {
    claim_config: ClaimConfig,
    backend: Option<OAuthBackend>,
    /// Blake3 hash of the static admin API key, if one was configured.
    admin_api_key_hash: Option<[u8; 32]>,
}

impl AuthState {
    pub async fn from_config(config: &OAuthConfig, admin_api_key: Option<&str>) -> Result<Self> {
        let claim_config = ClaimConfig::from_configs(&config.claims, &config.admin);

        let admin_api_key_hash = admin_api_key
            .filter(|key| !key.trim().is_empty())
            .map(|key| *blake3::hash(key.as_bytes()).as_bytes());

        if admin_api_key_hash.is_none() {
            // No static key — OAuth must be fully operational.
            if claim_config.admin_group.is_none() {
                return Err(anyhow!(
                    "oauth.admin.group must be set to enforce admin permissions"
                ));
            }

            if claim_config.groups_claim.is_none() {
                return Err(anyhow!(
                    "oauth.claims.groups must be configured to validate admin membership"
                ));
            }
        }

        let issuer = config
            .issuer_url
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());

        // Build the OAuth backend only when an issuer is configured.  When only
        // a static admin API key is set the OAuth stack is optional.
        let backend = if let Some(issuer) = issuer {
            let mut tenant_builder = TenantConfiguration::builder(issuer);
            if let Some(identifier) = config
                .tenant_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                tenant_builder = tenant_builder.identifier(identifier);
            }
            if let Some(jwks_url) = config
                .jwks_url
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                tenant_builder = tenant_builder.jwks_url(jwks_url);
            }
            tenant_builder = tenant_builder
                .jwks_refresh_interval(Duration::from_secs(config.jwks_refresh_interval_secs));

            if !config.audiences.is_empty() {
                let audiences = config
                    .audiences
                    .iter()
                    .map(|aud| aud.trim())
                    .filter(|aud| !aud.is_empty())
                    .collect::<Vec<_>>();
                if !audiences.is_empty() {
                    tenant_builder = tenant_builder.audiences(&audiences);
                }
            }

            let tenant = tenant_builder
                .build()
                .await
                .map_err(|err| anyhow!("failed to build OAuth tenant: {err}"))?;

            let server = OAuth2ResourceServer::<AuthClaims>::builder()
                .add_tenant(tenant)
                .build()
                .await
                .map_err(|err| anyhow!("failed to construct OAuth2 resource server: {err}"))?;

            Some(OAuthBackend::new(server))
        } else {
            if admin_api_key_hash.is_none() {
                return Err(anyhow!("oauth.issuer_url must be configured"));
            }
            None
        };

        Ok(Self {
            claim_config,
            backend,
            admin_api_key_hash,
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.backend.is_some()
    }

    pub fn oauth_layer(&self) -> Option<OAuth2ResourceServerLayer<Body, AuthClaims>> {
        self.backend.as_ref().map(|backend| backend.layer())
    }

    pub fn subject_from_claims(&self, claims: &AuthClaims) -> Option<String> {
        self.claim_config.subject_from_claims(claims)
    }

    pub fn user_has_admin_access(&self, claims: &AuthClaims) -> bool {
        self.claim_config.has_admin_group(claims)
    }

    /// Returns `true` when a static admin API key is configured and the supplied
    /// `key` matches it.  The comparison is done against a stored blake3 hash so
    /// the plaintext key is never kept in memory beyond initial startup.
    pub fn is_valid_admin_api_key(&self, key: &str) -> bool {
        match &self.admin_api_key_hash {
            Some(expected) => blake3::hash(key.as_bytes()).as_bytes() == expected,
            None => false,
        }
    }

    /// Returns `true` when a static admin API key has been configured.
    pub fn has_admin_api_key(&self) -> bool {
        self.admin_api_key_hash.is_some()
    }

    #[cfg(test)]
    pub fn disabled_for_tests() -> Self {
        Self {
            claim_config: ClaimConfig::default(),
            backend: None,
            admin_api_key_hash: None,
        }
    }

    #[cfg(test)]
    pub fn with_admin_api_key_for_tests(key: &str) -> Self {
        Self {
            claim_config: ClaimConfig::default(),
            backend: None,
            admin_api_key_hash: Some(*blake3::hash(key.as_bytes()).as_bytes()),
        }
    }

    #[cfg(test)]
    pub async fn for_tests_with_layer() -> Self {
        const TEST_JWKS: &str = r#"{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "test-key",
      "n": "oEz_RrupHP9d9XiFbXLoJMwG-75Z18t4ziBy2PHTZHxkHOep7aFeNj-13NmIcL4ooj-2nxrLhWbgA2iBaWr95wKkf5peTsc-5Q6-B2uCcn9xPSQK08Y_jNVhtly3mAOdsT4Y9mQIO_oqaqEyzutypZBEu-18NkbGVwkNhG9sxvUjFXHvMoJs5iwILaDA2FhuEioIDzOy-ZjD8p928ye2v8CdPWl1xPxoBXd2KIe3RkocRDxLeeBg3wH8a9tQ5Z7fOmiXiAI8_lN57zYf078yazvLUlKzCo1pQoR25MU51d7zgI_I7H2Fb5PZGcCmfvN1Up41OfEQyMLL6JYyoP23XQ",
      "e": "AQAB"
    }
  ]
}"#;

        let tenant = TenantConfiguration::static_builder(TEST_JWKS)
            .identifier("test-tenant")
            .build()
            .expect("failed to build test tenant");

        let server = OAuth2ResourceServer::<AuthClaims>::builder()
            .add_tenant(tenant)
            .build()
            .await
            .expect("failed to build test oauth server");

        let claim_config = ClaimConfig {
            subject_claim: "sub".to_string(),
            groups_claim: Some("groups".to_string()),
            admin_group: Some("admin".to_string()),
            admin_case_sensitive: false,
        };

        Self {
            claim_config,
            backend: Some(OAuthBackend::new(server)),
            admin_api_key_hash: None,
        }
    }
}

#[derive(Clone)]
pub struct OAuthBackend {
    server: Arc<OAuth2ResourceServer<AuthClaims>>,
}

impl OAuthBackend {
    fn new(server: OAuth2ResourceServer<AuthClaims>) -> Self {
        Self {
            server: Arc::new(server),
        }
    }

    pub fn layer(&self) -> OAuth2ResourceServerLayer<Body, AuthClaims> {
        self.server.as_ref().into_layer::<Body>()
    }
}

#[derive(Clone)]
struct ClaimConfig {
    subject_claim: String,
    groups_claim: Option<String>,
    admin_group: Option<String>,
    admin_case_sensitive: bool,
}

impl ClaimConfig {
    fn from_configs(claims: &OAuthClaimsConfig, admin: &OAuthAdminConfig) -> Self {
        let subject_claim = claims.subject.trim();
        let subject_claim = if subject_claim.is_empty() {
            "sub"
        } else {
            subject_claim
        }
        .to_string();

        let groups_claim = claims.groups.trim();
        let groups_claim = if groups_claim.is_empty() {
            None
        } else {
            Some(groups_claim.to_string())
        };

        let admin_group = admin.group.trim();
        let admin_group = if admin_group.is_empty() {
            None
        } else {
            Some(admin_group.to_string())
        };

        Self {
            subject_claim,
            groups_claim,
            admin_group,
            admin_case_sensitive: admin.group_case_sensitive,
        }
    }

    fn subject_from_claims(&self, claims: &AuthClaims) -> Option<String> {
        self.lookup_string(&self.subject_claim, claims)
    }

    fn has_admin_group(&self, claims: &AuthClaims) -> bool {
        let expected = match self.admin_group.as_deref() {
            Some(value) => value,
            None => return false,
        };

        let groups_claim = match self.groups_claim.as_deref() {
            Some(value) => value,
            None => return false,
        };

        let groups = match self.lookup_values(groups_claim, claims) {
            Some(values) => values,
            None => return false,
        };

        let expected = expected.to_string();

        groups.into_iter().any(|group| {
            if self.admin_case_sensitive {
                group == expected
            } else {
                group.eq_ignore_ascii_case(expected.as_str())
            }
        })
    }

    fn lookup_string(&self, name: &str, claims: &AuthClaims) -> Option<String> {
        match name {
            "sub" => claims.sub.clone(),
            "iss" => claims.iss.clone(),
            "jti" => claims.jti.clone(),
            "aud" => claims.aud.first().cloned(),
            other => claims.extra.get(other).and_then(extract_string),
        }
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
    }

    fn lookup_values(&self, name: &str, claims: &AuthClaims) -> Option<Vec<String>> {
        if name == "aud" {
            if claims.aud.is_empty() {
                return None;
            }
            return Some(claims.aud.clone());
        }

        claims
            .extra
            .get(name)
            .and_then(extract_values)
            .map(|values| {
                values
                    .into_iter()
                    .map(|value| value.trim().to_owned())
                    .filter(|value| !value.is_empty())
                    .collect::<Vec<_>>()
            })
            .filter(|values| !values.is_empty())
    }
}

impl Default for ClaimConfig {
    fn default() -> Self {
        Self {
            subject_claim: "sub".to_string(),
            groups_claim: None,
            admin_group: None,
            admin_case_sensitive: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct AuthClaims {
    pub iss: Option<String>,
    pub sub: Option<String>,
    #[serde(default, deserialize_with = "deserialize_audience")]
    pub aud: Vec<String>,
    pub jti: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

fn extract_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

fn extract_values(value: &Value) -> Option<Vec<String>> {
    match value {
        Value::String(single) => {
            let tokens = single
                .split_whitespace()
                .map(|entry| entry.to_owned())
                .collect::<Vec<_>>();
            Some(if tokens.is_empty() {
                vec![single.clone()]
            } else {
                tokens
            })
        }
        Value::Array(values) => {
            let items = values
                .iter()
                .filter_map(|entry| entry.as_str().map(|value| value.to_owned()))
                .collect::<Vec<_>>();
            if items.is_empty() { None } else { Some(items) }
        }
        _ => None,
    }
}

fn deserialize_audience<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct AudienceVisitor;

    impl<'de> serde::de::Visitor<'de> for AudienceVisitor {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string or array of strings")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(vec![value.to_owned()])
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(vec![value])
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut values = Vec::new();
            while let Some(value) = seq.next_element::<String>()? {
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_any(AudienceVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_values_from_string_supports_whitespace() {
        let value = Value::String("admin users maintainers".into());
        let extracted = extract_values(&value).expect("values");
        assert_eq!(
            extracted,
            vec!["admin", "users", "maintainers"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn extract_values_from_array_filters_non_strings() {
        let value = Value::Array(vec![
            Value::String("admin".into()),
            Value::Bool(true),
            Value::String("users".into()),
        ]);

        let extracted = extract_values(&value).expect("values");
        assert_eq!(extracted, vec!["admin".to_string(), "users".to_string()]);
    }

    #[test]
    fn claim_config_resolves_subject() {
        let claims = AuthClaims {
            iss: Some("issuer".into()),
            sub: Some("user-123".into()),
            aud: vec!["audience".into()],
            jti: None,
            extra: HashMap::new(),
        };

        let config = ClaimConfig::default();
        assert_eq!(
            config.subject_from_claims(&claims).as_deref(),
            Some("user-123")
        );
    }

    #[test]
    fn claim_config_matches_admin_group_case_insensitive() {
        let mut extra = HashMap::new();
        extra.insert(
            "groups".to_string(),
            Value::Array(vec![
                Value::String("Users".into()),
                Value::String("ADMIN".into()),
            ]),
        );

        let claims = AuthClaims {
            iss: None,
            sub: Some("alice".into()),
            aud: Vec::new(),
            jti: None,
            extra,
        };

        let config = ClaimConfig {
            groups_claim: Some("groups".into()),
            admin_group: Some("admin".into()),
            ..Default::default()
        };

        assert!(config.has_admin_group(&claims));
    }
}
