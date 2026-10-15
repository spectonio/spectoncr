//! Audit event shapes for the chained registry log.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// High-level category for filtering and retention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Auth,
    Push,
    Pull,
    Delete,
    Sign,
    Promote,
    Policy,
    Key,
    Admin,
    Rebuild,
    Scan,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Push => "push",
            Self::Pull => "pull",
            Self::Delete => "delete",
            Self::Sign => "sign",
            Self::Promote => "promote",
            Self::Policy => "policy",
            Self::Key => "key",
            Self::Admin => "admin",
            Self::Rebuild => "rebuild",
            Self::Scan => "scan",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "auth" => Some(Self::Auth),
            "push" => Some(Self::Push),
            "pull" => Some(Self::Pull),
            "delete" => Some(Self::Delete),
            "sign" => Some(Self::Sign),
            "promote" => Some(Self::Promote),
            "policy" => Some(Self::Policy),
            "key" => Some(Self::Key),
            "admin" => Some(Self::Admin),
            "rebuild" => Some(Self::Rebuild),
            "scan" => Some(Self::Scan),
            _ => None,
        }
    }
}

/// Who performed the action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Actor {
    pub sub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ua: Option<String>,
}

impl Actor {
    pub fn system() -> Self {
        Self {
            sub: "system".into(),
            role: Some("system".into()),
            source_ip: None,
            ua: None,
        }
    }
}

/// Optional registry subject (tenant/project/repo/ref/digest).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Subject {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    Failure { code: String },
}

impl Outcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure { .. } => "failure",
        }
    }

    pub fn error_code(&self) -> Option<&str> {
        match self {
            Self::Success => None,
            Self::Failure { code } => Some(code.as_str()),
        }
    }
}

/// Input event — callers never set hash fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub at: DateTime<Utc>,
    pub category: Category,
    pub action: String,
    pub actor: Actor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<Subject>,
    pub outcome: Outcome,
    #[serde(default)]
    pub attributes: Map<String, Value>,
}

impl AuditEvent {
    pub fn success(category: Category, action: impl Into<String>, actor: Actor) -> Self {
        Self {
            at: Utc::now(),
            category,
            action: action.into(),
            actor,
            subject: None,
            outcome: Outcome::Success,
            attributes: Map::new(),
        }
    }

    pub fn with_subject(mut self, subject: Subject) -> Self {
        self.subject = Some(subject);
        self
    }

    pub fn with_attr(mut self, key: impl Into<String>, value: Value) -> Self {
        self.attributes.insert(key.into(), value);
        self
    }
}

/// Persisted row including chain links.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRow {
    pub id: i64,
    pub event: AuditEvent,
    pub tenant: Option<String>,
    pub prev_hash: Option<Vec<u8>>,
    pub row_hash: Vec<u8>,
    pub hmac_key_id: String,
}

/// Stable payload used for hashing — field order is part of the contract.
#[derive(Serialize)]
pub(crate) struct CanonicalPayload<'a> {
    pub at: &'a DateTime<Utc>,
    pub category: &'a str,
    pub action: &'a str,
    pub actor_sub: &'a str,
    pub actor_ip: Option<&'a str>,
    pub actor_ua: Option<&'a str>,
    pub subject: Option<&'a Subject>,
    pub outcome: &'a str,
    pub error_code: Option<&'a str>,
    pub attributes: &'a Map<String, Value>,
    pub hmac_key_id: &'a str,
}
