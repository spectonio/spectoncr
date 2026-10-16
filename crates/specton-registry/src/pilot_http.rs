//! HTTP surface for specton-pilot (design 019 / 007 chat sidebar).
//!
//! Kill-switch: `[pilot] enabled = false` (default) → routes return 403.

use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use specton_common::errors::RegistryError;
use specton_pilot::llm::echo::EchoClient;
use specton_pilot::{
    AnthropicClient, ChatConfig, ChatMessage, ChatRole, LlmClient, OllamaClient, OpenAiClient,
    RegistryClient, ToolCtx, default_tools, run_turn_with_budget,
};

use crate::{AppState, AuthenticatedClaims};

#[derive(Debug, Deserialize)]
pub struct PilotChatBody {
    pub message: String,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub history: Vec<ChatMessage>,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub tenant: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PilotChatResponse {
    pub reply: String,
    pub messages: Vec<ChatMessage>,
    pub tool_rounds: u32,
    pub session_id: Option<String>,
    pub backend: String,
}

fn build_llm(backend: &str, model: &str) -> Result<Arc<dyn LlmClient>, RegistryError> {
    match backend {
        "echo" | "" => Ok(Arc::new(EchoClient) as Arc<dyn LlmClient>),
        "anthropic" => {
            let key = std::env::var("ANTHROPIC_API_KEY").map_err(|_| {
                RegistryError::Forbidden {
                    reason: "ANTHROPIC_API_KEY required for pilot backend=anthropic".into(),
                }
            })?;
            Ok(Arc::new(AnthropicClient::new(model.to_string(), key)) as Arc<dyn LlmClient>)
        }
        "openai" => {
            let key = std::env::var("OPENAI_API_KEY").map_err(|_| {
                RegistryError::Forbidden {
                    reason: "OPENAI_API_KEY required for pilot backend=openai".into(),
                }
            })?;
            Ok(Arc::new(OpenAiClient::new(model.to_string(), key)) as Arc<dyn LlmClient>)
        }
        "ollama" => Ok(Arc::new(OllamaClient::new(model.to_string())) as Arc<dyn LlmClient>),
        other => Err(RegistryError::ManifestInvalid {
            reason: format!("unknown pilot backend '{other}' (echo|anthropic|openai|ollama)"),
        }),
    }
}

pub async fn pilot_tools(
    State(state): State<AppState>,
    AuthenticatedClaims(_claims): AuthenticatedClaims,
) -> Result<impl IntoResponse, RegistryError> {
    if !state.config.pilot.enabled {
        return Err(RegistryError::Forbidden {
            reason: "pilot disabled (set [pilot] enabled = true)".into(),
        });
    }
    let client = Arc::new(RegistryClient::new("http://127.0.0.1:0", ""));
    let registry = default_tools(client, state.gc_pool.clone());
    let tools: Vec<serde_json::Value> = registry
        .descriptors()
        .into_iter()
        .map(|d| {
            serde_json::json!({
                "name": d.name,
                "description": d.description,
                "input_schema": d.input_schema,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "tools": tools })))
}

pub async fn pilot_chat(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
    Json(body): Json<PilotChatBody>,
) -> Result<impl IntoResponse, RegistryError> {
    if !state.config.pilot.enabled {
        return Err(RegistryError::Forbidden {
            reason: "pilot disabled (set [pilot] enabled = true)".into(),
        });
    }
    if body.message.trim().is_empty() {
        return Err(RegistryError::ManifestInvalid {
            reason: "message is required".into(),
        });
    }

    let port = state
        .config
        .server
        .listen_addr
        .rsplit(':')
        .next()
        .unwrap_or("5000");
    let base = format!("http://127.0.0.1:{port}");
    let client = Arc::new(RegistryClient::new(base, claims.sub.clone()));
    let tools = Arc::new(default_tools(client, state.gc_pool.clone()));
    let llm = build_llm(&state.config.pilot.backend, &state.config.pilot.model)?;

    let tenant = body
        .tenant
        .clone()
        .or_else(|| claims.tenant_name.clone())
        .unwrap_or_else(|| "default".into());
    let ctx = ToolCtx {
        actor_sub: claims.sub.clone(),
        tenant,
        dry_run: body.dry_run,
    };

    let mut history = body.history;
    let chat_cfg = ChatConfig::default();
    let budget = state.pilot_budget.as_deref();
    let rounds = run_turn_with_budget(
        llm,
        tools,
        ctx,
        &mut history,
        &body.message,
        &chat_cfg,
        budget,
    )
    .await
    .map_err(|e| RegistryError::Internal(e.to_string()))?;

    let reply = history
        .iter()
        .rev()
        .find(|m| matches!(m.role, ChatRole::Assistant))
        .map(|m| m.content.clone())
        .unwrap_or_default();

    Ok((
        StatusCode::OK,
        Json(PilotChatResponse {
            reply,
            messages: history,
            tool_rounds: rounds,
            session_id: body.session_id,
            backend: state.config.pilot.backend.clone(),
        }),
    )
        .into_response())
}
