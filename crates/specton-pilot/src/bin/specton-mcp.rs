//! Minimal JSON-RPC MCP-style stdio server (design 019 P3).
//!
//! Speaks a subset of the Model Context Protocol over stdin/stdout:
//! `tools/list` and `tools/call`. Enough for Cursor / Claude Code
//! adapters that can talk JSON-RPC stdio.
//!
//! ```text
//! SPECTONCR_REGISTRY=… SPECTONCR_TOKEN=… specton-mcp
//! ```

use std::env;
use std::io::{self, BufRead, Write};
use std::sync::Arc;

use serde_json::{Value, json};
use specton_pilot::{RegistryClient, ToolCtx, default_tools};

#[tokio::main]
async fn main() {
    let registry =
        env::var("SPECTONCR_REGISTRY").unwrap_or_else(|_| "http://127.0.0.1:5000".into());
    let token = env::var("SPECTONCR_TOKEN").unwrap_or_default();
    let tenant = env::var("SPECTONCR_TENANT").unwrap_or_else(|_| "acme".into());
    let actor = env::var("USER").unwrap_or_else(|_| "mcp".into());
    let dry_run = env::var("SPECTONCR_PILOT_DRY_RUN")
        .map(|v| matches!(v.as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);

    let client = Arc::new(RegistryClient::new(registry, token));
    let tools = Arc::new(default_tools(client, None));
    let ctx = ToolCtx {
        actor_sub: actor,
        tenant,
        dry_run,
    };

    let stdin = io::stdin();
    let mut stdout = io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                let _ = writeln!(
                    stdout,
                    "{}",
                    json!({"jsonrpc":"2.0","error":{"code":-32700,"message":e.to_string()}})
                );
                continue;
            }
        };
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let result = match method {
            "initialize" => json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "specton-mcp", "version": env!("CARGO_PKG_VERSION") }
            }),
            "tools/list" | "list_tools" => {
                let list: Vec<_> = tools
                    .names()
                    .into_iter()
                    .filter_map(|n| tools.get(n))
                    .map(|t| {
                        json!({
                            "name": t.name(),
                            "description": t.description(),
                            "inputSchema": t.input_schema(),
                        })
                    })
                    .collect();
                json!({ "tools": list })
            }
            "tools/call" | "call_tool" => {
                let params = req.get("params").cloned().unwrap_or(json!({}));
                let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
                match tools.invoke(name, &ctx, arguments).await {
                    Ok(out) => json!({
                        "content": [{
                            "type": "text",
                            "text": serde_json::to_string_pretty(&out.data).unwrap_or_default()
                        }],
                        "isError": false
                    }),
                    Err(e) => json!({
                        "content": [{ "type": "text", "text": e.to_string() }],
                        "isError": true
                    }),
                }
            }
            "notifications/initialized" | "ping" => {
                // no response for notifications without id
                if id.is_null() {
                    continue;
                }
                json!({})
            }
            other => {
                let err = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32601, "message": format!("method not found: {other}") }
                });
                let _ = writeln!(stdout, "{err}");
                let _ = stdout.flush();
                continue;
            }
        };
        if !id.is_null() {
            let _ = writeln!(
                stdout,
                "{}",
                json!({"jsonrpc":"2.0","id":id,"result":result})
            );
            let _ = stdout.flush();
        }
    }
}
