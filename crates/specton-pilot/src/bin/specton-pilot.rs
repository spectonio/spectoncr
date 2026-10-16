//! CLI REPL / one-shot for specton-pilot (design 019 P3).
//!
//! ```text
//! specton-pilot tools
//! specton-pilot --once "list repos in acme"
//! specton-pilot   # interactive (requires ANTHROPIC_API_KEY or OLLAMA)
//! ```

use std::env;
use std::io::{self, Write};
use std::process::ExitCode;
use std::sync::Arc;

use specton_pilot::{
    AnthropicClient, ChatConfig, ChatMessage, OllamaClient, RegistryClient, ToolCtx, default_tools,
    run_turn,
};

#[tokio::main]
async fn main() -> ExitCode {
    if let Err(e) = run().await {
        eprintln!("error: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print_help();
        return Ok(());
    }

    let registry =
        env::var("SPECTONCR_REGISTRY").unwrap_or_else(|_| "http://127.0.0.1:5000".into());
    let token = env::var("SPECTONCR_TOKEN").unwrap_or_default();
    let tenant = env::var("SPECTONCR_TENANT").unwrap_or_else(|_| "acme".into());
    let client = Arc::new(RegistryClient::new(registry, token));
    let tools = Arc::new(default_tools(client, None));

    if args.first().map(|s| s.as_str()) == Some("tools") {
        for n in tools.names() {
            if let Some(t) = tools.get(n) {
                println!("{n}\t{}\t{:?}", t.description(), t.destructiveness());
            }
        }
        return Ok(());
    }

    let once = if let Some(i) = args.iter().position(|a| a == "--once") {
        args.remove(i);
        Some(args.join(" "))
    } else {
        None
    };

    let llm: Arc<dyn specton_pilot::LlmClient> = if let Ok(key) = env::var("ANTHROPIC_API_KEY") {
        let model = env::var("ANTHROPIC_MODEL").unwrap_or_else(|_| "claude-sonnet-4-5".into());
        Arc::new(AnthropicClient::new(model, key))
    } else if env::var("OLLAMA_HOST").is_ok() || env::var("OLLAMA_MODEL").is_ok() {
        let model = env::var("OLLAMA_MODEL").unwrap_or_else(|_| "llama3.2".into());
        Arc::new(OllamaClient::new(model))
    } else {
        eprintln!("set ANTHROPIC_API_KEY or OLLAMA_HOST for chat; listing tools instead");
        for n in tools.names() {
            println!("{n}");
        }
        return Ok(());
    };

    let ctx = ToolCtx {
        actor_sub: env::var("USER").unwrap_or_else(|_| "pilot".into()),
        tenant,
        dry_run: args.iter().any(|a| a == "--dry-run"),
    };
    let config = ChatConfig::default();
    let mut history: Vec<ChatMessage> = Vec::new();

    if let Some(prompt) = once {
        run_turn(llm, tools, ctx, &mut history, &prompt, &config).await?;
        print_assistant(&history);
        return Ok(());
    }

    println!("specton-pilot REPL (empty line to quit)");
    loop {
        print!("> ");
        io::stdout().flush()?;
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        let line = line.trim();
        if line.is_empty() {
            break;
        }
        run_turn(
            llm.clone(),
            tools.clone(),
            ctx.clone(),
            &mut history,
            line,
            &config,
        )
        .await?;
        print_assistant(&history);
    }
    Ok(())
}

fn print_assistant(history: &[ChatMessage]) {
    if let Some(m) = history.last()
        && matches!(m.role, specton_pilot::ChatRole::Assistant)
    {
        println!("{}", m.content);
    }
}

fn print_help() {
    eprintln!(
        "specton-pilot — AI agent for SpectonCR\n\n\
         Env: SPECTONCR_REGISTRY, SPECTONCR_TOKEN, SPECTONCR_TENANT,\n\
              ANTHROPIC_API_KEY | OLLAMA_HOST\n\n\
         Commands:\n\
           specton-pilot tools\n\
           specton-pilot --once \"prompt\" [--dry-run]\n\
           specton-pilot [--dry-run]   # REPL\n"
    );
}
