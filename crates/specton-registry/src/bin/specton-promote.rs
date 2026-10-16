//! CLI for atomic promotion (design 006 C1).
//!
//! ```text
//! specton-promote acme/dev/api:1.2.3 acme/prod/api:1.2.3 \
//!   --registry https://registry.example [--token TOKEN] [--dry-run] [--no-signatures]
//! ```

use std::env;
use std::process::ExitCode;

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
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        print_help();
        return Ok(());
    }

    let registry = flag_take(&mut args, "--registry")
        .or_else(|| env::var("SPECTONCR_REGISTRY").ok())
        .ok_or("--registry URL or SPECTONCR_REGISTRY required")?;
    let token = flag_take(&mut args, "--token")
        .or_else(|| env::var("SPECTONCR_TOKEN").ok())
        .ok_or("--token or SPECTONCR_TOKEN required")?;
    let dry_run = flag_bool(&args, "--dry-run");
    let no_sigs = flag_bool(&args, "--no-signatures");
    args.retain(|a| {
        a != "--dry-run" && a != "--no-signatures" && !a.starts_with("--registry") && !a.starts_with("--token")
    });

    if args.len() != 2 {
        print_help();
        return Err("expected SOURCE DEST".into());
    }
    let source = args[0].clone();
    let dest = args[1].clone();

    let body = serde_json::json!({
        "source": source,
        "dest": dest,
        "include_signatures": !no_sigs,
        "include_attestations": true,
        "mode": if dry_run { "dry_run" } else { "force" },
    });

    let url = format!("{}/v2/_promote", registry.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        return Err(format!("{status}: {text}").into());
    }
    println!("{text}");
    Ok(())
}

fn print_help() {
    eprintln!(
        "specton-promote — atomic image promotion\n\n\
         Usage:\n\
           specton-promote SOURCE DEST --registry URL --token TOKEN [--dry-run] [--no-signatures]\n\n\
         SOURCE/DEST format: tenant/project/repo:tag\n\
         Env: SPECTONCR_REGISTRY, SPECTONCR_TOKEN\n"
    );
}

fn flag_take(args: &mut Vec<String>, name: &str) -> Option<String> {
    if let Some(i) = args.iter().position(|a| a == name) {
        args.remove(i);
        if i < args.len() {
            return Some(args.remove(i));
        }
    }
    None
}

fn flag_bool(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}
