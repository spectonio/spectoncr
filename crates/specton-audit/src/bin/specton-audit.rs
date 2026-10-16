//! Minimal CLI for audit query / verify / export (design 005 slice 3).
//!
//! Usage:
//!   specton-audit verify --from 1 --to 10
//!   specton-audit export --to ./audit-out [--compress]
//!   specton-audit query [--limit 50] [--category push]
//!
//! Env for Postgres:
//!   SPECTONCR_AUDIT__POSTGRES_URL
//!   SPECTONCR_AUDIT__HMAC_KEY
//!   SPECTONCR_AUDIT__HMAC_KEY_ID (default v1)

use std::env;
use std::process::ExitCode;
use std::sync::Arc;

use specton_audit::{
    AuditQuery, AuditSink, Category, InMemoryAudit, Keyring, PgChainedAudit,
    checkpoint::{CheckpointStore, MemoryCheckpointStore, PgCheckpointStore, export_pending},
    export::{FilesystemDestination, export_range},
};

#[tokio::main]
async fn main() -> ExitCode {
    if let Err(e) = run().await {
        eprintln!("error: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

enum Backend {
    Memory {
        sink: Arc<InMemoryAudit>,
        checkpoints: MemoryCheckpointStore,
    },
    Postgres {
        sink: Arc<PgChainedAudit>,
        checkpoints: PgCheckpointStore,
    },
}

impl Backend {
    fn sink(&self) -> Arc<dyn AuditSink> {
        match self {
            Self::Memory { sink, .. } => sink.clone(),
            Self::Postgres { sink, .. } => sink.clone(),
        }
    }

    fn checkpoints(&self) -> &dyn CheckpointStore {
        match self {
            Self::Memory { checkpoints, .. } => checkpoints,
            Self::Postgres { checkpoints, .. } => checkpoints,
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        print_help();
        return Ok(());
    }
    let cmd = args.remove(0);
    let backend = build_backend().await?;
    let sink = backend.sink();

    match cmd.as_str() {
        "query" => {
            let limit = flag_usize(&args, "--limit").unwrap_or(50);
            let category = flag_str(&args, "--category").and_then(|c| Category::parse(&c));
            let actor = flag_str(&args, "--actor");
            let rows = sink
                .query(AuditQuery {
                    limit,
                    category,
                    actor,
                    ..Default::default()
                })
                .await?;
            for r in rows {
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    r.id,
                    r.event.at.to_rfc3339(),
                    r.event.category.as_str(),
                    r.event.action,
                    r.event.actor.sub
                );
            }
        }
        "verify" => {
            let from = flag_i64(&args, "--from").ok_or("--from required")?;
            let to = flag_i64(&args, "--to").ok_or("--to required")?;
            let v = sink.verify_chain(from, to).await?;
            if v.ok {
                println!("ok checked={}", v.checked);
            } else {
                println!(
                    "BROKEN at {:?} expected={:?} actual={:?}",
                    v.broken_at, v.expected_hash, v.actual_hash
                );
                return Err("chain verification failed".into());
            }
        }
        "export" => {
            let to = flag_str(&args, "--to").ok_or("--to <dir> required")?;
            let compress = args.iter().any(|a| a == "--compress");
            let from = flag_i64(&args, "--from");
            let to_id = flag_i64(&args, "--range-to");
            let dest = FilesystemDestination::new(&to);
            let result = if let (Some(f), Some(t)) = (from, to_id) {
                export_range(sink.as_ref(), &dest, f, t, compress).await?.0
            } else {
                export_pending(sink.as_ref(), backend.checkpoints(), &dest, compress).await?
            };
            println!(
                "exported rows={} merkle={} path={}",
                result.row_count, result.merkle_root, result.exported_to
            );
        }
        other => {
            eprintln!("unknown command: {other}");
            print_help();
            return Err("bad command".into());
        }
    }
    Ok(())
}

fn print_help() {
    eprintln!(
        "specton-audit — registry audit CLI\n\n\
         Commands:\n\
           query   [--limit N] [--category C] [--actor S]\n\
           verify  --from ID --to ID\n\
           export  --to DIR [--compress] [--from ID --range-to ID]\n\n\
         Env:\n\
           SPECTONCR_AUDIT__POSTGRES_URL   postgres backend\n\
           SPECTONCR_AUDIT__HMAC_KEY       chain key (required for postgres)\n\
           SPECTONCR_AUDIT__HMAC_KEY_ID    default v1"
    );
}

async fn build_backend() -> Result<Backend, Box<dyn std::error::Error>> {
    if let Ok(url) = env::var("SPECTONCR_AUDIT__POSTGRES_URL") {
        let key = env::var("SPECTONCR_AUDIT__HMAC_KEY")
            .unwrap_or_else(|_| "dev-only-audit-hmac-key-change-me!".into());
        let key_id = env::var("SPECTONCR_AUDIT__HMAC_KEY_ID").unwrap_or_else(|_| "v1".into());
        let pool = specton_db::connect(&url, 4).await?;
        specton_db::migrate(&pool).await?;
        let pg = PgChainedAudit::new(pool.clone(), Keyring::single(key_id, key.into_bytes()));
        pg.ensure_key_row().await?;
        Ok(Backend::Postgres {
            sink: Arc::new(pg),
            checkpoints: PgCheckpointStore::new(pool),
        })
    } else {
        Ok(Backend::Memory {
            sink: Arc::new(InMemoryAudit::for_tests()),
            checkpoints: MemoryCheckpointStore::default(),
        })
    }
}

fn flag_str(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
}

fn flag_i64(args: &[String], name: &str) -> Option<i64> {
    flag_str(args, name)?.parse().ok()
}

fn flag_usize(args: &[String], name: &str) -> Option<usize> {
    flag_str(args, name)?.parse().ok()
}
