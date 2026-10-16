//! CLI for keyed image signing (design 001 B2).
//!
//! ```text
//! specton-sign keygen [--scheme ecdsa-p256|ed25519] --out ./cosign.key
//! specton-sign sign   --digest sha256:... --key file://./cosign.key [--out sig.json]
//! specton-sign verify --digest sha256:... --key file://./cosign.key --sig sig.json
//! ```

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use sigstore::crypto::SigningScheme;
use specton_signing::{
    CompositeKeyProvider, FilePemKeyProvider, Signer, SigningIdentity, SigstoreSigner,
    SigstoreVerifier, VaultKvConfig, VaultKvKeyProvider, VaultTransitConfig, VaultTransitSigner,
    VerificationPolicy, Verifier, generate_pem_keypair,
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
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        print_help();
        return Ok(());
    }
    let cmd = args.remove(0);
    match cmd.as_str() {
        "keygen" => cmd_keygen(&args)?,
        "sign" => cmd_sign(&args).await?,
        "verify" => cmd_verify(&args).await?,
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
        "specton-sign — keyed cosign signing (sigstore-rs)\n\n\
         Commands:\n\
           keygen  [--scheme ecdsa-p256|ed25519] --out PATH\n\
           sign    --digest sha256:... --key KEY_REF [--out FILE]\n\
           verify  --digest sha256:... --key KEY_REF --sig FILE\n\n\
         KEY_REF schemes:\n\
           file:///path/to/key.pem\n\
           vault://kv/<mount>/<path>   (needs VAULT_ADDR + VAULT_TOKEN)\n\
           vault://transit/<key-name>  (sign only; remote Transit)\n\
           cosign://name               (in-memory; tests)\n"
    );
}

fn cmd_keygen(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let scheme_name = flag_str(args, "--scheme").unwrap_or_else(|| "ecdsa-p256".into());
    let scheme = if scheme_name.eq_ignore_ascii_case("ed25519") {
        SigningScheme::ED25519
    } else {
        SigningScheme::ECDSA_P256_SHA256_ASN1
    };
    let out = flag_str(args, "--out").ok_or("--out PATH required")?;
    let (priv_pem, pub_pem) = generate_pem_keypair(scheme)?;
    std::fs::write(&out, &priv_pem)?;
    let pub_path = format!("{out}.pub");
    std::fs::write(&pub_path, &pub_pem)?;
    println!("wrote private key {out}");
    println!("wrote public  key {pub_path}");
    Ok(())
}

async fn cmd_sign(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let digest = flag_str(args, "--digest").ok_or("--digest required")?;
    let key = flag_str(args, "--key").ok_or("--key required")?;
    let out = flag_str(args, "--out");

    let artifact = if key.starts_with("vault://transit/") {
        let cfg = VaultTransitConfig::from_env()
            .ok_or("VAULT_TOKEN (+ VAULT_ADDR) required for transit sign")?;
        let signer = VaultTransitSigner::new(cfg);
        signer.sign(&digest, &SigningIdentity::keyed(&key)).await?
    } else {
        let keys = build_provider(&key)?;
        let signer = SigstoreSigner::new(keys);
        signer.sign(&digest, &SigningIdentity::keyed(&key)).await?
    };

    let json = serde_json::to_string_pretty(&artifact)?;
    if let Some(path) = out {
        std::fs::write(&path, &json)?;
        println!("wrote signature artifact to {path}");
    } else {
        println!("{json}");
    }
    let tag = specton_signing::SignatureArtifact::cosign_sig_tag(&digest)
        .unwrap_or_else(|| "<invalid-digest>".into());
    println!("cosign tag hint: {tag}");
    Ok(())
}

async fn cmd_verify(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let digest = flag_str(args, "--digest").ok_or("--digest required")?;
    let key = flag_str(args, "--key").ok_or("--key required")?;
    let sig_path = flag_str(args, "--sig").ok_or("--sig FILE required")?;
    let body = std::fs::read_to_string(&sig_path)?;
    let artifact: specton_signing::SignatureArtifact = serde_json::from_str(&body)?;

    let keys = build_provider(&key)?;
    let verifier = SigstoreVerifier::new(keys);
    let policy = VerificationPolicy::require_keys("cli", &[key.as_str()]);
    let outcome = verifier.verify(&digest, &[artifact], &policy).await?;
    if outcome.trusted {
        println!("trusted signers={:?}", outcome.matched_signers);
        Ok(())
    } else {
        Err(format!("not trusted: {:?}", outcome.reason).into())
    }
}

fn build_provider(
    key_ref: &str,
) -> Result<Arc<dyn specton_signing::KeyProvider>, Box<dyn std::error::Error>> {
    let mut b = CompositeKeyProvider::builder().file(Arc::new(FilePemKeyProvider::new()));
    if key_ref.starts_with("vault://")
        && let Some(cfg) = VaultKvConfig::from_env()
    {
        b = b.vault_kv(Arc::new(VaultKvKeyProvider::new(cfg)));
    }
    // If key is a relative path without scheme, still works via file provider.
    let _ = PathBuf::from(key_ref);
    Ok(Arc::new(b.build()))
}

fn flag_str(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
}
