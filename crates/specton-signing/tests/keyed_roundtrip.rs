//! Vector-style tests for the B1 in-memory keyed signer.

use specton_signing::{
    MemoryKeyedSigner, MemoryKeyedVerifier, NotationStub, SignatureArtifact, Signer,
    SigningIdentity, VerificationPolicy, Verifier, generate_ed25519,
};

const DIGEST: &str = "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

#[tokio::test]
async fn fixed_keypair_sign_verify() {
    let (keys, _seed, _pub) = generate_ed25519("cosign://ci");
    let signer = MemoryKeyedSigner::new(keys.clone());
    let verifier = MemoryKeyedVerifier::new(keys);

    let artifact = signer
        .sign(DIGEST, &SigningIdentity::keyed("cosign://ci"))
        .await
        .expect("sign");

    let tag = SignatureArtifact::cosign_sig_tag(DIGEST).unwrap();
    assert!(tag.ends_with(".sig"));
    assert!(tag.starts_with("sha256-"));

    let policy = VerificationPolicy::require_keys("default", &["cosign://ci"]);
    let outcome = verifier
        .verify(DIGEST, &[artifact.clone()], &policy)
        .await
        .expect("verify");
    assert!(outcome.trusted);
    assert_eq!(outcome.matched_signers, vec!["cosign://ci"]);
}

#[tokio::test]
async fn tampered_signature_rejected() {
    let (keys, _, _) = generate_ed25519("cosign://ci");
    let signer = MemoryKeyedSigner::new(keys.clone());
    let verifier = MemoryKeyedVerifier::new(keys);

    let mut artifact = signer
        .sign(DIGEST, &SigningIdentity::keyed("cosign://ci"))
        .await
        .unwrap();
    // Flip a byte in the body.
    if let Some(b) = artifact.body.last_mut() {
        *b ^= 0xff;
    }

    let policy = VerificationPolicy::require_keys("default", &["cosign://ci"]);
    let err = verifier
        .verify(DIGEST, &[artifact], &policy)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("no trusted")
            || err.to_string().contains("denied")
            || err.to_string().contains("malformed")
            || matches!(err, specton_signing::VerifyError::PolicyDenied(_))
    );
}

#[tokio::test]
async fn untrusted_key_ref_blocked() {
    let (keys_a, _, _) = generate_ed25519("cosign://a");
    let (keys_b, _, _) = generate_ed25519("cosign://b");
    let signer = MemoryKeyedSigner::new(keys_a);
    let art = signer
        .sign(DIGEST, &SigningIdentity::keyed("cosign://a"))
        .await
        .unwrap();

    // Verifier only knows B; policy only trusts B.
    let verifier = MemoryKeyedVerifier::new(keys_b);
    let policy = VerificationPolicy::require_keys("prod", &["cosign://b"]);
    assert!(verifier.verify(DIGEST, &[art], &policy).await.is_err());
}

#[tokio::test]
async fn notation_stub_not_implemented() {
    let stub = NotationStub;
    let err = stub
        .sign(DIGEST, &SigningIdentity::keyed("x"))
        .await
        .unwrap_err();
    assert!(matches!(err, specton_signing::SignError::NotImplemented(_)));
}

#[tokio::test]
async fn keyless_identity_rejected_by_memory_signer() {
    let (keys, _, _) = generate_ed25519("cosign://ci");
    let signer = MemoryKeyedSigner::new(keys);
    let id = SigningIdentity::Keyless {
        fulcio: specton_signing::FulcioConfig {
            url: "https://fulcio.example".into(),
        },
        oidc: specton_signing::OidcToken {
            token: "tok".into(),
        },
    };
    let err = signer.sign(DIGEST, &id).await.unwrap_err();
    assert!(matches!(
        err,
        specton_signing::SignError::InvalidIdentity(_)
    ));
}
