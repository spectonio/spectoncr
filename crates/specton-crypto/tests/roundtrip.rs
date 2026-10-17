use std::sync::Arc;

use bytes::Bytes;
use object_store::ObjectStore;
use object_store::memory::InMemory;
use specton_common::storage::sha256_digest;
use specton_crypto::{EncryptedStore, EnvelopeEncryptedStore, LocalDevProvider};

#[tokio::test]
async fn encrypt_decrypt_roundtrip_in_memory_store() {
    let inner: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let provider = Arc::new(LocalDevProvider::memory());
    let store = EnvelopeEncryptedStore::new(inner, provider, None);

    let plaintext = Bytes::from(vec![0u8; 64 * 1024]);
    let digest = sha256_digest(&plaintext);
    let hex = digest.strip_prefix("sha256:").unwrap();
    let path = format!("tenant-a/proj/repo/blobs/sha256/{hex}");

    let meta = store
        .put_blob("tenant-a", &path, plaintext.clone())
        .await
        .expect("put_blob");
    assert_eq!(meta.digest, digest);
    assert!(meta.size_ciphertext > meta.size_plaintext);

    let recovered = store
        .get_blob("tenant-a", &path)
        .await
        .expect("get_blob");
    assert_eq!(recovered, plaintext);
}
