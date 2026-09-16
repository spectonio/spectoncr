//! Real S3 multipart coverage for [`put_chunked`].
//!
//! The in-crate unit tests run against `InMemory`, which accepts any part
//! layout. Only a real S3-compatible store enforces the 5 MiB part floor,
//! part numbering and the CompleteMultipartUpload handshake, so these
//! tests run against MinIO when one is pointed at:
//!
//! ```sh
//! docker run -d -p 39000:9000 \
//!   -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin \
//!   quay.io/minio/minio server /data
//! SPECTONCR_TEST_S3_ENDPOINT=http://127.0.0.1:39000 cargo test -p specton-resilience
//! ```
//!
//! Without `SPECTONCR_TEST_S3_ENDPOINT` they skip, so CI stays green on
//! runners with no object store.

use bytes::Bytes;
use object_store::{ObjectStore, aws::AmazonS3Builder, path::Path as StorePath};
use specton_resilience::{ChunkedPutConfig, put_chunked};

fn store() -> Option<Box<dyn ObjectStore>> {
    let endpoint = std::env::var("SPECTONCR_TEST_S3_ENDPOINT").ok()?;
    let bucket =
        std::env::var("SPECTONCR_TEST_S3_BUCKET").unwrap_or_else(|_| "spectoncr-test".into());
    let s3 = AmazonS3Builder::new()
        .with_bucket_name(bucket)
        .with_endpoint(endpoint)
        .with_region(
            std::env::var("SPECTONCR_TEST_S3_REGION").unwrap_or_else(|_| "us-east-1".into()),
        )
        .with_access_key_id(
            std::env::var("SPECTONCR_TEST_S3_ACCESS_KEY").unwrap_or_else(|_| "minioadmin".into()),
        )
        .with_secret_access_key(
            std::env::var("SPECTONCR_TEST_S3_SECRET_KEY").unwrap_or_else(|_| "minioadmin".into()),
        )
        .with_virtual_hosted_style_request(false)
        .with_allow_http(true)
        .build()
        .expect("build S3 client");
    Some(Box::new(s3))
}

/// A layer-shaped payload: incompressible, and not a multiple of any
/// plausible part size.
fn payload(len: usize) -> Bytes {
    let mut state = 0x243f_6a88_85a3_08d3u64;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.push((state & 0xff) as u8);
    }
    Bytes::from(out)
}

#[tokio::test]
async fn multipart_blob_round_trips_through_real_s3() {
    let Some(store) = store() else {
        eprintln!("skipping: SPECTONCR_TEST_S3_ENDPOINT not set");
        return;
    };

    // 37 MiB + 13 bytes across 5 MiB parts: 7 full parts and a short
    // final one, which is exactly the shape S3 is fussiest about.
    let data = payload(37 * 1024 * 1024 + 13);
    let path = StorePath::from("itest/blobs/sha256/multipart-round-trip");
    let config = ChunkedPutConfig {
        threshold: 8 * 1024 * 1024,
        part_size: 5 * 1024 * 1024,
        concurrency: 4,
    };

    put_chunked(store.as_ref(), &path, data.clone(), config)
        .await
        .expect("multipart put should succeed against S3");

    let got = store
        .get(&path)
        .await
        .expect("blob should exist")
        .bytes()
        .await
        .expect("blob should read back");

    assert_eq!(got.len(), data.len(), "byte count must match");
    assert_eq!(got, data, "multipart reassembly must be byte-exact");

    store.delete(&path).await.ok();
}

#[tokio::test]
async fn undersized_part_config_is_corrected_not_rejected() {
    let Some(store) = store() else {
        eprintln!("skipping: SPECTONCR_TEST_S3_ENDPOINT not set");
        return;
    };

    // S3 rejects non-final parts under 5 MiB. An operator setting 1 MiB
    // must not break pushes — the config is clamped instead.
    let data = payload(12 * 1024 * 1024);
    let path = StorePath::from("itest/blobs/sha256/clamped-part-size");
    let config = ChunkedPutConfig {
        threshold: 1024,
        part_size: 1024 * 1024,
        concurrency: 2,
    };

    put_chunked(store.as_ref(), &path, data.clone(), config)
        .await
        .expect("clamped part size should still upload");

    let got = store.get(&path).await.unwrap().bytes().await.unwrap();
    assert_eq!(got, data);

    store.delete(&path).await.ok();
}

#[tokio::test]
async fn small_blob_still_uses_single_put() {
    let Some(store) = store() else {
        eprintln!("skipping: SPECTONCR_TEST_S3_ENDPOINT not set");
        return;
    };

    let data = payload(64 * 1024);
    let path = StorePath::from("itest/blobs/sha256/small-single-put");

    put_chunked(
        store.as_ref(),
        &path,
        data.clone(),
        ChunkedPutConfig::default(),
    )
    .await
    .expect("small put should succeed");

    let got = store.get(&path).await.unwrap().bytes().await.unwrap();
    assert_eq!(got, data);

    store.delete(&path).await.ok();
}
