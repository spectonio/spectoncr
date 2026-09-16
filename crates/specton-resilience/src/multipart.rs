//! Chunked object writes for payloads too large for a single request.
//!
//! `ObjectStore::put` ships the whole payload in one HTTP request, and
//! object_store bounds that request end to end with its `retry_timeout`
//! (180s by default). A container layer of a gigabyte or more cannot
//! finish inside that window on a modest uplink, so the write is
//! abandoned mid-flight and the caller sees:
//!
//! ```text
//! Generic S3 error: Error after 5 retries in 181.3s, max_retries:10,
//! retry_timeout:180s, source:error sending request for url (...)
//! ```
//!
//! Raising `retry_timeout` is not a fix — object_store documents it must
//! stay under five minutes because a request is retried without renewing
//! credentials or regenerating the payload.
//!
//! Splitting the payload into fixed-size parts gives every part its own
//! request and its own retry budget, so total object size stops being
//! bounded by a single request deadline.

use bytes::Bytes;
use futures::StreamExt;
use object_store::{ObjectStore, PutPayload, path::Path as StorePath};
use tracing::{debug, warn};

/// Payloads at or below this size go out as a single `put`, exactly as
/// before. Only genuinely large writes take the multipart path.
pub const DEFAULT_MULTIPART_THRESHOLD: usize = 64 * 1024 * 1024;

/// Part size used above the threshold. S3 caps an upload at 10,000
/// parts, so 32 MiB supports objects up to ~312 GiB.
pub const DEFAULT_PART_SIZE: usize = 32 * 1024 * 1024;

/// Parts in flight at once. Enough to keep a WAN link busy without
/// multiplying peak memory (parts are views into one buffer, but each
/// in-flight request holds its own connection).
pub const DEFAULT_PART_CONCURRENCY: usize = 4;

/// Smallest part size S3-compatible stores accept for a non-final part.
const MIN_PART_SIZE: usize = 5 * 1024 * 1024;

/// Most parts a single S3 multipart upload may contain.
const MAX_PARTS: usize = 10_000;

/// Tuning for [`put_chunked`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkedPutConfig {
    /// Payloads larger than this use a multipart upload.
    pub threshold: usize,
    /// Size of each part.
    pub part_size: usize,
    /// Parts uploaded concurrently.
    pub concurrency: usize,
}

impl Default for ChunkedPutConfig {
    fn default() -> Self {
        Self {
            threshold: DEFAULT_MULTIPART_THRESHOLD,
            part_size: DEFAULT_PART_SIZE,
            concurrency: DEFAULT_PART_CONCURRENCY,
        }
    }
}

impl ChunkedPutConfig {
    /// Clamp operator-supplied values to what the backing store accepts.
    ///
    /// A part size below S3's 5 MiB floor makes every upload fail, and a
    /// threshold below the part size would send single-part "multipart"
    /// uploads for no gain, so both are corrected rather than trusted.
    /// `part_size` is also raised when `total` would otherwise need more
    /// than [`MAX_PARTS`] parts.
    fn sanitized(self, total: usize) -> Self {
        let mut part_size = self.part_size.max(MIN_PART_SIZE);
        if total.div_ceil(part_size) > MAX_PARTS {
            part_size = total.div_ceil(MAX_PARTS);
        }
        Self {
            threshold: self.threshold.max(part_size),
            part_size,
            concurrency: self.concurrency.clamp(1, 16),
        }
    }
}

/// Write `data` to `location`, using a multipart upload when the payload
/// is large enough to risk the single-request retry deadline.
///
/// Small payloads take the same `put` path as before, so manifests, tags
/// and upload placeholders are unaffected.
pub async fn put_chunked(
    store: &dyn ObjectStore,
    location: &StorePath,
    data: Bytes,
    config: ChunkedPutConfig,
) -> object_store::Result<()> {
    let total = data.len();
    let config = config.sanitized(total);

    if total <= config.threshold {
        store.put(location, PutPayload::from_bytes(data)).await?;
        return Ok(());
    }

    let mut upload = store.put_multipart(location).await?;

    // `put_part` only assigns a part number and hands back a detached
    // future, so every part can be created up front and then driven
    // with bounded concurrency. The slices are views into `data`, so
    // this adds no copy of the payload.
    let mut parts = Vec::with_capacity(total.div_ceil(config.part_size));
    let mut offset = 0usize;
    while offset < total {
        let end = (offset + config.part_size).min(total);
        parts.push(upload.put_part(PutPayload::from_bytes(data.slice(offset..end))));
        offset = end;
    }
    let part_count = parts.len();

    debug!(
        location = %location,
        bytes = total,
        parts = part_count,
        part_size = config.part_size,
        "Writing object as multipart upload"
    );

    let outcome = futures::stream::iter(parts)
        .buffer_unordered(config.concurrency)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<object_store::Result<Vec<()>>>();

    if let Err(e) = outcome {
        abort_quietly(&mut upload, location).await;
        return Err(e);
    }

    match upload.complete().await {
        Ok(_) => {
            debug!(location = %location, parts = part_count, "Multipart upload complete");
            Ok(())
        }
        Err(e) => {
            abort_quietly(&mut upload, location).await;
            Err(e)
        }
    }
}

/// Abort a failed upload so S3 does not keep billing for orphaned parts.
/// A failed abort is logged and swallowed — the original error is what
/// the caller needs to see.
async fn abort_quietly(upload: &mut Box<dyn object_store::MultipartUpload>, location: &StorePath) {
    if let Err(e) = upload.abort().await {
        warn!(
            location = %location,
            error = %e,
            "Failed to abort multipart upload; orphaned parts may remain"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::memory::InMemory;

    fn payload(len: usize) -> Bytes {
        Bytes::from((0..len).map(|i| (i % 251) as u8).collect::<Vec<u8>>())
    }

    #[test]
    fn sanitize_raises_part_size_to_s3_floor() {
        let c = ChunkedPutConfig {
            threshold: 1024,
            part_size: 1024,
            concurrency: 0,
        }
        .sanitized(10 * 1024 * 1024);
        assert_eq!(c.part_size, MIN_PART_SIZE);
        // Threshold cannot sit below the part size.
        assert_eq!(c.threshold, MIN_PART_SIZE);
        assert_eq!(c.concurrency, 1);
    }

    #[test]
    fn sanitize_grows_part_size_to_stay_under_part_limit() {
        // 1 TiB at the default 32 MiB part size would need 32,768 parts.
        let total = 1024 * 1024 * 1024 * 1024;
        let c = ChunkedPutConfig::default().sanitized(total);
        assert!(total.div_ceil(c.part_size) <= MAX_PARTS);
    }

    #[test]
    fn sanitize_leaves_sensible_values_alone() {
        let c = ChunkedPutConfig::default().sanitized(100 * 1024 * 1024);
        assert_eq!(c, ChunkedPutConfig::default());
    }

    #[tokio::test]
    async fn small_payload_round_trips() {
        let store = InMemory::new();
        let path = StorePath::from("blobs/small");
        let data = payload(1024);

        put_chunked(&store, &path, data.clone(), ChunkedPutConfig::default())
            .await
            .unwrap();

        let got = store.get(&path).await.unwrap().bytes().await.unwrap();
        assert_eq!(got, data);
    }

    #[tokio::test]
    async fn multipart_payload_round_trips_byte_for_byte() {
        let store = InMemory::new();
        let path = StorePath::from("blobs/large");
        // Deliberately not a multiple of the part size, so the final
        // short part is exercised.
        let data = payload(21 * 1024 * 1024 + 7);
        let config = ChunkedPutConfig {
            threshold: 5 * 1024 * 1024,
            part_size: 5 * 1024 * 1024,
            concurrency: 3,
        };

        put_chunked(&store, &path, data.clone(), config)
            .await
            .unwrap();

        let got = store.get(&path).await.unwrap().bytes().await.unwrap();
        assert_eq!(got.len(), data.len());
        assert_eq!(got, data, "multipart reassembly must preserve byte order");
    }

    #[tokio::test]
    async fn payload_exactly_at_threshold_uses_single_put() {
        let store = InMemory::new();
        let path = StorePath::from("blobs/boundary");
        let size = 5 * 1024 * 1024;
        let data = payload(size);
        let config = ChunkedPutConfig {
            threshold: size,
            part_size: size,
            concurrency: 1,
        };

        put_chunked(&store, &path, data.clone(), config)
            .await
            .unwrap();

        let got = store.get(&path).await.unwrap().bytes().await.unwrap();
        assert_eq!(got, data);
    }

    #[tokio::test]
    async fn overwrites_existing_object() {
        let store = InMemory::new();
        let path = StorePath::from("blobs/overwrite");
        let config = ChunkedPutConfig {
            threshold: 5 * 1024 * 1024,
            part_size: 5 * 1024 * 1024,
            concurrency: 2,
        };

        put_chunked(&store, &path, payload(1024), config)
            .await
            .unwrap();
        let second = payload(12 * 1024 * 1024);
        put_chunked(&store, &path, second.clone(), config)
            .await
            .unwrap();

        let got = store.get(&path).await.unwrap().bytes().await.unwrap();
        assert_eq!(got, second);
    }
}
