//! Mark-and-sweep GC run bookkeeping (design 004 slice 1 stub).
//!
//! Full mark walks manifests via object storage; this stub records every
//! blob with a positive refcount in `gc_marks` so operators can inspect
//! reachability before enabling sweep. Sweep of unreachable blobs is
//! delegated to [`crate::reaper::ContinuousReaper`] (009).

use crate::refcount::GcError;
use sqlx::{Pool, Postgres};
use tracing::info;
use uuid::Uuid;

pub struct GcRunner {
    pool: Pool<Postgres>,
}

impl GcRunner {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }

    /// Creates a `gc_runs` row, marks all blobs with `refcount > 0`, and
    /// closes the run. Intended as a dry-run / audit hook until the full
    /// manifest walker lands.
    pub async fn mark_from_refcounts(&self, dry_run: bool) -> Result<Uuid, GcError> {
        let run_id = Uuid::new_v4();
        let mut tx = self.pool.begin().await?;

        sqlx::query(
            "INSERT INTO gc_runs (id, phase, dry_run) VALUES ($1, 'marking', $2)",
        )
        .bind(run_id)
        .bind(dry_run)
        .execute(&mut *tx)
        .await?;

        let digests: Vec<(String,)> = sqlx::query_as(
            "SELECT blob_digest FROM blob_refcounts WHERE refcount > 0",
        )
        .fetch_all(&mut *tx)
        .await?;

        let mut marked: i64 = 0;
        for (digest,) in digests {
            sqlx::query(
                "INSERT INTO gc_marks (run_id, digest) VALUES ($1, $2)
                 ON CONFLICT DO NOTHING",
            )
            .bind(run_id)
            .bind(&digest)
            .execute(&mut *tx)
            .await?;
            marked += 1;
        }

        sqlx::query(
            "UPDATE gc_runs
             SET phase = 'done', finished_at = NOW(), blobs_marked = $2
             WHERE id = $1",
        )
        .bind(run_id)
        .bind(marked)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        info!(%run_id, marked, dry_run, "gc mark stub completed");
        Ok(run_id)
    }
}
