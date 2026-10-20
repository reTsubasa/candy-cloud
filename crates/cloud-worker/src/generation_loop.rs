use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use cloud_db::control::{
    ControlStoreError, GenerationJob, GenerationJobRepository, JobFailure, SegmentControlSnapshot,
};
use thiserror::Error;
use tokio::sync::watch;

use crate::route_types::PUBLICATION_REFRESH_LEAD_SECONDS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishedGeneration {
    pub generation: u64,
    pub content_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicationFailure {
    Retryable { code: String, retry_after: Duration },
    Permanent { code: String },
}

#[async_trait]
pub trait GenerationPublisher: Send + Sync {
    fn ready(&self) -> bool;
    async fn publish(&self, job: &GenerationJob)
        -> Result<PublishedGeneration, PublicationFailure>;
}

#[async_trait]
pub trait SegmentGenerationPublisher: Send + Sync {
    fn ready(&self) -> bool;
    async fn publish_snapshot(
        &self,
        snapshot: &SegmentControlSnapshot,
    ) -> Result<PublishedGeneration, PublicationFailure>;
}

#[derive(Clone)]
pub struct SegmentGenerationAdapter<P> {
    pub control: cloud_db::control::ControlRepository,
    pub publisher: P,
}

#[async_trait]
impl<P> GenerationPublisher for SegmentGenerationAdapter<P>
where
    P: SegmentGenerationPublisher,
{
    fn ready(&self) -> bool {
        self.publisher.ready()
    }

    async fn publish(
        &self,
        job: &GenerationJob,
    ) -> Result<PublishedGeneration, PublicationFailure> {
        let snapshot = self
            .control
            .segment_snapshot(job.tenant_id, job.segment_id, job.desired_revision)
            .await
            .map_err(|error| {
                tracing::error!(
                    event = "segment_snapshot_failed",
                    tenant_id = %job.tenant_id,
                    segment_id = %job.segment_id,
                    desired_revision = job.desired_revision,
                    error = %error,
                    "could not build the SD-WAN control snapshot"
                );
                match error {
                    ControlStoreError::InvalidResource(_)
                    | ControlStoreError::InvalidRequest
                    | ControlStoreError::NotFound
                    | ControlStoreError::ReferenceConflict
                    | ControlStoreError::InvalidTransition => PublicationFailure::Permanent {
                        code: format!("CONTROL_SNAPSHOT_{}", control_error_code(&error)),
                    },
                    ControlStoreError::RevisionConflict
                    | ControlStoreError::IdempotencyConflict
                    | ControlStoreError::IdempotencyReplayExpired
                    | ControlStoreError::LeaseLost
                    | ControlStoreError::Database(_) => PublicationFailure::Retryable {
                        code: format!("CONTROL_SNAPSHOT_{}", control_error_code(&error)),
                        retry_after: Duration::from_secs(5),
                    },
                }
            })?;
        self.publisher.publish_snapshot(&snapshot).await
    }
}

fn control_error_code(error: &ControlStoreError) -> &'static str {
    match error {
        ControlStoreError::InvalidResource(_) => "INVALID_RESOURCE",
        ControlStoreError::InvalidRequest => "INVALID_REQUEST",
        ControlStoreError::NotFound => "NOT_FOUND",
        ControlStoreError::RevisionConflict => "REVISION_CONFLICT",
        ControlStoreError::ReferenceConflict => "REFERENCE_CONFLICT",
        ControlStoreError::IdempotencyConflict => "IDEMPOTENCY_CONFLICT",
        ControlStoreError::IdempotencyReplayExpired => "IDEMPOTENCY_REPLAY_EXPIRED",
        ControlStoreError::LeaseLost => "LEASE_LOST",
        ControlStoreError::InvalidTransition => "INVALID_TRANSITION",
        ControlStoreError::Database(_) => "DATABASE",
    }
}

#[async_trait]
pub trait GenerationJobQueue: Send + Sync {
    async fn recover_failed_heads(&self) -> Result<u64, ControlStoreError> {
        Ok(0)
    }
    async fn refresh_expiring(
        &self,
        _now: DateTime<Utc>,
        _refresh_before: Duration,
        _limit: u16,
    ) -> Result<u16, ControlStoreError> {
        Ok(0)
    }
    async fn claim_next(
        &self,
        owner: &str,
        now: DateTime<Utc>,
        ttl: Duration,
    ) -> Result<Option<GenerationJob>, ControlStoreError>;
    async fn publish(
        &self,
        job: &GenerationJob,
        now: DateTime<Utc>,
        result: PublishedGeneration,
    ) -> Result<(), ControlStoreError>;
    async fn fail(
        &self,
        job: &GenerationJob,
        now: DateTime<Utc>,
        failure: JobFailure,
    ) -> Result<(), ControlStoreError>;
}

#[async_trait]
impl GenerationJobQueue for GenerationJobRepository {
    async fn recover_failed_heads(&self) -> Result<u64, ControlStoreError> {
        self.recover_route_input_head_failures().await
    }
    async fn refresh_expiring(
        &self,
        now: DateTime<Utc>,
        refresh_before: Duration,
        limit: u16,
    ) -> Result<u16, ControlStoreError> {
        self.refresh_expiring(now, refresh_before, limit).await
    }

    async fn claim_next(
        &self,
        owner: &str,
        now: DateTime<Utc>,
        ttl: Duration,
    ) -> Result<Option<GenerationJob>, ControlStoreError> {
        self.claim_next(owner, now, ttl).await
    }

    async fn publish(
        &self,
        job: &GenerationJob,
        now: DateTime<Utc>,
        result: PublishedGeneration,
    ) -> Result<(), ControlStoreError> {
        self.publish(job, now, result.generation, result.content_hash)
            .await
    }

    async fn fail(
        &self,
        job: &GenerationJob,
        now: DateTime<Utc>,
        failure: JobFailure,
    ) -> Result<(), ControlStoreError> {
        self.fail(job, now, &failure).await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcome {
    PublisherUnavailable,
    Idle,
    Published,
    RetryScheduled,
    PermanentFailure,
}

#[derive(Debug, Error)]
pub enum WorkerLoopError {
    #[error("generation job storage failed: {0}")]
    Storage(#[from] ControlStoreError),
    #[error("retry delay is invalid")]
    InvalidRetryDelay,
    #[error("poll interval must be nonzero")]
    InvalidPollInterval,
    #[error("worker concurrency must be between 1 and 32")]
    InvalidConcurrency,
    #[error("generation worker task failed: {0}")]
    Task(#[from] tokio::task::JoinError),
}

pub struct GenerationWorker<Q, P> {
    queue: Arc<Q>,
    publisher: Arc<P>,
    owner_id: String,
    lease_ttl: Duration,
}

fn normalize_failure_code(code: &str) -> String {
    const MAX_LEN: usize = 80;
    let mut normalized = String::with_capacity(code.len().min(MAX_LEN));
    let mut previous_separator = false;
    for byte in code.bytes() {
        let value = if byte.is_ascii_alphanumeric() {
            previous_separator = false;
            byte.to_ascii_uppercase()
        } else {
            if previous_separator {
                continue;
            }
            previous_separator = true;
            b'_'
        };
        if normalized.len() == MAX_LEN {
            break;
        }
        normalized.push(char::from(value));
    }
    while normalized.ends_with('_') {
        normalized.pop();
    }
    if normalized.is_empty() {
        "PUBLICATION_FAILURE".into()
    } else {
        normalized
    }
}

impl<Q, P> GenerationWorker<Q, P>
where
    Q: GenerationJobQueue,
    P: GenerationPublisher,
{
    pub fn new(
        queue: Q,
        publisher: P,
        owner_id: String,
        lease_ttl: Duration,
    ) -> Result<Self, WorkerLoopError> {
        if owner_id.is_empty() || lease_ttl.is_zero() || lease_ttl > Duration::from_secs(300) {
            return Err(WorkerLoopError::Storage(ControlStoreError::InvalidRequest));
        }
        Ok(Self {
            queue: Arc::new(queue),
            publisher: Arc::new(publisher),
            owner_id,
            lease_ttl,
        })
    }

    pub async fn run_once(&self, now: DateTime<Utc>) -> Result<RunOutcome, WorkerLoopError> {
        if !self.publisher.ready() {
            return Ok(RunOutcome::PublisherUnavailable);
        }
        self.refresh_expiring(now).await;
        self.run_claimed_once(now).await
    }

    async fn refresh_expiring(&self, now: DateTime<Utc>) {
        let refresh = tokio::time::timeout(
            self.lease_ttl.div_f64(4.0).min(Duration::from_secs(5)),
            self.queue.refresh_expiring(
                now,
                Duration::from_secs(PUBLICATION_REFRESH_LEAD_SECONDS),
                32,
            ),
        )
        .await;
        match refresh {
            Ok(Ok(_)) => (),
            Ok(Err(error)) => {
                self.storage_failure("refresh", None, error);
            }
            Err(_) => {
                tracing::error!(code = "generation_refresh_timeout", module = "cloud_generation_worker",
                owner = %self.owner_id, detail = "renewal scan exceeded independent deadline",
                action = "preserve_existing_jobs_continue_claim")
            }
        }
    }

    async fn run_claimed_once(&self, now: DateTime<Utc>) -> Result<RunOutcome, WorkerLoopError> {
        if !self.publisher.ready() {
            return Ok(RunOutcome::PublisherUnavailable);
        }
        let Some(job) = self
            .queue
            .claim_next(&self.owner_id, now, self.lease_ttl)
            .await
            .map_err(|error| self.storage_failure("claim", None, error))?
        else {
            return Ok(RunOutcome::Idle);
        };
        match self.publisher.publish(&job).await {
            Ok(result) => {
                tracing::info!(
                    event = "segment_generation_published",
                    tenant_id = %job.tenant_id,
                    segment_id = %job.segment_id,
                    desired_revision = job.desired_revision,
                    publication_generation = result.generation,
                    "published SD-WAN runtime configuration"
                );
                self.queue
                    .publish(&job, Utc::now(), result)
                    .await
                    .map_err(|error| self.storage_failure("publish_receipt", Some(&job), error))?;
                Ok(RunOutcome::Published)
            }
            Err(PublicationFailure::Retryable { code, retry_after }) => {
                if retry_after.is_zero() || retry_after > Duration::from_secs(3600) {
                    tracing::error!(code = "publication_retry_delay_invalid", module = "cloud_generation_worker",
                        tenant_id = %job.tenant_id, segment_id = %job.segment_id,
                        detail = %code, retry_after_ms = retry_after.as_millis() as u64,
                        action = "reject_job_preserve_worker");
                    self.queue
                        .fail(
                            &job,
                            Utc::now(),
                            JobFailure::Permanent {
                                code: "PUBLICATION_RETRY_DELAY_INVALID".into(),
                            },
                        )
                        .await
                        .map_err(|error| {
                            self.storage_failure("reject_invalid_retry", Some(&job), error)
                        })?;
                    return Ok(RunOutcome::PermanentFailure);
                }
                let retry_at = Utc::now()
                    + chrono::Duration::from_std(retry_after)
                        .map_err(|_| WorkerLoopError::InvalidRetryDelay)?;
                tracing::warn!(
                    event = "segment_generation_retry",
                    tenant_id = %job.tenant_id,
                    segment_id = %job.segment_id,
                    desired_revision = job.desired_revision,
                    error_code = %normalize_failure_code(&code),
                    retry_after_seconds = retry_after.as_secs(),
                    "runtime configuration publication will be retried"
                );
                self.queue
                    .fail(
                        &job,
                        Utc::now(),
                        JobFailure::Retry {
                            code: normalize_failure_code(&code),
                            retry_at,
                        },
                    )
                    .await
                    .map_err(|error| self.storage_failure("retry_receipt", Some(&job), error))?;
                Ok(RunOutcome::RetryScheduled)
            }
            Err(PublicationFailure::Permanent { code }) => {
                tracing::error!(
                    event = "segment_generation_failed",
                    tenant_id = %job.tenant_id,
                    segment_id = %job.segment_id,
                    desired_revision = job.desired_revision,
                    error_code = %normalize_failure_code(&code),
                    "runtime configuration publication stopped for this revision"
                );
                self.queue
                    .fail(
                        &job,
                        Utc::now(),
                        JobFailure::Permanent {
                            code: normalize_failure_code(&code),
                        },
                    )
                    .await
                    .map_err(|error| self.storage_failure("failure_receipt", Some(&job), error))?;
                Ok(RunOutcome::PermanentFailure)
            }
        }
    }

    fn storage_failure(
        &self,
        phase: &'static str,
        job: Option<&GenerationJob>,
        error: ControlStoreError,
    ) -> WorkerLoopError {
        tracing::error!(code = "generation_storage_failed", module = "cloud_generation_worker",
            phase, owner = %self.owner_id, tenant_id = ?job.map(|job| job.tenant_id),
            segment_id = ?job.map(|job| job.segment_id), job_id = ?job.map(|job| job.id),
            desired_revision = ?job.map(|job| job.desired_revision),
            detail = %error, action = "retry_iteration_preserve_lease_fencing");
        WorkerLoopError::Storage(error)
    }

    async fn run_lane(
        &self,
        poll_interval: Duration,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), WorkerLoopError> {
        if poll_interval.is_zero() {
            return Err(WorkerLoopError::InvalidPollInterval);
        }
        let mut failures = 0_u32;
        loop {
            if *shutdown.borrow() || shutdown.has_changed().is_err() {
                return Ok(());
            }
            // Cancellation leaves a claimed job leased. The repository fences
            // late commits and makes abandoned jobs claimable after expiration.
            let result = tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { return Ok(()); }
                    continue;
                }
                result = tokio::time::timeout(self.lease_ttl, self.run_claimed_once(Utc::now())) => result,
            };
            let delay = match result {
                Ok(Ok(outcome)) => {
                    failures = 0;
                    if matches!(
                        outcome,
                        RunOutcome::Published
                            | RunOutcome::RetryScheduled
                            | RunOutcome::PermanentFailure
                    ) {
                        tokio::task::yield_now().await;
                        continue;
                    }
                    poll_interval
                }
                failure => {
                    failures = failures.saturating_add(1);
                    let delay = Duration::from_secs(1_u64 << failures.min(5));
                    let (code, detail) = match failure {
                        Ok(Err(error)) => ("generation_iteration_failed", error.to_string()),
                        Err(_) => (
                            "generation_iteration_timeout",
                            "operation exceeded job lease deadline".into(),
                        ),
                        Ok(Ok(_)) => unreachable!(),
                    };
                    tracing::error!(code, module = "cloud_generation_worker", owner = %self.owner_id,
                        detail, consecutive_failures = failures, retry_after_ms = delay.as_millis() as u64,
                        action = "retry_iteration_preserve_worker");
                    delay
                }
            };
            tokio::select! {
                _ = tokio::time::sleep(delay) => {},
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return Ok(());
                    }
                }
            }
        }
    }

    async fn run_recovery_scanner(
        &self,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), WorkerLoopError> {
        let deadline = self.lease_ttl.div_f64(4.0).min(Duration::from_secs(5));
        let mut failures = 0_u32;
        loop {
            if *shutdown.borrow() || shutdown.has_changed().is_err() {
                return Ok(());
            }
            let result = tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { return Ok(()); }
                    continue;
                }
                result = tokio::time::timeout(deadline, self.queue.recover_failed_heads()) => result,
            };
            let delay = match result {
                Ok(Ok(count)) => {
                    if count > 0 {
                        tracing::warn!(event = "route_jobs_recovered", job_count = count,
                            owner = %self.owner_id, reason = "topology_materialization_available",
                            "requeued recoverable route jobs without pausing publication lanes");
                    }
                    // Upgrade reconciliation is attempted once per process.
                    // Repeating a successful scan would resurrect permanent
                    // invalid configuration jobs indefinitely.
                    return Ok(());
                }
                failure => {
                    failures = failures.saturating_add(1);
                    let delay = Duration::from_secs(1_u64 << failures.min(6));
                    let detail = match failure {
                        Ok(Err(error)) => error.to_string(),
                        Err(_) => "recovery scan exceeded independent deadline".into(),
                        Ok(Ok(_)) => unreachable!(),
                    };
                    tracing::error!(code = "generation_recovery_scan_failed", module = "cloud_generation_worker",
                        owner = %self.owner_id, detail, consecutive_failures = failures,
                        retry_after_ms = delay.as_millis() as u64,
                        action = "retry_recovery_scan_preserve_other_lanes");
                    delay
                }
            };
            tokio::select! {
                _ = tokio::time::sleep(delay) => {},
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { return Ok(()); }
                }
            }
        }
    }

    /// Runs bounded independent publication lanes. The queue must serialize each
    /// (tenant, segment) across all owners; this is enforced by the repository's
    /// claim transaction. Each lane gets its own fencing owner, and dropped or
    /// timed-out publications remain reclaimable when their lease expires.
    pub async fn run(
        &self,
        poll_interval: Duration,
        shutdown: watch::Receiver<bool>,
    ) -> Result<(), WorkerLoopError>
    where
        Q: 'static,
        P: 'static,
    {
        self.run_with_concurrency(poll_interval, 4, shutdown).await
    }

    pub async fn run_with_concurrency(
        &self,
        poll_interval: Duration,
        concurrency: usize,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), WorkerLoopError>
    where
        Q: 'static,
        P: 'static,
    {
        if poll_interval.is_zero() {
            return Err(WorkerLoopError::InvalidPollInterval);
        }
        if !(1..=32).contains(&concurrency) {
            return Err(WorkerLoopError::InvalidConcurrency);
        }
        if *shutdown.borrow() || shutdown.has_changed().is_err() {
            return Ok(());
        }
        let mut tasks = tokio::task::JoinSet::new();
        // A UUID per run avoids reusing an abandoned lane's lease owner after
        // restart, even when CLOUD_WORKER_ID is configured identically.
        let run_id = uuid::Uuid::now_v7();
        tracing::info!(event = "generation_scheduler_started", owner = %self.owner_id,
            %run_id, concurrency, lease_seconds = self.lease_ttl.as_secs(),
            "started bounded publication lanes with independent renewal and recovery scanners");
        for lane in 0..concurrency {
            let worker = Self {
                queue: self.queue.clone(),
                publisher: self.publisher.clone(),
                owner_id: format!("{run_id}:lane-{lane}"),
                lease_ttl: self.lease_ttl,
            };
            let lane_shutdown = shutdown.clone();
            tasks.spawn(async move { worker.run_lane(poll_interval, lane_shutdown).await });
        }
        let refresh_worker = Self {
            queue: self.queue.clone(),
            publisher: self.publisher.clone(),
            owner_id: self.owner_id.clone(),
            lease_ttl: self.lease_ttl,
        };
        let mut refresh_shutdown = shutdown.clone();
        tasks.spawn(async move {
            loop {
                if *refresh_shutdown.borrow() || refresh_shutdown.has_changed().is_err() {
                    return Ok(());
                }
                tokio::select! {
                    biased;
                    changed = refresh_shutdown.changed() => {
                        if changed.is_err() || *refresh_shutdown.borrow() { return Ok(()); }
                        continue;
                    }
                    _ = refresh_worker.refresh_expiring(Utc::now()) => {}
                }
                tokio::select! {
                    _ = tokio::time::sleep(poll_interval) => {}
                    changed = refresh_shutdown.changed() => {
                        if changed.is_err() || *refresh_shutdown.borrow() { return Ok(()); }
                    }
                }
            }
        });
        let recovery_worker = Self {
            queue: self.queue.clone(),
            publisher: self.publisher.clone(),
            owner_id: self.owner_id.clone(),
            lease_ttl: self.lease_ttl,
        };
        let recovery_shutdown = shutdown.clone();
        tasks.spawn(async move {
            recovery_worker
                .run_recovery_scanner(recovery_shutdown)
                .await
        });
        let result = loop {
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { break Ok(()); }
                }
                result = tasks.join_next() => {
                    match result {
                        Some(Ok(Ok(()))) if *shutdown.borrow() || shutdown.has_changed().is_err() => break Ok(()),
                        Some(Ok(Ok(()))) => continue,
                        Some(Ok(Err(error))) => break Err(error),
                        Some(Err(error)) => break Err(error.into()),
                        None => break Ok(()),
                    }
                }
            }
        };
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        result
    }
}
