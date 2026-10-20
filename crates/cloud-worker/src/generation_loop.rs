use std::time::Duration;

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
}

pub struct GenerationWorker<Q, P> {
    queue: Q,
    publisher: P,
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
            queue,
            publisher,
            owner_id,
            lease_ttl,
        })
    }

    pub async fn run_once(&self, now: DateTime<Utc>) -> Result<RunOutcome, WorkerLoopError> {
        if !self.publisher.ready() {
            return Ok(RunOutcome::PublisherUnavailable);
        }
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

    pub async fn run(
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
                result = tokio::time::timeout(self.lease_ttl, self.run_once(Utc::now())) => result,
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
}
