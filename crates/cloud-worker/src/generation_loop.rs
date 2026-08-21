use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use cloud_db::control::{
    ControlStoreError, GenerationJob, GenerationJobRepository, JobFailure, SegmentControlSnapshot,
};
use thiserror::Error;
use tokio::sync::watch;

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
            .map_err(|error| match error {
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
}

pub struct GenerationWorker<Q, P> {
    queue: Q,
    publisher: P,
    owner_id: String,
    lease_ttl: Duration,
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
        self.queue
            .refresh_expiring(now, Duration::from_secs(3600), 32)
            .await?;
        let Some(job) = self
            .queue
            .claim_next(&self.owner_id, now, self.lease_ttl)
            .await?
        else {
            return Ok(RunOutcome::Idle);
        };
        match self.publisher.publish(&job).await {
            Ok(result) => {
                self.queue.publish(&job, Utc::now(), result).await?;
                Ok(RunOutcome::Published)
            }
            Err(PublicationFailure::Retryable { code, retry_after }) => {
                if retry_after.is_zero() || retry_after > Duration::from_secs(3600) {
                    return Err(WorkerLoopError::InvalidRetryDelay);
                }
                let retry_at = Utc::now()
                    + chrono::Duration::from_std(retry_after)
                        .map_err(|_| WorkerLoopError::InvalidRetryDelay)?;
                self.queue
                    .fail(&job, Utc::now(), JobFailure::Retry { code, retry_at })
                    .await?;
                Ok(RunOutcome::RetryScheduled)
            }
            Err(PublicationFailure::Permanent { code }) => {
                self.queue
                    .fail(&job, Utc::now(), JobFailure::Permanent { code })
                    .await?;
                Ok(RunOutcome::PermanentFailure)
            }
        }
    }

    pub async fn run(
        &self,
        poll_interval: Duration,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), WorkerLoopError> {
        loop {
            if *shutdown.borrow() {
                return Ok(());
            }
            match self.run_once(Utc::now()).await? {
                RunOutcome::Published
                | RunOutcome::RetryScheduled
                | RunOutcome::PermanentFailure => continue,
                RunOutcome::Idle | RunOutcome::PublisherUnavailable => {}
            }
            tokio::select! {
                _ = tokio::time::sleep(poll_interval) => {},
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return Ok(());
                    }
                }
            }
        }
    }
}
