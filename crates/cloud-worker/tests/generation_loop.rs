use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use cloud_db::control::{ControlStoreError, GenerationJob, JobFailure};
use cloud_worker::generation_loop::{
    GenerationJobQueue, GenerationPublisher, GenerationWorker, PublicationFailure,
    PublishedGeneration, RunOutcome,
};
use cloud_worker::route_types::PUBLICATION_REFRESH_LEAD_SECONDS;
use uuid::Uuid;

#[derive(Default)]
struct QueueState {
    jobs: VecDeque<GenerationJob>,
    published: Vec<(Uuid, PublishedGeneration)>,
    failures: Vec<(Uuid, JobFailure)>,
    refreshes: Vec<(DateTime<Utc>, Duration, u16)>,
    claims: usize,
    refresh_failures: usize,
    claim_failures: usize,
    commit_failures: usize,
    hang_refresh: bool,
    hang_claim: bool,
}

#[derive(Clone, Default)]
struct FakeQueue(Arc<Mutex<QueueState>>, Arc<tokio::sync::Notify>);

#[async_trait]
impl GenerationJobQueue for FakeQueue {
    async fn refresh_expiring(
        &self,
        now: DateTime<Utc>,
        refresh_before: Duration,
        limit: u16,
    ) -> Result<u16, ControlStoreError> {
        let hang = {
            let mut state = self.0.lock().unwrap();
            state.refreshes.push((now, refresh_before, limit));
            if state.refresh_failures > 0 {
                state.refresh_failures -= 1;
                return Err(ControlStoreError::LeaseLost);
            }
            state.hang_refresh
        };
        if hang {
            std::future::pending::<()>().await;
        }
        Ok(0)
    }

    async fn claim_next(
        &self,
        _owner: &str,
        _now: DateTime<Utc>,
        _ttl: Duration,
    ) -> Result<Option<GenerationJob>, ControlStoreError> {
        let (hang, job) = {
            let mut state = self.0.lock().unwrap();
            state.claims += 1;
            if state.claim_failures > 0 {
                state.claim_failures -= 1;
                return Err(ControlStoreError::LeaseLost);
            }
            (state.hang_claim, state.jobs.pop_front())
        };
        if hang {
            std::future::pending::<()>().await;
        }
        Ok(job)
    }

    async fn publish(
        &self,
        job: &GenerationJob,
        _now: DateTime<Utc>,
        result: PublishedGeneration,
    ) -> Result<(), ControlStoreError> {
        let mut state = self.0.lock().unwrap();
        if state.commit_failures > 0 {
            state.commit_failures -= 1;
            return Err(ControlStoreError::LeaseLost);
        }
        state.published.push((job.id, result));
        self.1.notify_one();
        Ok(())
    }

    async fn fail(
        &self,
        job: &GenerationJob,
        _now: DateTime<Utc>,
        failure: JobFailure,
    ) -> Result<(), ControlStoreError> {
        self.0.lock().unwrap().failures.push((job.id, failure));
        Ok(())
    }
}

#[derive(Clone)]
struct FakePublisher(Result<PublishedGeneration, PublicationFailure>);

#[async_trait]
impl GenerationPublisher for FakePublisher {
    fn ready(&self) -> bool {
        true
    }
    async fn publish(
        &self,
        _job: &GenerationJob,
    ) -> Result<PublishedGeneration, PublicationFailure> {
        self.0.clone()
    }
}

fn job() -> GenerationJob {
    GenerationJob {
        id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        segment_id: Uuid::new_v4(),
        desired_revision: 4,
        policy_only: false,
        attempt_count: 2,
        lease_owner: "worker-a".into(),
        lease_until: Utc::now() + chrono::Duration::minutes(1),
    }
}

fn queue_with_job() -> FakeQueue {
    let queue = FakeQueue::default();
    queue.0.lock().unwrap().jobs.push_back(job());
    queue
}

#[tokio::test]
async fn successful_publication_completes_the_claimed_job() {
    let queue = queue_with_job();
    let result = PublishedGeneration {
        generation: 9,
        content_hash: [7; 32],
    };
    let worker = GenerationWorker::new(
        queue.clone(),
        FakePublisher(Ok(result)),
        "worker-a".into(),
        Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(
        worker.run_once(Utc::now()).await.unwrap(),
        RunOutcome::Published
    );
    assert_eq!(queue.0.lock().unwrap().published.len(), 1);
    let state = queue.0.lock().unwrap();
    assert_eq!(state.refreshes.len(), 1);
    assert_eq!(
        state.refreshes[0].1,
        Duration::from_secs(PUBLICATION_REFRESH_LEAD_SECONDS)
    );
    assert_eq!(state.refreshes[0].2, 32);
}

#[tokio::test]
async fn retryable_failure_is_scheduled_without_marking_success() {
    let queue = queue_with_job();
    let publisher = FakePublisher(Err(PublicationFailure::Retryable {
        code: "DATABASE_UNAVAILABLE".into(),
        retry_after: Duration::from_secs(10),
    }));
    let worker = GenerationWorker::new(
        queue.clone(),
        publisher,
        "worker-a".into(),
        Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(
        worker.run_once(Utc::now()).await.unwrap(),
        RunOutcome::RetryScheduled
    );
    let state = queue.0.lock().unwrap();
    assert!(state.published.is_empty());
    assert!(
        matches!(&state.failures[0].1, JobFailure::Retry { code, .. } if code == "DATABASE_UNAVAILABLE")
    );
}

#[tokio::test]
async fn permanent_failure_is_terminal_without_marking_success() {
    let queue = queue_with_job();
    let publisher = FakePublisher(Err(PublicationFailure::Permanent {
        code: "PREFIX_OVERLAP".into(),
    }));
    let worker = GenerationWorker::new(
        queue.clone(),
        publisher,
        "worker-a".into(),
        Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(
        worker.run_once(Utc::now()).await.unwrap(),
        RunOutcome::PermanentFailure
    );
    let state = queue.0.lock().unwrap();
    assert!(state.published.is_empty());
    assert!(
        matches!(&state.failures[0].1, JobFailure::Permanent { code } if code == "PREFIX_OVERLAP")
    );
}

#[tokio::test]
async fn publisher_error_text_is_normalized_before_persistence() {
    let queue = queue_with_job();
    let publisher = FakePublisher(Err(PublicationFailure::Permanent {
        code: "route input: active Attachment has no signed path candidates / unsafe detail".into(),
    }));
    let worker = GenerationWorker::new(
        queue.clone(),
        publisher,
        "worker-a".into(),
        Duration::from_secs(30),
    )
    .unwrap();

    assert_eq!(
        worker.run_once(Utc::now()).await.unwrap(),
        RunOutcome::PermanentFailure
    );
    let state = queue.0.lock().unwrap();
    assert!(matches!(
        &state.failures[0].1,
        JobFailure::Permanent { code }
            if code == "ROUTE_INPUT_ACTIVE_ATTACHMENT_HAS_NO_SIGNED_PATH_CANDIDATES_UNSAFE_DETAIL"
                && code.len() <= 80
    ));
}

fn successful_worker(
    queue: FakeQueue,
    ttl: Duration,
) -> GenerationWorker<FakeQueue, FakePublisher> {
    GenerationWorker::new(
        queue,
        FakePublisher(Ok(PublishedGeneration {
            generation: 9,
            content_hash: [7; 32],
        })),
        "worker-a".into(),
        ttl,
    )
    .unwrap()
}

#[tokio::test(start_paused = true)]
async fn storage_outage_backs_off_and_recovers_without_exiting_worker() {
    let queue = queue_with_job();
    queue.0.lock().unwrap().claim_failures = 2;
    let worker = successful_worker(queue.clone(), Duration::from_secs(30));
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move { worker.run(Duration::from_secs(1), shutdown).await });
    tokio::time::timeout(Duration::from_secs(10), queue.1.notified())
        .await
        .unwrap();
    assert!(!task.is_finished());
    {
        let state = queue.0.lock().unwrap();
        assert_eq!(state.refreshes.len(), 3);
        assert_eq!(state.claims, 3);
        assert_eq!(state.published.len(), 1);
    }
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn one_segments_receipt_failure_does_not_stop_the_next_segment() {
    let queue = queue_with_job();
    let healthy_job = job();
    {
        let mut state = queue.0.lock().unwrap();
        state.jobs.push_back(healthy_job.clone());
        state.commit_failures = 1;
    }
    let worker = successful_worker(queue.clone(), Duration::from_secs(30));
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move { worker.run(Duration::from_secs(1), shutdown).await });
    tokio::time::timeout(Duration::from_secs(10), queue.1.notified())
        .await
        .unwrap();
    assert_eq!(queue.0.lock().unwrap().published[0].0, healthy_job.id);
    assert!(!task.is_finished());
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn hung_storage_is_deadlined_and_shutdown_does_not_wait_for_it() {
    let queue = FakeQueue::default();
    queue.0.lock().unwrap().hang_claim = true;
    let worker = successful_worker(queue.clone(), Duration::from_secs(1));
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move { worker.run(Duration::from_secs(1), shutdown).await });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    // First timeout waits two seconds before the next iteration.
    assert_eq!(queue.0.lock().unwrap().refreshes.len(), 1);
    tokio::time::advance(Duration::from_secs(2)).await;
    tokio::task::yield_now().await;
    assert_eq!(queue.0.lock().unwrap().refreshes.len(), 2);
    drop(stop);
    tokio::time::timeout(Duration::from_millis(10), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn malformed_publisher_retry_is_rejected_as_a_job_error() {
    let queue = queue_with_job();
    let worker = GenerationWorker::new(
        queue.clone(),
        FakePublisher(Err(PublicationFailure::Retryable {
            code: "broken publisher retry".into(),
            retry_after: Duration::ZERO,
        })),
        "worker-a".into(),
        Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(
        worker.run_once(Utc::now()).await.unwrap(),
        RunOutcome::PermanentFailure
    );
    assert!(matches!(&queue.0.lock().unwrap().failures[0].1,
        JobFailure::Permanent { code } if code == "PUBLICATION_RETRY_DELAY_INVALID"));
}

#[tokio::test]
async fn zero_poll_interval_is_rejected_without_spinning() {
    let worker = successful_worker(FakeQueue::default(), Duration::from_secs(30));
    let (_stop, shutdown) = tokio::sync::watch::channel(false);
    assert!(matches!(
        worker.run(Duration::ZERO, shutdown).await,
        Err(cloud_worker::generation_loop::WorkerLoopError::InvalidPollInterval)
    ));
}

#[tokio::test(start_paused = true)]
async fn failing_or_stalled_renewal_scan_does_not_block_existing_jobs() {
    for hang in [false, true] {
        let queue = queue_with_job();
        {
            let mut state = queue.0.lock().unwrap();
            state.hang_refresh = hang;
            state.refresh_failures = usize::from(!hang);
        }
        let worker = successful_worker(queue.clone(), Duration::from_secs(30));
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(6), worker.run_once(Utc::now()))
                .await
                .unwrap()
                .unwrap(),
            RunOutcome::Published
        );
        assert_eq!(queue.0.lock().unwrap().published.len(), 1);
    }
}
