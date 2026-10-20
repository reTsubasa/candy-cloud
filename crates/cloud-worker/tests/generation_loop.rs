use std::{
    collections::{HashMap, VecDeque},
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
    leased: HashMap<Uuid, (GenerationJob, tokio::time::Instant)>,
    owners: Vec<String>,
    published: Vec<(Uuid, PublishedGeneration)>,
    failures: Vec<(Uuid, JobFailure)>,
    refreshes: Vec<(DateTime<Utc>, Duration, u16)>,
    claims: usize,
    recovery_calls: usize,
    recovery_failures: usize,
    hang_recovery: bool,
    recoverable_job: Option<GenerationJob>,
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
    async fn recover_failed_heads(&self) -> Result<u64, ControlStoreError> {
        let hang = {
            let mut state = self.0.lock().unwrap();
            state.recovery_calls += 1;
            if state.recovery_failures > 0 {
                state.recovery_failures -= 1;
                return Err(ControlStoreError::LeaseLost);
            }
            if let Some(job) = state.recoverable_job.take() {
                state.jobs.push_back(job);
                return Ok(1);
            }
            state.hang_recovery
        };
        if hang {
            std::future::pending::<()>().await;
        }
        Ok(0)
    }
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
        owner: &str,
        _now: DateTime<Utc>,
        ttl: Duration,
    ) -> Result<Option<GenerationJob>, ControlStoreError> {
        let (hang, job) = {
            let mut state = self.0.lock().unwrap();
            state.claims += 1;
            if state.claim_failures > 0 {
                state.claim_failures -= 1;
                return Err(ControlStoreError::LeaseLost);
            }
            state.owners.push(owner.to_owned());
            let now = tokio::time::Instant::now();
            let expired = state
                .leased
                .iter()
                .filter(|(_, (_, expires))| *expires <= now)
                .map(|(id, _)| *id)
                .collect::<Vec<_>>();
            for id in expired {
                let (job, _) = state.leased.remove(&id).unwrap();
                state.jobs.push_front(job);
            }
            let index = state.jobs.iter().position(|candidate| {
                !state.leased.values().any(|(active, _)| {
                    active.tenant_id == candidate.tenant_id
                        && active.segment_id == candidate.segment_id
                }) && !state.jobs.iter().any(|earlier| {
                    earlier.tenant_id == candidate.tenant_id
                        && earlier.segment_id == candidate.segment_id
                        && earlier.desired_revision < candidate.desired_revision
                })
            });
            let job = index.and_then(|index| state.jobs.remove(index));
            if let Some(job) = &job {
                state.leased.insert(job.id, (job.clone(), now + ttl));
            }
            (state.hang_claim, job)
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
        state.leased.remove(&job.id);
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
        let mut state = self.0.lock().unwrap();
        state.leased.remove(&job.id);
        state.failures.push((job.id, failure));
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
    let task = tokio::spawn(async move {
        worker
            .run_with_concurrency(Duration::from_secs(1), 1, shutdown)
            .await
    });
    tokio::time::timeout(Duration::from_secs(10), queue.1.notified())
        .await
        .unwrap();
    assert!(!task.is_finished());
    {
        let state = queue.0.lock().unwrap();
        assert!(!state.refreshes.is_empty());
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
    let task = tokio::spawn(async move {
        worker
            .run_with_concurrency(Duration::from_secs(1), 1, shutdown)
            .await
    });
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
    let task = tokio::spawn(async move {
        worker
            .run_with_concurrency(Duration::from_secs(1), 1, shutdown)
            .await
    });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    // First timeout waits two seconds before the next iteration.
    assert_eq!(queue.0.lock().unwrap().claims, 1);
    tokio::time::advance(Duration::from_secs(2)).await;
    tokio::task::yield_now().await;
    assert_eq!(queue.0.lock().unwrap().claims, 2);
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

#[derive(Clone)]
struct DelayedPublisher {
    slow_job: Uuid,
    attempts: Arc<Mutex<HashMap<Uuid, usize>>>,
    in_flight: Arc<std::sync::atomic::AtomicUsize>,
    peak: Arc<std::sync::atomic::AtomicUsize>,
    cancelled: Arc<std::sync::atomic::AtomicUsize>,
    delay: Duration,
    first_attempt_only: bool,
}

struct InFlight {
    count: Arc<std::sync::atomic::AtomicUsize>,
    cancelled: Arc<std::sync::atomic::AtomicUsize>,
    finished: bool,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;
        self.count.fetch_sub(1, Ordering::SeqCst);
        if !self.finished {
            self.cancelled.fetch_add(1, Ordering::SeqCst);
        }
    }
}

impl DelayedPublisher {
    fn new(slow_job: Uuid, delay: Duration) -> Self {
        Self {
            slow_job,
            attempts: Default::default(),
            in_flight: Default::default(),
            peak: Default::default(),
            cancelled: Default::default(),
            delay,
            first_attempt_only: false,
        }
    }
}

#[async_trait]
impl GenerationPublisher for DelayedPublisher {
    fn ready(&self) -> bool {
        true
    }

    async fn publish(
        &self,
        job: &GenerationJob,
    ) -> Result<PublishedGeneration, PublicationFailure> {
        use std::sync::atomic::Ordering;
        let attempt = {
            let mut attempts = self.attempts.lock().unwrap();
            let count = attempts.entry(job.id).or_default();
            *count += 1;
            *count
        };
        let count = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(count, Ordering::SeqCst);
        let mut guard = InFlight {
            count: self.in_flight.clone(),
            cancelled: self.cancelled.clone(),
            finished: false,
        };
        if job.id == self.slow_job && (!self.first_attempt_only || attempt == 1) {
            tokio::time::sleep(self.delay).await;
        } else {
            tokio::task::yield_now().await;
        }
        guard.finished = true;
        Ok(PublishedGeneration {
            generation: job.desired_revision,
            content_hash: [7; 32],
        })
    }
}

#[tokio::test(start_paused = true)]
async fn slow_segment_does_not_block_other_segments_and_same_segment_stays_ordered() {
    use std::sync::atomic::Ordering;
    let queue = FakeQueue::default();
    let slow = job();
    let mut next = slow.clone();
    next.id = Uuid::new_v4();
    next.desired_revision += 1;
    let healthy = job();
    queue
        .0
        .lock()
        .unwrap()
        .jobs
        .extend([slow.clone(), next.clone(), healthy.clone()]);
    let publisher = DelayedPublisher::new(slow.id, Duration::from_secs(10));
    let worker = GenerationWorker::new(
        queue.clone(),
        publisher.clone(),
        "worker-a".into(),
        Duration::from_secs(30),
    )
    .unwrap();
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move {
        worker
            .run_with_concurrency(Duration::from_millis(50), 2, shutdown)
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), queue.1.notified())
        .await
        .unwrap();
    assert_eq!(queue.0.lock().unwrap().published[0].0, healthy.id);
    assert!(!publisher.attempts.lock().unwrap().contains_key(&next.id));
    while queue.0.lock().unwrap().published.len() < 3 {
        tokio::time::timeout(Duration::from_secs(11), queue.1.notified())
            .await
            .unwrap();
    }
    {
        let state = queue.0.lock().unwrap();
        assert_eq!(
            state
                .published
                .iter()
                .map(|(id, _)| *id)
                .collect::<Vec<_>>(),
            [healthy.id, slow.id, next.id]
        );
        assert!(
            state
                .owners
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                >= 2
        );
    }
    assert_eq!(publisher.peak.load(Ordering::SeqCst), 2);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn hung_publication_is_cancelled_then_reclaimed_after_lease_expiration() {
    use std::sync::atomic::Ordering;
    let queue = queue_with_job();
    let slow_id = queue.0.lock().unwrap().jobs[0].id;
    let mut publisher = DelayedPublisher::new(slow_id, Duration::from_secs(100));
    publisher.first_attempt_only = true;
    let worker = GenerationWorker::new(
        queue.clone(),
        publisher.clone(),
        "worker-a".into(),
        Duration::from_secs(1),
    )
    .unwrap();
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move {
        worker
            .run_with_concurrency(Duration::from_millis(50), 1, shutdown)
            .await
    });
    tokio::time::timeout(Duration::from_secs(4), queue.1.notified())
        .await
        .unwrap();
    assert_eq!(publisher.attempts.lock().unwrap()[&slow_id], 2);
    assert_eq!(publisher.cancelled.load(Ordering::SeqCst), 1);
    assert_eq!(queue.0.lock().unwrap().published.len(), 1);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn shutdown_aborts_in_flight_publication_and_single_renewal_scanner() {
    use std::sync::atomic::Ordering;
    let queue = queue_with_job();
    let slow_id = queue.0.lock().unwrap().jobs[0].id;
    queue.0.lock().unwrap().hang_refresh = true;
    let publisher = DelayedPublisher::new(slow_id, Duration::from_secs(100));
    let worker = GenerationWorker::new(
        queue.clone(),
        publisher.clone(),
        "worker-a".into(),
        Duration::from_secs(30),
    )
    .unwrap();
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move {
        worker
            .run_with_concurrency(Duration::from_secs(1), 4, shutdown)
            .await
    });
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(publisher.in_flight.load(Ordering::SeqCst), 1);
    assert_eq!(queue.0.lock().unwrap().refreshes.len(), 1);
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_millis(10), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(publisher.in_flight.load(Ordering::SeqCst), 0);
    assert_eq!(publisher.cancelled.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_secs(100)).await;
    let state = queue.0.lock().unwrap();
    assert!(state.published.is_empty());
    assert_eq!(state.refreshes.len(), 1);
    assert_eq!(state.leased.len(), 1);
}

#[tokio::test]
async fn invalid_concurrency_is_rejected_before_any_claim() {
    for concurrency in [0, 33] {
        let queue = FakeQueue::default();
        let worker = successful_worker(queue.clone(), Duration::from_secs(30));
        let (_stop, shutdown) = tokio::sync::watch::channel(false);
        assert!(matches!(
            worker
                .run_with_concurrency(Duration::from_secs(1), concurrency, shutdown)
                .await,
            Err(cloud_worker::generation_loop::WorkerLoopError::InvalidConcurrency)
        ));
        assert_eq!(queue.0.lock().unwrap().claims, 0);
    }
}

#[tokio::test(start_paused = true)]
async fn failing_recovery_retries_without_blocking_healthy_publications() {
    let queue = queue_with_job();
    let recovered = job();
    let recovered_id = recovered.id;
    {
        let mut state = queue.0.lock().unwrap();
        state.recovery_failures = 2;
        state.recoverable_job = Some(recovered);
    }
    let worker = successful_worker(queue.clone(), Duration::from_secs(30));
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move {
        worker
            .run_with_concurrency(Duration::from_millis(50), 2, shutdown)
            .await
    });
    while queue.0.lock().unwrap().published.len() < 2 {
        tokio::time::timeout(Duration::from_secs(10), queue.1.notified())
            .await
            .unwrap();
    }
    {
        let state = queue.0.lock().unwrap();
        assert_eq!(state.recovery_calls, 3);
        assert_eq!(state.published[1].0, recovered_id);
        assert!(!state.refreshes.is_empty());
    }
    assert!(!task.is_finished());
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn stalled_recovery_does_not_block_lanes_or_shutdown() {
    let queue = queue_with_job();
    queue.0.lock().unwrap().hang_recovery = true;
    let worker = successful_worker(queue.clone(), Duration::from_secs(30));
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move {
        worker
            .run_with_concurrency(Duration::from_millis(50), 2, shutdown)
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), queue.1.notified())
        .await
        .unwrap();
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(queue.0.lock().unwrap().recovery_calls, 1);
    assert_eq!(queue.0.lock().unwrap().published.len(), 1);
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_millis(10), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
