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
use uuid::Uuid;

#[derive(Default)]
struct QueueState {
    jobs: VecDeque<GenerationJob>,
    published: Vec<(Uuid, PublishedGeneration)>,
    failures: Vec<(Uuid, JobFailure)>,
    claims: usize,
}

#[derive(Clone, Default)]
struct FakeQueue(Arc<Mutex<QueueState>>);

#[async_trait]
impl GenerationJobQueue for FakeQueue {
    async fn claim_next(
        &self,
        _owner: &str,
        _now: DateTime<Utc>,
        _ttl: Duration,
    ) -> Result<Option<GenerationJob>, ControlStoreError> {
        let mut state = self.0.lock().unwrap();
        state.claims += 1;
        Ok(state.jobs.pop_front())
    }

    async fn publish(
        &self,
        job: &GenerationJob,
        _now: DateTime<Utc>,
        result: PublishedGeneration,
    ) -> Result<(), ControlStoreError> {
        self.0.lock().unwrap().published.push((job.id, result));
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
