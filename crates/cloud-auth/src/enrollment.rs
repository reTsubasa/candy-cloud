use chrono::{DateTime, Duration, Utc};
use cloud_db::{
    enrollment::{
        ChallengeCreationOutcome, EnrollmentChallengeStatus, EnrollmentChallengeWrite,
        EnrollmentRepository,
    },
    enrollment_completion::{
        EnrollmentCompletionOutcome, EnrollmentCompletionRecord, EnrollmentCompletionRepository,
        EnrollmentCompletionWrite,
    },
    DbPool,
};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    certificates::DeviceCertificateIssuer,
    enrollment_crypto::{verify_operational_proof, EnrollmentTranscript},
};

pub const ENROLLMENT_CHALLENGE_TTL: Duration = Duration::minutes(10);
const MAX_REQUEST_ID_LEN: usize = 120;
const MAX_INSTANCE_ID_LEN: usize = 120;
const MAX_DISPLAY_NAME_LEN: usize = 200;
const DEFAULT_ASSURANCE_LEVEL: u64 = 1;

#[derive(Clone)]
pub struct EnrollmentChallengeCommand {
    pub activation_credential: [u8; 32],
    pub request_id: String,
    pub enrollment_instance_id: String,
    pub display_name: String,
    pub root_public_key: [u8; 32],
    pub operational_public_key: [u8; 32],
    pub metadata_hash: [u8; 32],
    pub attestation_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentChallengeReceipt {
    pub challenge_id: Uuid,
    pub organization_id: Uuid,
    pub server_nonce: [u8; 32],
    pub expires_at: DateTime<Utc>,
    pub replayed: bool,
}

#[derive(Clone)]
pub struct EnrollmentCompleteCommand {
    pub challenge_id: Uuid,
    pub request_id: String,
    pub operational_proof: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentCompleteReceipt {
    pub device_id: Uuid,
    pub device_key_id: Uuid,
    pub certificate_der: Vec<u8>,
    pub certificate_chain_pem: String,
    pub not_after: DateTime<Utc>,
    pub replayed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EnrollmentCoordinatorError {
    #[error("invalid enrollment request")]
    InvalidRequest,
    #[error("activation credential unavailable")]
    ActivationUnavailable,
    #[error("enrollment request conflicts with persisted state")]
    Conflict,
    #[error("enrollment challenge unavailable")]
    ChallengeUnavailable,
    #[error("operational proof rejected")]
    ProofRejected,
    #[error("enrollment service unavailable")]
    Unavailable,
}

pub struct EnrollmentCoordinator {
    challenges: EnrollmentRepository,
    completions: EnrollmentCompletionRepository,
    certificate_issuer: DeviceCertificateIssuer,
}

impl EnrollmentCoordinator {
    pub fn new(pool: DbPool, certificate_issuer: DeviceCertificateIssuer) -> Self {
        Self {
            challenges: EnrollmentRepository::new(pool.clone()),
            completions: EnrollmentCompletionRepository::new(pool),
            certificate_issuer,
        }
    }

    pub async fn challenge(
        &self,
        command: EnrollmentChallengeCommand,
    ) -> Result<EnrollmentChallengeReceipt, EnrollmentCoordinatorError> {
        validate_challenge_command(&command)?;
        let now = Utc::now();
        let mut server_nonce = [0; 32];
        OsRng.fill_bytes(&mut server_nonce);
        let request_fingerprint = challenge_fingerprint(&command);
        let activation_code_hash = hash_activation_credential(&command.activation_credential);
        let write = EnrollmentChallengeWrite {
            id: Uuid::now_v7(),
            request_id: command.request_id,
            request_fingerprint,
            enrollment_instance_id: command.enrollment_instance_id,
            display_name: command.display_name,
            root_public_key: command.root_public_key,
            operational_public_key: command.operational_public_key,
            metadata_hash: command.metadata_hash,
            attestation_hash: command.attestation_hash,
            server_nonce,
            assurance_level: DEFAULT_ASSURANCE_LEVEL,
            expires_at: now + ENROLLMENT_CHALLENGE_TTL,
        };
        let outcome = self
            .challenges
            .reserve_challenge(&activation_code_hash, &write, now)
            .await
            .map_err(|_| EnrollmentCoordinatorError::Unavailable)?;
        match outcome {
            ChallengeCreationOutcome::Created(record) => Ok(EnrollmentChallengeReceipt {
                challenge_id: record.id,
                organization_id: record.organization_id,
                server_nonce: record.server_nonce,
                expires_at: record.expires_at,
                replayed: false,
            }),
            ChallengeCreationOutcome::Replay(record) => Ok(EnrollmentChallengeReceipt {
                challenge_id: record.id,
                organization_id: record.organization_id,
                server_nonce: record.server_nonce,
                expires_at: record.expires_at,
                replayed: true,
            }),
            ChallengeCreationOutcome::Conflict => Err(EnrollmentCoordinatorError::Conflict),
            ChallengeCreationOutcome::ActivationUnavailable => {
                Err(EnrollmentCoordinatorError::ActivationUnavailable)
            }
        }
    }

    pub async fn complete(
        &self,
        command: EnrollmentCompleteCommand,
    ) -> Result<EnrollmentCompleteReceipt, EnrollmentCoordinatorError> {
        if command.challenge_id.is_nil() || !bounded(&command.request_id, MAX_REQUEST_ID_LEN) {
            return Err(EnrollmentCoordinatorError::InvalidRequest);
        }
        let now = Utc::now();
        let challenge = self
            .challenges
            .load_challenge_for_proof(command.challenge_id, now)
            .await
            .map_err(|_| EnrollmentCoordinatorError::Unavailable)?
            .ok_or(EnrollmentCoordinatorError::ChallengeUnavailable)?;
        let transcript = EnrollmentTranscript::new(
            challenge.id,
            &challenge.server_nonce,
            &challenge.root_public_key,
            &challenge.operational_public_key,
            challenge.organization_id,
            &challenge.metadata_hash,
            &challenge.attestation_hash,
        )
        .map_err(|_| EnrollmentCoordinatorError::ProofRejected)?;
        verify_operational_proof(&transcript, &command.operational_proof)
            .map_err(|_| EnrollmentCoordinatorError::ProofRejected)?;

        if challenge.status == EnrollmentChallengeStatus::Issued {
            return self.replay(command.challenge_id, &command.request_id).await;
        }

        let device_id = Uuid::now_v7();
        let device_key_id = Uuid::now_v7();
        let certificate_id = Uuid::now_v7();
        let certificate = self
            .certificate_issuer
            .issue(
                device_id,
                device_key_id,
                challenge.operational_public_key,
                challenge.assurance_level,
                now,
            )
            .map_err(|_| EnrollmentCoordinatorError::Unavailable)?;
        let write = EnrollmentCompletionWrite {
            challenge_id: challenge.id,
            organization_id: challenge.organization_id,
            tenant_id: challenge.tenant_id,
            completion_request_id: command.request_id.clone(),
            device_record_id: device_id,
            device_identity: device_id,
            key_record_id: device_key_id,
            key_id: device_key_id.to_string(),
            certificate_id,
            issuer_key_id: certificate.issuer_key_id,
            serial_number: certificate.serial_number,
            certificate_der: certificate.certificate_der,
            certificate_chain_pem: certificate.certificate_chain_pem,
            environment: certificate.environment,
            not_before: certificate.not_before,
            not_after: certificate.not_after,
            issued_at: now,
        };
        match self
            .completions
            .complete(&write)
            .await
            .map_err(|_| EnrollmentCoordinatorError::Unavailable)?
        {
            EnrollmentCompletionOutcome::Issued(record) => Ok(receipt(record, false)),
            EnrollmentCompletionOutcome::Replay(record) => Ok(receipt(record, true)),
            EnrollmentCompletionOutcome::Conflict => {
                self.replay(command.challenge_id, &command.request_id).await
            }
            EnrollmentCompletionOutcome::ChallengeUnavailable => {
                Err(EnrollmentCoordinatorError::ChallengeUnavailable)
            }
        }
    }

    async fn replay(
        &self,
        challenge_id: Uuid,
        request_id: &str,
    ) -> Result<EnrollmentCompleteReceipt, EnrollmentCoordinatorError> {
        match self
            .completions
            .load_issued(challenge_id, request_id)
            .await
            .map_err(|_| EnrollmentCoordinatorError::Unavailable)?
        {
            EnrollmentCompletionOutcome::Replay(record) => Ok(receipt(record, true)),
            EnrollmentCompletionOutcome::Conflict => Err(EnrollmentCoordinatorError::Conflict),
            EnrollmentCompletionOutcome::ChallengeUnavailable => {
                Err(EnrollmentCoordinatorError::ChallengeUnavailable)
            }
            EnrollmentCompletionOutcome::Issued(_) => Err(EnrollmentCoordinatorError::Unavailable),
        }
    }
}

pub fn hash_activation_credential(credential: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"candy/enrollment-activation/v1");
    hash.update(credential);
    hash.finalize().into()
}

fn validate_challenge_command(
    command: &EnrollmentChallengeCommand,
) -> Result<(), EnrollmentCoordinatorError> {
    if !bounded(&command.request_id, MAX_REQUEST_ID_LEN)
        || !bounded(&command.enrollment_instance_id, MAX_INSTANCE_ID_LEN)
        || !bounded(&command.display_name, MAX_DISPLAY_NAME_LEN)
    {
        return Err(EnrollmentCoordinatorError::InvalidRequest);
    }
    Ok(())
}

fn challenge_fingerprint(command: &EnrollmentChallengeCommand) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"candy/enrollment-challenge-request/v1");
    for field in [
        command.request_id.as_bytes(),
        command.enrollment_instance_id.as_bytes(),
        command.display_name.as_bytes(),
        command.root_public_key.as_slice(),
        command.operational_public_key.as_slice(),
        command.metadata_hash.as_slice(),
        command.attestation_hash.as_slice(),
    ] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    hash.finalize().into()
}

fn receipt(record: EnrollmentCompletionRecord, replayed: bool) -> EnrollmentCompleteReceipt {
    EnrollmentCompleteReceipt {
        device_id: record.device_id,
        device_key_id: record.device_key_id,
        certificate_der: record.certificate_der,
        certificate_chain_pem: record.certificate_chain_pem,
        not_after: record.not_after,
        replayed,
    }
}

fn bounded(value: &str, max_len: usize) -> bool {
    !value.is_empty() && value.len() <= max_len
}
