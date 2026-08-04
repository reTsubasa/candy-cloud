use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use uuid::Uuid;

pub const ENROLLMENT_TRANSCRIPT_DOMAIN: &[u8] = b"candy/device-enrollment/v1";
pub const ENROLLMENT_PUBLIC_KEY_LEN: usize = 32;
pub const ENROLLMENT_HASH_LEN: usize = 32;
pub const ENROLLMENT_NONCE_LEN: usize = 32;
const MAX_TRANSCRIPT_LEN: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EnrollmentTranscriptError {
    #[error("server nonce must be exactly 32 bytes")]
    InvalidServerNonceLength,
    #[error("root public key must be exactly 32 bytes")]
    InvalidRootPublicKeyLength,
    #[error("operational public key must be exactly 32 bytes")]
    InvalidOperationalPublicKeyLength,
    #[error("metadata hash must be exactly 32 bytes")]
    InvalidMetadataHashLength,
    #[error("attestation hash must be exactly 32 bytes")]
    InvalidAttestationHashLength,
    #[error("enrollment transcript exceeds its bound")]
    TranscriptTooLarge,
    #[error("operational proof verification failed")]
    ProofVerificationFailed,
}

/// Canonical data that an operational key proves possession of during enrollment.
/// The caller owns challenge freshness and replay persistence; this primitive is deterministic.
#[derive(Debug, Clone, Copy)]
pub struct EnrollmentTranscript<'a> {
    challenge_id: Uuid,
    server_nonce: &'a [u8],
    root_public_key: &'a [u8],
    operational_public_key: &'a [u8],
    requested_organization: Uuid,
    metadata_hash: &'a [u8],
    attestation_hash: &'a [u8],
}

impl<'a> EnrollmentTranscript<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        challenge_id: Uuid,
        server_nonce: &'a [u8],
        root_public_key: &'a [u8],
        operational_public_key: &'a [u8],
        requested_organization: Uuid,
        metadata_hash: &'a [u8],
        attestation_hash: &'a [u8],
    ) -> Result<Self, EnrollmentTranscriptError> {
        exact_length(
            server_nonce,
            ENROLLMENT_NONCE_LEN,
            EnrollmentTranscriptError::InvalidServerNonceLength,
        )?;
        exact_length(
            root_public_key,
            ENROLLMENT_PUBLIC_KEY_LEN,
            EnrollmentTranscriptError::InvalidRootPublicKeyLength,
        )?;
        exact_length(
            operational_public_key,
            ENROLLMENT_PUBLIC_KEY_LEN,
            EnrollmentTranscriptError::InvalidOperationalPublicKeyLength,
        )?;
        exact_length(
            metadata_hash,
            ENROLLMENT_HASH_LEN,
            EnrollmentTranscriptError::InvalidMetadataHashLength,
        )?;
        exact_length(
            attestation_hash,
            ENROLLMENT_HASH_LEN,
            EnrollmentTranscriptError::InvalidAttestationHashLength,
        )?;
        Ok(Self {
            challenge_id,
            server_nonce,
            root_public_key,
            operational_public_key,
            requested_organization,
            metadata_hash,
            attestation_hash,
        })
    }

    /// Encodes every field with an explicit length prefix to make the transcript unambiguous.
    pub fn encode(&self) -> Result<Vec<u8>, EnrollmentTranscriptError> {
        let mut out = Vec::with_capacity(256);
        for field in [
            ENROLLMENT_TRANSCRIPT_DOMAIN,
            self.challenge_id.as_bytes(),
            self.server_nonce,
            self.root_public_key,
            self.operational_public_key,
            self.requested_organization.as_bytes(),
            self.metadata_hash,
            self.attestation_hash,
        ] {
            append_bounded(&mut out, field)?;
        }
        Ok(out)
    }
}

/// Verifies the Ed25519 proof without retaining or logging the proof bytes.
pub fn verify_operational_proof(
    transcript: &EnrollmentTranscript<'_>,
    proof: &[u8; 64],
) -> Result<(), EnrollmentTranscriptError> {
    let encoded = transcript.encode()?;
    let key_bytes: &[u8; ENROLLMENT_PUBLIC_KEY_LEN] = transcript
        .operational_public_key
        .try_into()
        .map_err(|_| EnrollmentTranscriptError::InvalidOperationalPublicKeyLength)?;
    let verifying_key = VerifyingKey::from_bytes(key_bytes)
        .map_err(|_| EnrollmentTranscriptError::ProofVerificationFailed)?;
    verifying_key
        .verify(&encoded, &Signature::from_bytes(proof))
        .map_err(|_| EnrollmentTranscriptError::ProofVerificationFailed)
}

fn exact_length(
    value: &[u8],
    expected: usize,
    error: EnrollmentTranscriptError,
) -> Result<(), EnrollmentTranscriptError> {
    if value.len() == expected {
        Ok(())
    } else {
        Err(error)
    }
}

fn append_bounded(out: &mut Vec<u8>, field: &[u8]) -> Result<(), EnrollmentTranscriptError> {
    let length =
        u16::try_from(field.len()).map_err(|_| EnrollmentTranscriptError::TranscriptTooLarge)?;
    let final_len = out
        .len()
        .checked_add(std::mem::size_of::<u16>())
        .and_then(|length| length.checked_add(field.len()))
        .ok_or(EnrollmentTranscriptError::TranscriptTooLarge)?;
    if final_len > MAX_TRANSCRIPT_LEN {
        return Err(EnrollmentTranscriptError::TranscriptTooLarge);
    }
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    use super::{verify_operational_proof, EnrollmentTranscript, EnrollmentTranscriptError};

    struct Fixture {
        challenge_id: Uuid,
        server_nonce: [u8; 32],
        root_public_key: [u8; 32],
        operational_key: SigningKey,
        operational_public_key: [u8; 32],
        organization_id: Uuid,
        metadata_hash: [u8; 32],
        attestation_hash: [u8; 32],
    }

    impl Fixture {
        fn new() -> Self {
            let operational_key = SigningKey::from_bytes(&[4; 32]);
            Self {
                challenge_id: Uuid::from_bytes([1; 16]),
                server_nonce: [2; 32],
                root_public_key: [3; 32],
                operational_public_key: operational_key.verifying_key().to_bytes(),
                operational_key,
                organization_id: Uuid::from_bytes([5; 16]),
                metadata_hash: [6; 32],
                attestation_hash: [7; 32],
            }
        }

        fn transcript(&self) -> EnrollmentTranscript<'_> {
            EnrollmentTranscript::new(
                self.challenge_id,
                &self.server_nonce,
                &self.root_public_key,
                &self.operational_public_key,
                self.organization_id,
                &self.metadata_hash,
                &self.attestation_hash,
            )
            .expect("valid fixture")
        }
    }

    #[test]
    fn valid_operational_proof_verifies_for_its_transcript() {
        let fixture = Fixture::new();
        let transcript = fixture.transcript();
        let proof = fixture
            .operational_key
            .sign(&transcript.encode().unwrap())
            .to_bytes();

        assert_eq!(verify_operational_proof(&transcript, &proof), Ok(()));
    }

    #[test]
    fn altered_proof_fails_closed() {
        let fixture = Fixture::new();
        let transcript = fixture.transcript();
        let mut proof = fixture
            .operational_key
            .sign(&transcript.encode().unwrap())
            .to_bytes();
        proof[0] ^= 1;

        assert_eq!(
            verify_operational_proof(&transcript, &proof),
            Err(EnrollmentTranscriptError::ProofVerificationFailed)
        );
    }

    #[test]
    fn proof_must_be_verified_by_the_operational_key_bound_into_the_transcript() {
        let fixture = Fixture::new();
        let transcript = fixture.transcript();
        let attacker = SigningKey::from_bytes(&[10; 32]);
        let proof = attacker.sign(&transcript.encode().unwrap()).to_bytes();

        assert_eq!(
            verify_operational_proof(&transcript, &proof),
            Err(EnrollmentTranscriptError::ProofVerificationFailed)
        );
    }

    #[test]
    fn changed_nonce_invalidates_proof() {
        let fixture = Fixture::new();
        let proof = fixture
            .operational_key
            .sign(&fixture.transcript().encode().unwrap())
            .to_bytes();
        let mut changed_nonce = fixture.server_nonce;
        changed_nonce[0] ^= 1;
        let changed = EnrollmentTranscript::new(
            fixture.challenge_id,
            &changed_nonce,
            &fixture.root_public_key,
            &fixture.operational_public_key,
            fixture.organization_id,
            &fixture.metadata_hash,
            &fixture.attestation_hash,
        )
        .unwrap();

        assert_eq!(
            verify_operational_proof(&changed, &proof),
            Err(EnrollmentTranscriptError::ProofVerificationFailed)
        );
    }

    #[test]
    fn changed_organization_invalidates_proof() {
        let fixture = Fixture::new();
        let proof = fixture
            .operational_key
            .sign(&fixture.transcript().encode().unwrap())
            .to_bytes();
        let changed = EnrollmentTranscript::new(
            fixture.challenge_id,
            &fixture.server_nonce,
            &fixture.root_public_key,
            &fixture.operational_public_key,
            Uuid::from_bytes([8; 16]),
            &fixture.metadata_hash,
            &fixture.attestation_hash,
        )
        .unwrap();

        assert_eq!(
            verify_operational_proof(&changed, &proof),
            Err(EnrollmentTranscriptError::ProofVerificationFailed)
        );
    }

    #[test]
    fn proof_cannot_be_replayed_against_another_challenge() {
        let fixture = Fixture::new();
        let proof = fixture
            .operational_key
            .sign(&fixture.transcript().encode().unwrap())
            .to_bytes();
        let changed = EnrollmentTranscript::new(
            Uuid::from_bytes([9; 16]),
            &fixture.server_nonce,
            &fixture.root_public_key,
            &fixture.operational_public_key,
            fixture.organization_id,
            &fixture.metadata_hash,
            &fixture.attestation_hash,
        )
        .unwrap();

        assert_eq!(
            verify_operational_proof(&changed, &proof),
            Err(EnrollmentTranscriptError::ProofVerificationFailed)
        );
    }

    #[test]
    fn field_boundaries_are_length_delimited_and_bad_lengths_are_rejected() {
        let fixture = Fixture::new();
        let original = fixture.transcript().encode().unwrap();
        let changed = EnrollmentTranscript::new(
            fixture.challenge_id,
            &fixture.server_nonce,
            &fixture.root_public_key,
            &fixture.operational_public_key,
            fixture.organization_id,
            &[0; 32],
            &fixture.attestation_hash,
        )
        .unwrap()
        .encode()
        .unwrap();

        assert_ne!(original, changed);
        assert!(matches!(
            EnrollmentTranscript::new(
                fixture.challenge_id,
                &fixture.server_nonce,
                &[0; 31],
                &fixture.operational_key.verifying_key().to_bytes(),
                fixture.organization_id,
                &fixture.metadata_hash,
                &fixture.attestation_hash,
            ),
            Err(EnrollmentTranscriptError::InvalidRootPublicKeyLength)
        ));
    }

    #[test]
    fn canonical_encoding_matches_the_v1_golden_vector() {
        let encoded = EnrollmentTranscript::new(
            Uuid::from_bytes([1; 16]),
            &[2; 32],
            &[3; 32],
            &[4; 32],
            Uuid::from_bytes([5; 16]),
            &[6; 32],
            &[7; 32],
        )
        .unwrap()
        .encode()
        .unwrap();

        assert_eq!(encoded.len(), 234);
        assert_eq!(
            Sha256::digest(encoded).as_slice(),
            &[
                0x42, 0x63, 0x13, 0xb2, 0x01, 0xac, 0xf8, 0x41, 0xfd, 0x9f, 0x47, 0xf8, 0xec, 0xe2,
                0xca, 0x5e, 0x7b, 0x0a, 0x28, 0x4f, 0xcb, 0x42, 0xcc, 0x78, 0x68, 0x55, 0xeb, 0x4c,
                0x3e, 0xb1, 0x5a, 0x85,
            ]
        );
    }
}
