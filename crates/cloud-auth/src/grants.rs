use std::sync::Arc;

use cloud_core_module::{CoreModule, ObjectType, PreparedObject};
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub const PRIVATE_GRANT_TTL_SECS: u64 = 24 * 60 * 60;
pub const PRIVATE_GRANT_REFRESH_NUMERATOR: u64 = 3;
pub const PRIVATE_GRANT_REFRESH_DENOMINATOR: u64 = 4;

const BUILD_SCHEMA_V1: &str = "candy-core-cloud-build-v1";

#[derive(Debug, thiserror::Error)]
pub enum GrantIssueError {
    #[error("grant time arithmetic overflow")]
    TimeOverflow,
    #[error("Core Grant build request serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Core Grant operation failed: {0}")]
    Core(String),
    #[error("Core returned object type {0} for a Grant payload request")]
    UnexpectedObjectType(u32),
}

/// A Core-defined signed envelope. Cloud persists and returns only the opaque
/// wire bytes and never owns a Grant codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedGrant {
    raw: Vec<u8>,
}

impl IssuedGrant {
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(&self.raw).into()
    }
}

/// Narrow protocol surface used by Grant issuance. Production uses the native
/// Core module; tests can exercise Cloud policy without duplicating Core codecs.
pub trait GrantCoreModule: Send + Sync {
    fn prepare(&self, request: &[u8]) -> Result<PreparedObject, String>;
    fn assemble(
        &self,
        object_type: ObjectType,
        signing_key_id: &[u8],
        payload: &[u8],
        signature: &[u8; 64],
    ) -> Result<Vec<u8>, String>;
    fn validate(
        &self,
        object_type: ObjectType,
        input: &[u8],
        verifying_key: Option<&[u8; 32]>,
    ) -> Result<(), String>;
}

impl GrantCoreModule for CoreModule {
    fn prepare(&self, request: &[u8]) -> Result<PreparedObject, String> {
        CoreModule::prepare(self, request).map_err(|error| error.to_string())
    }

    fn assemble(
        &self,
        object_type: ObjectType,
        signing_key_id: &[u8],
        payload: &[u8],
        signature: &[u8; 64],
    ) -> Result<Vec<u8>, String> {
        CoreModule::assemble(self, object_type, signing_key_id, payload, signature)
            .map_err(|error| error.to_string())
    }

    fn validate(
        &self,
        object_type: ObjectType,
        input: &[u8],
        verifying_key: Option<&[u8; 32]>,
    ) -> Result<(), String> {
        CoreModule::validate(self, object_type, input, verifying_key)
            .map_err(|error| error.to_string())
    }
}

/// Cloud-owned Ed25519 signing capability paired with one immutable Core
/// module loaded and verified at process startup.
pub struct GrantSigner {
    key_id: String,
    signing_key: SigningKey,
    core: Arc<dyn GrantCoreModule>,
}

impl GrantSigner {
    pub fn new(
        key_id: impl Into<String>,
        signing_key: SigningKey,
        core: Arc<CoreModule>,
    ) -> Self {
        Self::with_core(key_id, signing_key, core)
    }

    pub fn with_core(
        key_id: impl Into<String>,
        signing_key: SigningKey,
        core: Arc<dyn GrantCoreModule>,
    ) -> Self {
        Self {
            key_id: key_id.into(),
            signing_key,
            core,
        }
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Prepares canonical bytes in Core, signs the exact Core transcript in
    /// Cloud, then delegates envelope assembly and final validation to Core.
    pub fn issue_private<T: Serialize>(&self, object: &T) -> Result<IssuedGrant, GrantIssueError> {
        #[derive(Serialize)]
        struct BuildRequest<'a, T> {
            schema: &'static str,
            signing_key_id_hex: String,
            object: &'a T,
        }

        let request = serde_json::to_vec(&BuildRequest {
            schema: BUILD_SCHEMA_V1,
            signing_key_id_hex: encode_hex(self.key_id.as_bytes()),
            object,
        })?;
        let prepared = self
            .core
            .prepare(&request)
            .map_err(GrantIssueError::Core)?;
        if prepared.object_type != ObjectType::GRANT_PAYLOAD_V1 {
            return Err(GrantIssueError::UnexpectedObjectType(
                prepared.object_type.0,
            ));
        }
        let signature = self.signing_key.sign(&prepared.signing_transcript).to_bytes();
        let raw = self
            .core
            .assemble(
                prepared.object_type,
                self.key_id.as_bytes(),
                &prepared.payload,
                &signature,
            )
            .map_err(GrantIssueError::Core)?;
        let verifying_key = self.signing_key.verifying_key().to_bytes();
        self.core
            .validate(
                ObjectType::GRANT_ENVELOPE_V1,
                &raw,
                Some(&verifying_key),
            )
            .map_err(GrantIssueError::Core)?;
        Ok(IssuedGrant { raw })
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    pub(crate) struct TestGrantCore;

    impl GrantCoreModule for TestGrantCore {
        fn prepare(&self, request: &[u8]) -> Result<PreparedObject, String> {
            let mut transcript = b"candy-test-grant-transcript-v1".to_vec();
            transcript.extend_from_slice(request);
            Ok(PreparedObject {
                object_type: ObjectType::GRANT_PAYLOAD_V1,
                payload: request.to_vec(),
                signing_transcript: transcript,
            })
        }

        fn assemble(
            &self,
            object_type: ObjectType,
            _signing_key_id: &[u8],
            payload: &[u8],
            signature: &[u8; 64],
        ) -> Result<Vec<u8>, String> {
            if object_type != ObjectType::GRANT_PAYLOAD_V1 {
                return Err("unexpected object type".into());
            }
            let mut raw = Vec::with_capacity(4 + payload.len() + signature.len());
            raw.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            raw.extend_from_slice(payload);
            raw.extend_from_slice(signature);
            Ok(raw)
        }

        fn validate(
            &self,
            object_type: ObjectType,
            input: &[u8],
            verifying_key: Option<&[u8; 32]>,
        ) -> Result<(), String> {
            if object_type != ObjectType::GRANT_ENVELOPE_V1 || input.len() < 68 {
                return Err("invalid test envelope".into());
            }
            let payload_len = u32::from_be_bytes(
                input[..4]
                    .try_into()
                    .map_err(|_| "invalid test payload length")?,
            ) as usize;
            if input.len() != 4 + payload_len + 64 {
                return Err("invalid test envelope length".into());
            }
            let payload = &input[4..4 + payload_len];
            let mut transcript = b"candy-test-grant-transcript-v1".to_vec();
            transcript.extend_from_slice(payload);
            let key = VerifyingKey::from_bytes(
                verifying_key.ok_or("missing test verifying key")?,
            )
            .map_err(|error| error.to_string())?;
            let signature = Signature::from_slice(&input[4 + payload_len..])
                .map_err(|error| error.to_string())?;
            key.verify(&transcript, &signature)
                .map_err(|error| error.to_string())
        }
    }

    pub(crate) fn signer(key_id: &str, seed: [u8; 32]) -> GrantSigner {
        GrantSigner::with_core(
            key_id,
            SigningKey::from_bytes(&seed),
            Arc::new(TestGrantCore),
        )
    }

    pub(crate) fn request_from_issued(issued: &IssuedGrant) -> serde_json::Value {
        let payload_len = u32::from_be_bytes(issued.raw[..4].try_into().unwrap()) as usize;
        serde_json::from_slice(&issued.raw[4..4 + payload_len]).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{request_from_issued, signer};

    #[test]
    fn signer_executes_prepare_sign_assemble_and_validate() {
        let signer = signer("k1", [7; 32]);
        let issued = signer
            .issue_private(&serde_json::json!({"object_type":"grant_payload_v1"}))
            .unwrap();
        assert_eq!(
            request_from_issued(&issued)["schema"],
            "candy-core-cloud-build-v1"
        );
        assert_ne!(issued.digest(), [0; 32]);
    }
}
