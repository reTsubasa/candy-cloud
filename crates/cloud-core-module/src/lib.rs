//! Verified loading and bounded invocation of the Candy Core Cloud C ABI.
//!
//! Installation code verifies the signed release catalog and manifest. This
//! crate accepts the resulting pinned digest, independently verifies the file
//! and its trust path, and keeps the loaded module pinned for the process
//! lifetime.

use libloading::Library;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const CLOUD_ABI_VERSION: u32 = 1;
pub const LINUX_CORE_MODULE_FILE_NAME: &str = "libcandy_core_cloud.so";
pub const BUILD_REQUEST_SCHEMA_V1: &str = "candy-core-cloud-build-v1";
pub const DEFAULT_MAX_MODULE_BYTES: u64 = 256 * 1024 * 1024;
const STATUS_OK: i32 = 0;
const STATUS_BUFFER_TOO_SMALL: i32 = -6;
const CAPABILITY_SCHEMA: &str = "candy-core-cloud-capabilities-v1";

type AbiVersionFn = unsafe extern "C" fn() -> u32;
type CapabilitiesFn = unsafe extern "C" fn(*mut u8, usize, *mut usize) -> i32;
type CanonicalizeFn =
    unsafe extern "C" fn(u32, *const u8, usize, *mut u8, usize, *mut usize) -> i32;
type PrepareFn = unsafe extern "C" fn(
    *const u8,
    usize,
    *mut u32,
    *mut u8,
    usize,
    *mut usize,
    *mut u8,
    usize,
    *mut usize,
) -> i32;
type AssembleFn = unsafe extern "C" fn(
    u32,
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *mut u8,
    usize,
    *mut usize,
) -> i32;
type ValidateFn = unsafe extern "C" fn(u32, *const u8, usize, *const u8, usize) -> i32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectType(pub u32);

impl ObjectType {
    pub const GRANT_PAYLOAD_V1: Self = Self(1);
    pub const GRANT_ENVELOPE_V1: Self = Self(2);
    pub const ROUTE_ENVELOPE_V1: Self = Self(0x100);
    pub const SEGMENT_SNAPSHOT_V1: Self = Self(0x101);
    pub const SITE_PROJECTION_V1: Self = Self(0x102);
    pub const SHARED_HUB_ADMISSION_V1: Self = Self(0x103);
    pub const MESH_MEMBERSHIP_V1: Self = Self(0x104);
    pub const DYNAMIC_ROUTE_SNAPSHOT_V1: Self = Self(0x105);
    pub const FABRIC_ASSIGNMENT_V1: Self = Self(0x106);
}

#[derive(Clone, Debug)]
pub struct VerifiedModuleSpec {
    pub trusted_root: PathBuf,
    pub module_path: PathBuf,
    pub sha256: [u8; 32],
    pub owner_uid: u32,
    pub max_module_bytes: u64,
}

impl VerifiedModuleSpec {
    pub fn new(
        trusted_root: impl Into<PathBuf>,
        module_path: impl Into<PathBuf>,
        sha256: [u8; 32],
        owner_uid: u32,
    ) -> Self {
        Self {
            trusted_root: trusted_root.into(),
            module_path: module_path.into(),
            sha256,
            owner_uid,
            max_module_bytes: DEFAULT_MAX_MODULE_BYTES,
        }
    }

    pub fn with_max_module_bytes(mut self, max_module_bytes: u64) -> Self {
        self.max_module_bytes = max_module_bytes;
        self
    }
}

#[derive(Clone, Debug)]
pub struct ModuleRequirements {
    pub abi_version: u32,
    pub wire_protocol: Option<String>,
    pub library: Option<String>,
    pub build_request_schema: Option<String>,
    pub required_operations: BTreeSet<String>,
    pub required_objects: BTreeSet<String>,
    pub limits: CallLimits,
}

impl Default for ModuleRequirements {
    fn default() -> Self {
        Self {
            abi_version: CLOUD_ABI_VERSION,
            wire_protocol: None,
            library: Some(LINUX_CORE_MODULE_FILE_NAME.to_owned()),
            build_request_schema: Some(BUILD_REQUEST_SCHEMA_V1.to_owned()),
            required_operations: [
                "capabilities",
                "canonicalize",
                "prepare",
                "assemble",
                "validate",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            required_objects: BTreeSet::new(),
            limits: CallLimits::default(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CallLimits {
    pub max_capability_bytes: usize,
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
}

impl Default for CallLimits {
    fn default() -> Self {
        Self {
            max_capability_bytes: 64 * 1024,
            max_input_bytes: 8 * 1024 * 1024,
            max_output_bytes: 8 * 1024 * 1024,
        }
    }
}

impl CallLimits {
    fn validate(self) -> Result<Self, ModuleError> {
        if self.max_capability_bytes == 0 || self.max_input_bytes == 0 || self.max_output_bytes == 0
        {
            return Err(ModuleError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct CoreCapabilities {
    pub schema: String,
    pub abi_version: u32,
    pub module_version: String,
    pub wire_protocol: String,
    #[serde(default)]
    pub library: Option<String>,
    #[serde(default)]
    pub build_request_schema: Option<String>,
    #[serde(default)]
    pub max_build_request_bytes: Option<usize>,
    pub operations: BTreeSet<String>,
    pub objects: BTreeSet<String>,
}

pub struct CoreModule {
    _library: Library,
    _module_file: File,
    canonical_path: PathBuf,
    capabilities: CoreCapabilities,
    limits: CallLimits,
    canonicalize_fn: CanonicalizeFn,
    prepare_fn: PrepareFn,
    assemble_fn: AssembleFn,
    validate_fn: ValidateFn,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedObject {
    pub object_type: ObjectType,
    pub payload: Vec<u8>,
    pub signing_transcript: Vec<u8>,
}

impl fmt::Debug for CoreModule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoreModule")
            .field("canonical_path", &self.canonical_path)
            .field("capabilities", &self.capabilities)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl CoreModule {
    /// Loads an already selected module after rechecking its digest, ownership,
    /// permissions, ABI and declared capabilities.
    pub fn load(
        spec: &VerifiedModuleSpec,
        requirements: &ModuleRequirements,
    ) -> Result<Self, ModuleError> {
        let limits = requirements.limits.validate()?;
        let opened = open_verified_module(spec)?;
        let load_path = load_path(&opened.file, &opened.canonical_path);
        // SAFETY: the path names the file pinned and verified above. Symbols are
        // copied only after their exact C signatures have been checked by name.
        let library = unsafe { Library::new(&load_path) }
            .map_err(|error| ModuleError::Load(error.to_string()))?;
        ensure_same_file(&opened.file, &opened.canonical_path)?;

        // SAFETY: the signed module ABI defines these stable symbol signatures.
        let abi_version_fn =
            unsafe { load_symbol::<AbiVersionFn>(&library, b"candy_core_cloud_abi_version\0")? };
        let capabilities_fn =
            unsafe { load_symbol::<CapabilitiesFn>(&library, b"candy_core_cloud_capabilities\0")? };
        let canonicalize_fn =
            unsafe { load_symbol::<CanonicalizeFn>(&library, b"candy_core_cloud_canonicalize\0")? };
        let prepare_fn =
            unsafe { load_symbol::<PrepareFn>(&library, b"candy_core_cloud_prepare\0")? };
        let assemble_fn =
            unsafe { load_symbol::<AssembleFn>(&library, b"candy_core_cloud_assemble\0")? };
        let validate_fn =
            unsafe { load_symbol::<ValidateFn>(&library, b"candy_core_cloud_validate\0")? };

        // SAFETY: the function has no arguments and returns the negotiated ABI.
        let actual_abi = unsafe { abi_version_fn() };
        if actual_abi != requirements.abi_version {
            return Err(ModuleError::AbiMismatch {
                expected: requirements.abi_version,
                actual: actual_abi,
            });
        }

        let capabilities = read_capabilities(capabilities_fn, limits.max_capability_bytes)?;
        negotiate(&capabilities, requirements, actual_abi)?;

        Ok(Self {
            _library: library,
            _module_file: opened.file,
            canonical_path: opened.canonical_path,
            capabilities,
            limits,
            canonicalize_fn,
            prepare_fn,
            assemble_fn,
            validate_fn,
        })
    }

    pub fn capabilities(&self) -> &CoreCapabilities {
        &self.capabilities
    }

    pub fn canonical_path(&self) -> &Path {
        &self.canonical_path
    }

    pub fn canonicalize(
        &self,
        object_type: ObjectType,
        input: &[u8],
    ) -> Result<Vec<u8>, ModuleError> {
        ensure_input("canonicalize", input, self.limits.max_input_bytes)?;
        let mut required = 0usize;
        // SAFETY: input is valid for its declared length and output_len is valid.
        let status = unsafe {
            (self.canonicalize_fn)(
                object_type.0,
                input.as_ptr(),
                input.len(),
                std::ptr::null_mut(),
                0,
                &mut required,
            )
        };
        require_size_query(
            "canonicalize",
            status,
            required,
            self.limits.max_output_bytes,
        )?;

        let mut output = vec![0u8; required];
        let mut written = output.len();
        // SAFETY: all slices and the output length pointer remain live for the call.
        let status = unsafe {
            (self.canonicalize_fn)(
                object_type.0,
                input.as_ptr(),
                input.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut written,
            )
        };
        require_ok("canonicalize", status)?;
        if written > output.len() {
            return Err(ModuleError::InvalidOutputLength {
                operation: "canonicalize",
                declared: written,
                capacity: output.len(),
            });
        }
        output.truncate(written);
        Ok(output)
    }

    /// Constructs a canonical protocol payload and the exact bytes Cloud must
    /// sign. The signing key remains entirely outside the Core module.
    pub fn prepare(&self, request: &[u8]) -> Result<PreparedObject, ModuleError> {
        let module_limit = self
            .capabilities
            .max_build_request_bytes
            .unwrap_or(self.limits.max_input_bytes);
        ensure_input(
            "prepare",
            request,
            self.limits.max_input_bytes.min(module_limit),
        )?;
        let mut object_type = 0u32;
        let mut payload_len = 0usize;
        let mut transcript_len = 0usize;
        // SAFETY: all length and object pointers are valid; null output buffers
        // request their sizes as defined by ABI v1.
        let status = unsafe {
            (self.prepare_fn)(
                request.as_ptr(),
                request.len(),
                &mut object_type,
                std::ptr::null_mut(),
                0,
                &mut payload_len,
                std::ptr::null_mut(),
                0,
                &mut transcript_len,
            )
        };
        require_two_size_query(
            "prepare",
            status,
            payload_len,
            transcript_len,
            self.limits.max_output_bytes,
        )?;

        let mut payload = vec![0u8; payload_len];
        let mut transcript = vec![0u8; transcript_len];
        let mut written_payload = payload.len();
        let mut written_transcript = transcript.len();
        let mut written_object_type = 0u32;
        // SAFETY: inputs and both independent output buffers remain live for
        // the duration of the call and have their exact declared capacities.
        let status = unsafe {
            (self.prepare_fn)(
                request.as_ptr(),
                request.len(),
                &mut written_object_type,
                payload.as_mut_ptr(),
                payload.len(),
                &mut written_payload,
                transcript.as_mut_ptr(),
                transcript.len(),
                &mut written_transcript,
            )
        };
        require_ok("prepare", status)?;
        validate_written_len("prepare payload", written_payload, payload.len())?;
        validate_written_len("prepare transcript", written_transcript, transcript.len())?;
        if written_object_type != object_type {
            return Err(ModuleError::InconsistentObjectType {
                queried: object_type,
                written: written_object_type,
            });
        }
        payload.truncate(written_payload);
        transcript.truncate(written_transcript);
        Ok(PreparedObject {
            object_type: ObjectType(object_type),
            payload,
            signing_transcript: transcript,
        })
    }

    /// Assembles the externally generated Ed25519 signature with the exact
    /// payload returned by [`Self::prepare`].
    pub fn assemble(
        &self,
        object_type: ObjectType,
        signing_key_id: &[u8],
        payload: &[u8],
        signature: &[u8; 64],
    ) -> Result<Vec<u8>, ModuleError> {
        ensure_input("assemble signing key id", signing_key_id, 64)?;
        ensure_input("assemble payload", payload, self.limits.max_input_bytes)?;
        let mut required = 0usize;
        // SAFETY: all input slices and output_len are valid for the call.
        let status = unsafe {
            (self.assemble_fn)(
                object_type.0,
                signing_key_id.as_ptr(),
                signing_key_id.len(),
                payload.as_ptr(),
                payload.len(),
                signature.as_ptr(),
                signature.len(),
                std::ptr::null_mut(),
                0,
                &mut required,
            )
        };
        require_size_query("assemble", status, required, self.limits.max_output_bytes)?;

        let mut output = vec![0u8; required];
        let mut written = output.len();
        // SAFETY: the caller-owned output and all input slices remain valid.
        let status = unsafe {
            (self.assemble_fn)(
                object_type.0,
                signing_key_id.as_ptr(),
                signing_key_id.len(),
                payload.as_ptr(),
                payload.len(),
                signature.as_ptr(),
                signature.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut written,
            )
        };
        require_ok("assemble", status)?;
        validate_written_len("assemble", written, output.len())?;
        output.truncate(written);
        Ok(output)
    }

    pub fn validate(
        &self,
        object_type: ObjectType,
        input: &[u8],
        verifying_key: Option<&[u8; 32]>,
    ) -> Result<(), ModuleError> {
        ensure_input("validate", input, self.limits.max_input_bytes)?;
        let (key_ptr, key_len) = verifying_key
            .map(|key| (key.as_ptr(), key.len()))
            .unwrap_or((std::ptr::null(), 0));
        // SAFETY: all input pointers are valid for their declared lengths.
        let status = unsafe {
            (self.validate_fn)(object_type.0, input.as_ptr(), input.len(), key_ptr, key_len)
        };
        require_ok("validate", status)
    }
}

#[derive(Debug, Error)]
pub enum ModuleError {
    #[error("Core module trust root and module path must be absolute")]
    RelativePath,
    #[error("Core module path resolution failed: {0}")]
    PathResolution(#[source] std::io::Error),
    #[error("Core module resolves outside its trusted root")]
    OutsideTrustedRoot,
    #[error("untrusted Core path component {path}: {reason}")]
    UntrustedPath { path: PathBuf, reason: &'static str },
    #[error("Core module is not a regular file")]
    NotRegularFile,
    #[error("Core module file size must be between 1 and {limit} bytes")]
    ModuleFileSize { limit: u64 },
    #[error("Core module file could not be opened or read: {0}")]
    Io(#[source] std::io::Error),
    #[error("Core module digest does not match its verified manifest")]
    DigestMismatch,
    #[error("Core module file changed while it was being loaded")]
    FileChanged,
    #[error("Core module could not be loaded: {0}")]
    Load(String),
    #[error("Core module is missing required ABI symbol {0}")]
    MissingSymbol(&'static str),
    #[error("Core ABI mismatch: expected {expected}, got {actual}")]
    AbiMismatch { expected: u32, actual: u32 },
    #[error("Core capability document is malformed: {0}")]
    MalformedCapabilities(String),
    #[error("Core capability schema is unsupported: {0}")]
    UnsupportedCapabilitySchema(String),
    #[error("Core capabilities declare ABI {declared}, but the module exports ABI {exported}")]
    CapabilityAbiMismatch { declared: u32, exported: u32 },
    #[error("Core wire protocol mismatch: expected {expected}, got {actual}")]
    WireProtocolMismatch { expected: String, actual: String },
    #[error("Core library identity mismatch: expected {expected}, got {actual:?}")]
    LibraryMismatch {
        expected: String,
        actual: Option<String>,
    },
    #[error("Core build request schema mismatch: expected {expected}, got {actual:?}")]
    BuildRequestSchemaMismatch {
        expected: String,
        actual: Option<String>,
    },
    #[error("Core module lacks required {kind} capability {name}")]
    MissingCapability { kind: &'static str, name: String },
    #[error("Core call limits must be greater than zero")]
    InvalidLimits,
    #[error("Core {operation} input is empty")]
    EmptyInput { operation: &'static str },
    #[error("Core {operation} input exceeds the configured {limit}-byte limit")]
    InputTooLarge {
        operation: &'static str,
        limit: usize,
    },
    #[error("Core {operation} output exceeds the configured {limit}-byte limit")]
    OutputTooLarge {
        operation: &'static str,
        limit: usize,
    },
    #[error("Core {operation} returned invalid output length {declared} for capacity {capacity}")]
    InvalidOutputLength {
        operation: &'static str,
        declared: usize,
        capacity: usize,
    },
    #[error(
        "Core prepare changed object type between size query ({queried}) and write ({written})"
    )]
    InconsistentObjectType { queried: u32, written: u32 },
    #[error("Core {operation} failed with ABI status {status}")]
    CallFailed {
        operation: &'static str,
        status: i32,
    },
}

struct OpenedModule {
    file: File,
    canonical_path: PathBuf,
}

fn open_verified_module(spec: &VerifiedModuleSpec) -> Result<OpenedModule, ModuleError> {
    if !spec.trusted_root.is_absolute() || !spec.module_path.is_absolute() {
        return Err(ModuleError::RelativePath);
    }
    let root = fs::canonicalize(&spec.trusted_root).map_err(ModuleError::PathResolution)?;
    let module = fs::canonicalize(&spec.module_path).map_err(ModuleError::PathResolution)?;
    let relative = module
        .strip_prefix(&root)
        .map_err(|_| ModuleError::OutsideTrustedRoot)?;
    verify_path_component(&root, spec.owner_uid, true)?;
    let mut component = root.clone();
    for part in relative.components() {
        component.push(part);
        verify_path_component(&component, spec.owner_uid, component != module)?;
    }

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&module)
        .map_err(ModuleError::Io)?;
    let metadata = file.metadata().map_err(ModuleError::Io)?;
    if !metadata.is_file() {
        return Err(ModuleError::NotRegularFile);
    }
    if spec.max_module_bytes == 0 || metadata.len() == 0 || metadata.len() > spec.max_module_bytes {
        return Err(ModuleError::ModuleFileSize {
            limit: spec.max_module_bytes,
        });
    }
    verify_metadata(&module, &metadata, spec.owner_uid, false)?;

    let digest = hash_file(&file, spec.max_module_bytes)?;
    if digest != spec.sha256 {
        return Err(ModuleError::DigestMismatch);
    }
    Ok(OpenedModule {
        file,
        canonical_path: module,
    })
}

fn verify_path_component(
    path: &Path,
    owner_uid: u32,
    must_be_directory: bool,
) -> Result<(), ModuleError> {
    let metadata = fs::symlink_metadata(path).map_err(ModuleError::PathResolution)?;
    if metadata.file_type().is_symlink() {
        return Err(ModuleError::UntrustedPath {
            path: path.to_path_buf(),
            reason: "resolved path still contains a symlink",
        });
    }
    if must_be_directory && !metadata.is_dir() {
        return Err(ModuleError::UntrustedPath {
            path: path.to_path_buf(),
            reason: "expected a directory",
        });
    }
    verify_metadata(path, &metadata, owner_uid, must_be_directory)
}

fn verify_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    owner_uid: u32,
    _directory: bool,
) -> Result<(), ModuleError> {
    if metadata.uid() != owner_uid {
        return Err(ModuleError::UntrustedPath {
            path: path.to_path_buf(),
            reason: "unexpected owner",
        });
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(ModuleError::UntrustedPath {
            path: path.to_path_buf(),
            reason: "group-writable or world-writable",
        });
    }
    Ok(())
}

fn hash_file(file: &File, max_bytes: u64) -> Result<[u8; 32], ModuleError> {
    let mut file = file.try_clone().map_err(ModuleError::Io)?;
    file.seek(SeekFrom::Start(0)).map_err(ModuleError::Io)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = file.read(&mut buffer).map_err(ModuleError::Io)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > max_bytes {
            return Err(ModuleError::ModuleFileSize { limit: max_bytes });
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

#[cfg(target_os = "linux")]
fn load_path(file: &File, _canonical_path: &Path) -> PathBuf {
    use std::os::fd::AsRawFd;
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn load_path(file: &File, _canonical_path: &Path) -> PathBuf {
    use std::os::fd::AsRawFd;
    PathBuf::from(format!("/dev/fd/{}", file.as_raw_fd()))
}

fn ensure_same_file(file: &File, canonical_path: &Path) -> Result<(), ModuleError> {
    let pinned = file.metadata().map_err(ModuleError::Io)?;
    let current = fs::metadata(canonical_path).map_err(ModuleError::Io)?;
    if pinned.dev() != current.dev() || pinned.ino() != current.ino() {
        return Err(ModuleError::FileChanged);
    }
    Ok(())
}

unsafe fn load_symbol<T: Copy>(library: &Library, name: &'static [u8]) -> Result<T, ModuleError> {
    library.get::<T>(name).map(|symbol| *symbol).map_err(|_| {
        let display = std::str::from_utf8(&name[..name.len() - 1]).unwrap_or("unknown");
        ModuleError::MissingSymbol(display)
    })
}

fn read_capabilities(
    function: CapabilitiesFn,
    max_bytes: usize,
) -> Result<CoreCapabilities, ModuleError> {
    let mut required = 0usize;
    // SAFETY: output_len is valid and the ABI permits a null size-query buffer.
    let status = unsafe { function(std::ptr::null_mut(), 0, &mut required) };
    require_size_query("capabilities", status, required, max_bytes)?;
    let mut bytes = vec![0u8; required];
    let mut written = bytes.len();
    // SAFETY: the output buffer and length pointer are live for the call.
    let status = unsafe { function(bytes.as_mut_ptr(), bytes.len(), &mut written) };
    require_ok("capabilities", status)?;
    if written > bytes.len() {
        return Err(ModuleError::InvalidOutputLength {
            operation: "capabilities",
            declared: written,
            capacity: bytes.len(),
        });
    }
    bytes.truncate(written);
    serde_json::from_slice(&bytes)
        .map_err(|error| ModuleError::MalformedCapabilities(error.to_string()))
}

fn negotiate(
    capabilities: &CoreCapabilities,
    requirements: &ModuleRequirements,
    exported_abi: u32,
) -> Result<(), ModuleError> {
    if capabilities.schema != CAPABILITY_SCHEMA {
        return Err(ModuleError::UnsupportedCapabilitySchema(
            capabilities.schema.clone(),
        ));
    }
    if capabilities.abi_version != exported_abi {
        return Err(ModuleError::CapabilityAbiMismatch {
            declared: capabilities.abi_version,
            exported: exported_abi,
        });
    }
    if let Some(expected) = &requirements.wire_protocol {
        if capabilities.wire_protocol != *expected {
            return Err(ModuleError::WireProtocolMismatch {
                expected: expected.clone(),
                actual: capabilities.wire_protocol.clone(),
            });
        }
    }
    if let Some(expected) = &requirements.library {
        if capabilities.library.as_ref() != Some(expected) {
            return Err(ModuleError::LibraryMismatch {
                expected: expected.clone(),
                actual: capabilities.library.clone(),
            });
        }
    }
    if let Some(expected) = &requirements.build_request_schema {
        if capabilities.build_request_schema.as_ref() != Some(expected) {
            return Err(ModuleError::BuildRequestSchemaMismatch {
                expected: expected.clone(),
                actual: capabilities.build_request_schema.clone(),
            });
        }
    }
    if capabilities.max_build_request_bytes == Some(0) {
        return Err(ModuleError::MalformedCapabilities(
            "max_build_request_bytes must be greater than zero".to_owned(),
        ));
    }
    require_capabilities(
        "operation",
        &requirements.required_operations,
        &capabilities.operations,
    )?;
    require_capabilities(
        "object",
        &requirements.required_objects,
        &capabilities.objects,
    )
}

fn require_capabilities(
    kind: &'static str,
    required: &BTreeSet<String>,
    available: &BTreeSet<String>,
) -> Result<(), ModuleError> {
    if let Some(name) = required.difference(available).next() {
        return Err(ModuleError::MissingCapability {
            kind,
            name: name.clone(),
        });
    }
    Ok(())
}

fn ensure_input(operation: &'static str, input: &[u8], limit: usize) -> Result<(), ModuleError> {
    if input.is_empty() {
        return Err(ModuleError::EmptyInput { operation });
    }
    if input.len() > limit {
        return Err(ModuleError::InputTooLarge { operation, limit });
    }
    Ok(())
}

fn require_two_size_query(
    operation: &'static str,
    status: i32,
    first: usize,
    second: usize,
    limit: usize,
) -> Result<(), ModuleError> {
    if status != STATUS_BUFFER_TOO_SMALL {
        return Err(ModuleError::CallFailed { operation, status });
    }
    if first == 0 || second == 0 || first > limit || second > limit {
        return Err(ModuleError::OutputTooLarge { operation, limit });
    }
    Ok(())
}

fn validate_written_len(
    operation: &'static str,
    declared: usize,
    capacity: usize,
) -> Result<(), ModuleError> {
    if declared > capacity {
        Err(ModuleError::InvalidOutputLength {
            operation,
            declared,
            capacity,
        })
    } else {
        Ok(())
    }
}

fn require_size_query(
    operation: &'static str,
    status: i32,
    required: usize,
    limit: usize,
) -> Result<(), ModuleError> {
    if status != STATUS_BUFFER_TOO_SMALL {
        return Err(ModuleError::CallFailed { operation, status });
    }
    if required == 0 || required > limit {
        return Err(ModuleError::OutputTooLarge { operation, limit });
    }
    Ok(())
}

fn require_ok(operation: &'static str, status: i32) -> Result<(), ModuleError> {
    if status == STATUS_OK {
        Ok(())
    } else {
        Err(ModuleError::CallFailed { operation, status })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_limits() {
        let limits = CallLimits {
            max_input_bytes: 0,
            ..CallLimits::default()
        };
        assert!(matches!(limits.validate(), Err(ModuleError::InvalidLimits)));
    }

    #[test]
    fn rejects_oversized_size_query_before_allocation() {
        assert!(matches!(
            require_size_query("test", STATUS_BUFFER_TOO_SMALL, 1025, 1024),
            Err(ModuleError::OutputTooLarge { .. })
        ));
    }
}
