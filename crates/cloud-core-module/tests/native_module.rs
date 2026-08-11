use cloud_core_module::{
    CallLimits, CoreModule, ModuleError, ModuleRequirements, ObjectType, VerifiedModuleSpec,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

fn module_path() -> PathBuf {
    PathBuf::from(env!("CANDY_CORE_TEST_MODULE"))
}

fn digest(path: &Path) -> [u8; 32] {
    Sha256::digest(fs::read(path).expect("read test module")).into()
}

fn spec() -> VerifiedModuleSpec {
    let module = module_path();
    let root = module.parent().expect("test module has parent");
    let owner_uid = fs::metadata(root).expect("test module root metadata").uid();
    VerifiedModuleSpec::new(root, &module, digest(&module), owner_uid)
}

#[test]
fn loads_negotiates_and_invokes_the_native_module() {
    let mut requirements = ModuleRequirements {
        wire_protocol: Some("0.3".to_owned()),
        build_request_schema: Some("candy-core-cloud-build-v1".to_owned()),
        ..ModuleRequirements::default()
    };
    requirements
        .required_objects
        .insert("grant-payload-v1".to_owned());

    let module = CoreModule::load(&spec(), &requirements).expect("load test module");
    assert_eq!(module.capabilities().module_version, "test-1");
    assert_eq!(
        module
            .canonicalize(ObjectType::GRANT_PAYLOAD_V1, b"canonical")
            .expect("canonicalize"),
        b"canonical"
    );
    module
        .validate(ObjectType::GRANT_PAYLOAD_V1, b"canonical", None)
        .expect("validate");

    let prepared = module.prepare(br#"{"object":"test"}"#).expect("prepare");
    assert_eq!(prepared.object_type, ObjectType::GRANT_PAYLOAD_V1);
    assert_eq!(prepared.payload, br#"{"object":"test"}"#);
    assert_eq!(prepared.signing_transcript, prepared.payload);
    let signature = [0x5a; 64];
    let envelope = module
        .assemble(
            prepared.object_type,
            b"test-key",
            &prepared.payload,
            &signature,
        )
        .expect("assemble");
    assert!(envelope.starts_with(b"test-key"));
    assert!(envelope.ends_with(&signature));
}

#[test]
fn fails_closed_on_digest_or_abi_mismatch() {
    let mut invalid_digest = spec();
    invalid_digest.sha256 = [0x55; 32];
    assert!(matches!(
        CoreModule::load(&invalid_digest, &ModuleRequirements::default()),
        Err(ModuleError::DigestMismatch)
    ));

    let requirements = ModuleRequirements {
        abi_version: 2,
        ..ModuleRequirements::default()
    };
    assert!(matches!(
        CoreModule::load(&spec(), &requirements),
        Err(ModuleError::AbiMismatch {
            expected: 2,
            actual: 1
        })
    ));
}

#[test]
fn rejects_missing_capabilities_and_oversized_output() {
    let mut requirements = ModuleRequirements::default();
    requirements
        .required_objects
        .insert("route-envelope-v2".to_owned());
    assert!(matches!(
        CoreModule::load(&spec(), &requirements),
        Err(ModuleError::MissingCapability { kind: "object", .. })
    ));

    let requirements = ModuleRequirements {
        limits: CallLimits {
            max_output_bytes: 4,
            ..CallLimits::default()
        },
        ..ModuleRequirements::default()
    };
    let module = CoreModule::load(&spec(), &requirements).expect("load bounded test module");
    assert!(matches!(
        module.canonicalize(ObjectType::GRANT_PAYLOAD_V1, b"12345"),
        Err(ModuleError::OutputTooLarge {
            operation: "canonicalize",
            limit: 4
        })
    ));
}

#[test]
fn rejects_relative_and_outside_root_paths() {
    let mut relative = spec();
    relative.module_path = module_path().file_name().expect("module file name").into();
    assert!(matches!(
        CoreModule::load(&relative, &ModuleRequirements::default()),
        Err(ModuleError::RelativePath)
    ));

    let mut outside = spec();
    outside.trusted_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    assert!(matches!(
        CoreModule::load(&outside, &ModuleRequirements::default()),
        Err(ModuleError::OutsideTrustedRoot)
    ));
}

#[test]
fn loaded_module_is_shareable_between_service_threads() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<CoreModule>();
}
