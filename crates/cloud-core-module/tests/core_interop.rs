use cloud_core_module::{CoreModule, ModuleRequirements, VerifiedModuleSpec};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

#[test]
#[ignore = "requires CANDY_CORE_INTEROP_MODULE pointing to a released Core module"]
fn loads_the_real_core_cloud_module() {
    let module = PathBuf::from(
        std::env::var_os("CANDY_CORE_INTEROP_MODULE")
            .expect("CANDY_CORE_INTEROP_MODULE must point to the released shared module"),
    );
    let root = module.parent().expect("Core module has a parent");
    let bytes = fs::read(&module).expect("read Core module");
    let digest = Sha256::digest(bytes).into();
    let owner_uid = fs::metadata(root).expect("read Core module root").uid();
    let spec = VerifiedModuleSpec::new(root, &module, digest, owner_uid);

    let loaded = CoreModule::load(&spec, &ModuleRequirements::default())
        .expect("load and negotiate real Core module");
    assert_eq!(loaded.capabilities().abi_version, 1);
    assert_eq!(
        loaded.capabilities().library.as_deref(),
        Some("libcandy_core_cloud.so")
    );
    assert!(loaded.capabilities().operations.contains("prepare"));
    assert!(loaded.capabilities().operations.contains("assemble"));
}
