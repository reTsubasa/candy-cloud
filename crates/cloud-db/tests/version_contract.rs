use std::{fs, path::PathBuf};

#[test]
fn cloud_and_core_version_contract_is_pinned() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest: toml::Value = fs::read_to_string(workspace.join("Cargo.toml"))
        .unwrap()
        .parse()
        .unwrap();
    let package = &manifest["workspace"]["package"];
    let candy = &manifest["workspace"]["metadata"]["candy"];
    assert_eq!(package["version"].as_str(), Some("0.1.0"));
    assert_eq!(candy["core_version"].as_str(), Some("0.3.10"));
    assert_eq!(
        candy["core_revision"].as_str(),
        Some("a2ace9cb524dc5fcc2e01481ba9d515588a61936")
    );
    assert_eq!(candy["wire_line"].as_str(), Some("0.3"));
    assert_eq!(candy["auth_profile"].as_str(), Some("cloud_grant_v1"));
}
