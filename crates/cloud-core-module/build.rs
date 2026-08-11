use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=tests/fixtures/test_module.rs");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_TEST_MODULE_FIXTURE");

    if env::var_os("CARGO_FEATURE_TEST_MODULE_FIXTURE").is_none() {
        return;
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    let source = PathBuf::from("tests/fixtures/test_module.rs");
    let target = env::var("TARGET").expect("TARGET is set by Cargo");
    let rustc = env::var_os("RUSTC").expect("RUSTC is set by Cargo");
    let file_name = if target.contains("apple") {
        "libcandy_core_test.dylib"
    } else if target.contains("windows") {
        "candy_core_test.dll"
    } else {
        "libcandy_core_test.so"
    };
    let output = out_dir.join(file_name);

    let status = Command::new(rustc)
        .arg("--crate-name")
        .arg("candy_core_test")
        .arg("--crate-type")
        .arg("cdylib")
        .arg("--edition")
        .arg("2021")
        .arg("--target")
        .arg(target)
        .arg(source)
        .arg("-o")
        .arg(&output)
        .status()
        .expect("run rustc for the native Core test module");
    assert!(
        status.success(),
        "native Core test module compilation failed"
    );

    println!(
        "cargo:rustc-env=CANDY_CORE_TEST_MODULE={}",
        output.display()
    );
}
