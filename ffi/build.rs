use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let project_root = manifest_dir.parent().unwrap();

    // Determine optimization level from Cargo profile
    let optimize = if env::var("PROFILE").unwrap() == "release" {
        "-Doptimize=ReleaseFast"
    } else {
        "-Doptimize=Debug"
    };

    // Build the Zig static library
    let status = Command::new("zig")
        .arg("build")
        .arg(optimize)
        .current_dir(project_root)
        .status()
        .expect("failed to run zig build — is zig installed?");

    if !status.success() {
        panic!("zig build failed with status: {}", status);
    }

    // Tell Cargo where to find the library
    let lib_dir = project_root.join("zig-out").join("lib");
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=constellazig");

    // Rerun if Zig sources change
    println!("cargo:rerun-if-changed=../src/");
    println!("cargo:rerun-if-changed=../build.zig");
    println!("cargo:rerun-if-changed=../build.zig.zon");
}
