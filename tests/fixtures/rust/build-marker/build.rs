// Test fixture: records that cargo ran this build script, by writing a marker
// beside the manifest (the test's scratch copy). It writes nothing else.
fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    std::fs::write(std::path::Path::new(&dir).join("build-script-ran"), "build.rs executed\n")
        .expect("write the marker");
    println!("cargo:rerun-if-changed=build.rs");
}
