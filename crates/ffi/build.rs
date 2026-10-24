fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir");
    let config = cbindgen::Config::from_file("cbindgen.toml").expect("cbindgen.toml");
    let header = cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
        .expect("cbindgen");
    let mut bytes = Vec::new();
    header.write(&mut bytes);
    let path = std::path::Path::new(&crate_dir).join("include/butcherbird.h");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("include dir");
    }
    let changed = std::fs::read(&path).ok().as_deref() != Some(bytes.as_slice());
    if changed {
        std::fs::write(&path, bytes).expect("write header");
    }
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=src/lib.rs");
}
