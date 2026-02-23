use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=ffi/libnftables_wrapper.h");
    println!("cargo:rustc-link-lib=nftables");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap_or_default());

    let bindings = bindgen::Builder::default()
        .header("ffi/libnftables_wrapper.h")
        .allowlist_type("nft_ctx")
        .allowlist_function("nft_ctx_.*")
        .allowlist_function("nft_run_cmd_from_buffer")
        .allowlist_var("NFT_CTX_.*")
        .layout_tests(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .unwrap_or_else(|error| panic!("failed to generate libnftables bindings: {error}"));

    bindings
        .write_to_file(out_dir.join("libnftables_bindings.rs"))
        .unwrap_or_else(|error| panic!("failed to write libnftables bindings: {error}"));
}
