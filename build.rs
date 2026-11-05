use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=ffi/libnftables_wrapper.h");
    println!("cargo:rustc-link-lib=nftables");

    // The version Portcullis reports: Cargo.toml's, with a suffix for builds of main
    // (e.g. -dev+abc1234), so a bug report tells which build it was.
    println!("cargo:rerun-if-env-changed=PORTCULLIS_VERSION_SUFFIX");
    println!(
        "cargo:rustc-env=PORTCULLIS_VERSION={}{}",
        env::var("CARGO_PKG_VERSION").unwrap_or_default(),
        env::var("PORTCULLIS_VERSION_SUFFIX").unwrap_or_default()
    );

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap_or_default());

    let bindings = bindgen::Builder::default()
        .header("ffi/libnftables_wrapper.h")
        .allowlist_type("nft_ctx")
        .allowlist_function("nft_ctx_new")
        .allowlist_function("nft_ctx_free")
        .allowlist_function("nft_ctx_buffer_output")
        .allowlist_function("nft_ctx_buffer_error")
        .allowlist_function("nft_ctx_get_error_buffer")
        .allowlist_function("nft_ctx_get_output_buffer")
        .allowlist_function("nft_ctx_output_get_flags")
        .allowlist_function("nft_ctx_output_set_flags")
        .allowlist_item("NFT_CTX_OUTPUT_TERSE")
        .allowlist_function("nft_run_cmd_from_buffer")
        .allowlist_var("NFT_CTX_DEFAULT")
        .layout_tests(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .unwrap_or_else(|error| panic!("failed to generate libnftables bindings: {error}"));

    bindings
        .write_to_file(out_dir.join("libnftables_bindings.rs"))
        .unwrap_or_else(|error| panic!("failed to write libnftables bindings: {error}"));
}
