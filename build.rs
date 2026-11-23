use std::env;

fn main() {
    // The version Portcullis reports: Cargo.toml's, with a suffix for builds of main
    // (e.g. -dev+abc1234), so a bug report tells which build it was.
    println!("cargo:rerun-if-env-changed=PORTCULLIS_VERSION_SUFFIX");
    println!(
        "cargo:rustc-env=PORTCULLIS_VERSION={}{}",
        env::var("CARGO_PKG_VERSION").unwrap_or_default(),
        env::var("PORTCULLIS_VERSION_SUFFIX").unwrap_or_default()
    );
}
