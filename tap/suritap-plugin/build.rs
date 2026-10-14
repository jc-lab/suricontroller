//! Compiles the C glue against a configured Suricata source tree.
//!
//! Environment:
//!   SURICATA_SRC            configured Suricata source tree (required)
//!   SURICATA_EXTRA_INCLUDE  extra include directories, ':'-separated
//!                           (e.g. for jansson or libyaml headers)

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=SURICATA_SRC");
    println!("cargo:rerun-if-env-changed=SURICATA_EXTRA_INCLUDE");
    println!("cargo:rerun-if-changed=shim/shim.c");
    let src = PathBuf::from(std::env::var("SURICATA_SRC").expect(
        "SURICATA_SRC must point to a configured Suricata source tree (the same version the plugin is loaded into)",
    ));
    let autoconf = std::fs::read_to_string(src.join("src/autoconf.h"))
        .expect("SURICATA_SRC/src/autoconf.h not found: run ./configure in the Suricata tree first");
    let version = autoconf
        .lines()
        .find_map(|l| l.strip_prefix("#define PACKAGE_VERSION \""))
        .and_then(|l| l.strip_suffix('"'))
        .expect("PACKAGE_VERSION missing from autoconf.h");
    println!("cargo:rustc-env=SURICATA_VERSION={version}");

    let mut b = cc::Build::new();
    b.file("shim/shim.c")
        .include(src.join("src"))
        .include(src.join("rust/gen"))
        .include(src.join("rust/dist"))
        .define("HAVE_CONFIG_H", None)
        .define("__SCFILENAME__", "\"suritap\"")
        .flag_if_supported("-std=c11")
        .warnings(false);
    if let Ok(extra) = std::env::var("SURICATA_EXTRA_INCLUDE") {
        for d in extra.split(':').filter(|d| !d.is_empty()) {
            b.include(d);
        }
    }
    b.compile("suritap_shim");
}
