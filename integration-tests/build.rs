use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    tonic_build::configure()
        .build_server(true)
        .out_dir(out_dir.clone())
        .file_descriptor_set_path(out_dir.clone().join("whoami.bin"))
        .compile_protos(&["proto/whoami.proto"], &["proto"])?;
    Ok(())
}
