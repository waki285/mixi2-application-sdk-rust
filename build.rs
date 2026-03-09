use std::{env, error::Error, path::PathBuf};

const PROTO_ROOT: &str = "proto/vendor";
const PROTO_FILES: &[&str] = &[
    "social/mixi/application/const/v1/event_type.proto",
    "social/mixi/application/const/v1/language_code.proto",
    "social/mixi/application/const/v1/media_type.proto",
    "social/mixi/application/const/v1/post_access_level.proto",
    "social/mixi/application/const/v1/post_mask_type.proto",
    "social/mixi/application/const/v1/post_media_type.proto",
    "social/mixi/application/const/v1/post_publishing_type.proto",
    "social/mixi/application/const/v1/post_visibility.proto",
    "social/mixi/application/const/v1/stamp_set_type.proto",
    "social/mixi/application/const/v1/user_access_level.proto",
    "social/mixi/application/const/v1/user_visibility.proto",
    "social/mixi/application/model/v1/event.proto",
    "social/mixi/application/model/v1/media.proto",
    "social/mixi/application/model/v1/message.proto",
    "social/mixi/application/model/v1/post.proto",
    "social/mixi/application/model/v1/stamp.proto",
    "social/mixi/application/model/v1/user.proto",
    "social/mixi/application/service/application_api/v1/service.proto",
    "social/mixi/application/service/application_stream/v1/service.proto",
    "social/mixi/application/service/client_endpoint/v1/service.proto",
];

fn main() -> Result<(), Box<dyn Error>> {
    for proto_file in PROTO_FILES {
        println!("cargo:rerun-if-changed={PROTO_ROOT}/{proto_file}");
    }

    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let descriptor_path = out_dir.join("mixi2_application_descriptor.bin");

    // build.rs needs to point prost at the vendored protoc binary explicitly.
    // SAFETY: this build script only updates its own process environment before code generation.
    unsafe {
        env::set_var("PROTOC", protoc);
    }

    let proto_paths = PROTO_FILES
        .iter()
        .map(|proto_file| PathBuf::from(PROTO_ROOT).join(proto_file))
        .collect::<Vec<_>>();

    tonic_prost_build::configure()
        .file_descriptor_set_path(descriptor_path)
        .extern_path(".google.protobuf.Timestamp", "::prost_types::Timestamp")
        .compile_protos(&proto_paths, &[PathBuf::from(PROTO_ROOT)])?;

    Ok(())
}
