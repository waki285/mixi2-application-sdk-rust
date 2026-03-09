//! Generated protobuf and gRPC types for the mixi2 application API.

pub const FILE_DESCRIPTOR_SET: &[u8] =
    tonic::include_file_descriptor_set!("mixi2_application_descriptor");

#[expect(clippy::pedantic, reason = "generated protobuf code")]
#[expect(clippy::nursery, reason = "generated protobuf code")]
#[expect(
    clippy::allow_attributes,
    reason = "generated protobuf code uses allow attributes"
)]
#[expect(
    clippy::absolute_paths,
    reason = "generated protobuf code uses absolute paths"
)]
#[expect(
    clippy::clone_on_ref_ptr,
    reason = "generated protobuf code clones Arc values"
)]
#[expect(
    clippy::empty_structs_with_brackets,
    reason = "generated protobuf code uses prost-style empty structs"
)]
#[expect(
    clippy::same_name_method,
    reason = "generated gRPC stubs mirror proto RPC names"
)]
pub mod social {
    pub mod mixi {
        pub mod application {
            pub mod r#const {
                pub mod v1 {
                    tonic::include_proto!("social.mixi.application.r#const.v1");
                }
            }

            pub mod model {
                pub mod v1 {
                    tonic::include_proto!("social.mixi.application.model.v1");
                }
            }

            pub mod service {
                pub mod application_api {
                    pub mod v1 {
                        tonic::include_proto!("social.mixi.application.service.application_api.v1");
                    }
                }

                pub mod application_stream {
                    pub mod v1 {
                        tonic::include_proto!(
                            "social.mixi.application.service.application_stream.v1"
                        );
                    }
                }

                pub mod client_endpoint {
                    pub mod v1 {
                        tonic::include_proto!("social.mixi.application.service.client_endpoint.v1");
                    }
                }
            }
        }
    }
}
