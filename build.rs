#[rustfmt::skip]

use cbindgen::{Config, EnumConfig, ExportConfig, ItemType, Language, RenameRule};

const DPLANE_PROTO_FILE: &str = "src/proto.rs";
const DPLANE_PROTO_C_HEADER: &str = "include/dplane-rpc.h";

fn regenerate_check() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", DPLANE_PROTO_FILE);
}

fn gen_proto_c_header() {
    /* enum config */
    let enumeration = EnumConfig {
        derive_const_casts: false,
        prefix_with_name: false,
        rename_variant_name_fields: RenameRule::QualifiedScreamingSnakeCase,
        add_sentinel: false,
        ..Default::default()
    };

    /* Export */
    let mut export = ExportConfig::default();
    export.item_types.push(ItemType::Constants);
    export.item_types.push(ItemType::Enums);
    export.item_types.push(ItemType::Typedefs);

    /* Exported types */
    export.include.push("MsgType".to_owned());
    export.include.push("RpcResultCode".to_owned());
    export.include.push("IpVer".to_owned());
    export.include.push("RpcOp".to_owned());
    export.include.push("ObjType".to_owned());
    export.include.push("EncapType".to_owned());
    export.include.push("RouteType".to_owned());

    /* vanilla types */
    export.include.push("MsgSeqn".to_owned());
    export.include.push("MsgLen".to_owned());
    export.include.push("MsgNumObjects".to_owned());
    export.include.push("RouteDistance".to_owned());
    export.include.push("RouteMetric".to_owned());
    export.include.push("RouteTableId".to_owned());
    export.include.push("NumNhops".to_owned());
    export.include.push("Ifindex".to_owned());
    export.include.push("MaskLen".to_owned());
    export.include.push("Vni".to_owned());
    export.include.push("VrfId".to_owned());
    export.include.push("MatchType".to_owned());

    /* Main config */
    let config = Config {
        header: Some("/* --- Do NOT edit this file -- */".to_owned()),
        documentation: true,
        include_guard: Some("DPLANE_WIRE".to_owned()),
        include_version: true,
        language: Language::C,
        package_version: true,
        export,
        enumeration,
        ..Default::default()
    };

    /* Builder */
    let _builder = cbindgen::Builder::new()
        .with_config(config)
        .with_std_types(true)
        .with_src(DPLANE_PROTO_FILE)
        .generate()
        .expect("Failed to generate C header for dplane proto")
        .write_to_file(DPLANE_PROTO_C_HEADER);
}

fn main() {
    regenerate_check();
    gen_proto_c_header();
}
