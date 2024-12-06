pub use crate::proto::*;
pub use mac_address::MacAddress;
pub use std::net::IpAddr;

#[doc = "The id of a VRF."]
#[repr(transparent)]
#[derive(Debug, PartialEq)]
pub struct VrfId {
    pub(crate) id: u32,
}

#[doc = "A versioning information object."]
#[derive(Debug, PartialEq)]
pub struct VerInfo {
    pub(crate) major: u8,
    pub(crate) minor: u8,
    pub(crate) patch: u8,
}

#[doc = "A (IP, MAC, Vni) tuple"]
#[derive(Debug, PartialEq)]
pub struct Rmac {
    pub(crate) address: IpAddr,
    pub(crate) mac: MacAddress,
    pub(crate) vni: Vni,
}

#[doc = "An interface IP address/mask"]
#[derive(Debug, PartialEq)]
pub struct IfAddress {
    pub(crate) address: IpAddr,
    pub(crate) mask_len: MaskLen,
    pub(crate) ifindex: Ifindex,
    pub(crate) vrfid: VrfId,
}

#[doc = "An IP route"]
#[derive(Debug, PartialEq)]
pub struct IpRoute {
    pub(crate) prefix: IpAddr,
    pub(crate) prefix_len: MaskLen,
    pub(crate) vrfid: VrfId,
    pub(crate) tableid: RouteTableId,
    pub(crate) rtype: RouteType,
    pub(crate) distance: RouteDistance,
    pub(crate) metric: RouteMetric,
    pub(crate) nhops: Vec<NextHop>,
}

#[doc = "Encapsulation data for a VxLAN encapsulation."]
#[repr(transparent)]
#[derive(Debug, PartialEq)]
pub struct VxlanEncap {
    pub(crate) vni: Vni,
}

#[doc = "Type for distinct encapsulation types"]
#[derive(Debug, PartialEq)]
pub enum NextHopEncap {
    VXLAN(VxlanEncap),
}

#[doc = "An IP route next-hop"]
#[derive(Debug, PartialEq)]
pub struct NextHop {
    pub(crate) address: Option<IpAddr>,
    pub(crate) ifindex: Option<Ifindex>,
    pub(crate) vrfid: VrfId,
    pub(crate) encap: Option<NextHopEncap>,
}

#[doc = "An object that may be exchanged between DP and CP. All first-class objects are contained here."]
#[derive(Debug, PartialEq)]
pub enum RpcObject {
    VerInfo(VerInfo),
    IfAddress(IfAddress),
    Rmac(Rmac),
    IpRoute(IpRoute),
}
impl RpcObject {
    #[doc = "Return the code (wire code) for an object"]
    pub fn wire_type(obj: &RpcObject) -> ObjType {
        match obj {
            RpcObject::IfAddress(_) => ObjType::IfAddress,
            RpcObject::Rmac(_) => ObjType::Rmac,
            RpcObject::VerInfo(_) => ObjType::VerInfo,
            RpcObject::IpRoute(_) => ObjType::IpRoute,
        }
    }
}

/* Utils */
impl Rmac {
    #[allow(dead_code)]
    pub fn new(address: IpAddr, mac: MacAddress, vni: Vni) -> Self {
        Self { address, mac, vni }
    }
}
impl IfAddress {
    #[allow(dead_code)]
    pub fn new(address: IpAddr, mask_len: MaskLen, ifindex: Ifindex, vrf_id: u32) -> Self {
        Self {
            address,
            mask_len,
            ifindex,
            vrfid: VrfId { id: vrf_id },
        }
    }
}
impl Default for VerInfo {
    fn default() -> Self {
        Self {
            major: VER_DP_MAJOR,
            minor: VER_DP_MINOR,
            patch: VER_DP_PATCH,
        }
    }
}
