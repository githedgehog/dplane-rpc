// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

pub use crate::proto::*;
use crate::wire::WireError;
pub use mac_address::MacAddress;
use std::fmt::Display;
pub use std::net::IpAddr;

#[doc = "A versioning information object."]
#[derive(Debug, PartialEq)]
pub struct VerInfo {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
}

#[doc = "A connection information object identifying the requestor."]
#[derive(Debug, PartialEq)]
pub struct ConnectInfo {
    pub pid: u32,
    pub name: String,
    pub verinfo: VerInfo,
}

#[doc = "A (IP, MAC, Vni) tuple"]
#[derive(Debug, PartialEq)]
pub struct Rmac {
    pub address: IpAddr,
    pub mac: MacAddress,
    pub vni: Vni,
}

#[doc = "An interface IP address/mask"]
#[derive(Debug, PartialEq)]
pub struct IfAddress {
    pub ifname: String,
    pub address: IpAddr,
    pub mask_len: MaskLen,
    pub ifindex: Ifindex,
    pub vrfid: VrfId,
}

#[doc = "An IP route. Routes can have 255 next-hops at the most."]
#[derive(Debug, PartialEq)]
pub struct IpRoute {
    pub prefix: IpAddr,
    pub prefix_len: MaskLen,
    pub vrfid: VrfId,
    pub tableid: RouteTableId,
    pub rtype: RouteType,
    pub distance: RouteDistance,
    pub metric: RouteMetric,
    pub nhops: Vec<NextHop>,
}

#[doc = "Encapsulation data for a VxLAN encapsulation."]
#[repr(transparent)]
#[derive(Debug, PartialEq)]
pub struct VxlanEncap {
    pub vni: Vni,
}

#[doc = "Type for distinct encapsulation types"]
#[derive(Debug, PartialEq)]
pub enum NextHopEncap {
    VXLAN(VxlanEncap),
}

#[doc = "An IP route next-hop"]
#[derive(Debug, PartialEq)]
pub struct NextHop {
    pub fwaction: ForwardAction,
    pub address: Option<IpAddr>,
    pub ifindex: Option<Ifindex>,
    pub vrfid: VrfId,
    pub encap: Option<NextHopEncap>,
}

#[doc = "An object that may be exchanged between DP and CP. All first-class objects are contained here."]
#[derive(Debug, PartialEq)]
pub enum RpcObject {
    ConnectInfo(ConnectInfo),
    IfAddress(IfAddress),
    Rmac(Rmac),
    IpRoute(IpRoute),
    GetFilter(GetFilter),
}
impl RpcObject {
    #[doc = "Return the code (wire code) for an object"]
    pub fn wire_type(obj: &RpcObject) -> ObjType {
        match obj {
            RpcObject::IfAddress(_) => ObjType::IfAddress,
            RpcObject::Rmac(_) => ObjType::Rmac,
            RpcObject::ConnectInfo(_) => ObjType::ConnectInfo,
            RpcObject::IpRoute(_) => ObjType::IpRoute,
            RpcObject::GetFilter(_) => ObjType::GetFilter,
        }
    }
}

#[doc = "A struct to indicate a filter for the objects to retrieve (e.g. from dataplane). Unlike the other objects,
this struct is not intended to represent any piece of state. Each field is optional and represents a match criteria
with distinct options. Hence, the semantics are a logical OR. If multiple fields are present only objects satisfying
all matches shall be returned. The structure is kept flat for simplicity and reuse and for flexibility. E.g. specifying
no object type and a given Ifindex, the DP should return interface addresses configured on the interface specified as
well as routes using that interface. If a combination of fields is meaningless, the ObjType takes precedence and the
spurious filter be ignored. E.g. setting ObjecType to match routes and a MAC address (although in this case, the
DP could return the routes with next-hops resolving to some MAC at L2)."]
#[derive(Debug, PartialEq, Default)]
pub struct GetFilter {
    pub otype: Vec<ObjType>,
    pub vrfid: Vec<VrfId>,
    /*
       pub prefix: Option<Vec<IpAddr>>,
       pub routetype: Option<Vec<RouteType>>,
       pub address: Option<Vec<IpAddr>>,
       pub ifindex: Option<Vec<Ifindex>>,
       pub mac: Option<Vec<MacAddress>>,
       pub vni: Option<Vec<Vni>>,
       pub nexthop_address: Option<Vec<IpAddr>>,
    */
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
    pub fn new(
        ifname: String,
        address: IpAddr,
        mask_len: MaskLen,
        ifindex: Ifindex,
        vrfid: VrfId,
    ) -> Self {
        Self {
            ifname,
            address,
            mask_len,
            ifindex,
            vrfid,
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
impl IpRoute {
    #[allow(dead_code)]
    pub fn add_next_hop(&mut self, nhop: NextHop) -> Result<(), WireError> {
        if self.nhops.len() == NumNhops::MAX as usize {
            Err(WireError::TooManyNextHops)
        } else {
            self.nhops.push(nhop);
            Ok(())
        }
    }
}

/* Display for terser logs */
impl Display for VerInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v{}.{}.{}", self.major, self.minor, self.patch)
    }
}
impl Display for ConnectInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ConnectInfo ─── name:{} pid:{} verinfo:{}",
            &self.name, self.pid, self.verinfo
        )
    }
}
impl Display for Rmac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Rmac ─── vni:{} ip:{} mac:{}",
            self.vni, self.address, self.mac
        )
    }
}
impl Display for IfAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "IfAddress ─── ifname:{} ip:{}/{} ifindex:{} vrfid:{}",
            self.ifname, self.address, self.mask_len, self.ifindex, self.vrfid
        )
    }
}
impl Display for NextHopEncap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NextHopEncap::VXLAN(e) => {
                write!(f, "Vxlan (vni:{})", e.vni)
            }
        }
    }
}
impl Display for NextHop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(address) = &self.address {
            write!(f, " via {}", address)?;
        }
        if let Some(ifindex) = &self.ifindex {
            write!(f, " ifindex:{}", ifindex)?;
        }
        write!(f, " vrfid: {}", self.vrfid)?;
        if self.fwaction != ForwardAction::Forward {
            write!(f, " action: {:?}", self.fwaction)?;
        }
        if let Some(encap) = &self.encap {
            write!(f, " encap: {}", encap)?;
        }
        Ok(())
    }
}
impl Display for IpRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "IpRoute ─── vrf:{} tbl:{} {:?}[{}/{}] {}/{}",
            self.vrfid,
            self.tableid,
            self.rtype,
            self.distance,
            self.metric,
            self.prefix,
            self.prefix_len
        )?;

        for nhop in &self.nhops {
            write!(f, " {}", nhop)?;
        }
        Ok(())
    }
}
impl Display for GetFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GetFilter ─── ")?;
        write!(f, "  ObjType: ")?;
        for otype in &self.otype {
            write!(f, " {:?}", otype)?;
        }
        write!(f, "  vrfId: ")?;
        for vrfid in &self.vrfid {
            write!(f, " {:?}", vrfid)?;
        }
        Ok(())
    }
}
impl Display for RpcObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcObject::ConnectInfo(o) => o.fmt(f),
            RpcObject::IfAddress(o) => o.fmt(f),
            RpcObject::Rmac(o) => o.fmt(f),
            RpcObject::IpRoute(o) => o.fmt(f),
            RpcObject::GetFilter(o) => o.fmt(f),
        }
    }
}
