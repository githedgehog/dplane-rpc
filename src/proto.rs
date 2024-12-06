use num_derive::FromPrimitive;

/* The version of this wire format */
pub const VER_DP_MAJOR: u8 = 0;
pub const VER_DP_MINOR: u8 = 1;
pub const VER_DP_PATCH: u8 = 0;

/* Some constants */
pub const MAC_LEN: usize = 6;
pub const IPV4_ADDR_LEN: usize = 4;
pub const IPV6_ADDR_LEN: usize = 16;
pub const REQUEST_HDR_SIZE: usize = 10;
pub const RESPONSE_HDR_SIZE: usize = 11;

#[doc = "Code for the type of a message"]
#[repr(u8)]
#[derive(Copy, Clone, Debug, FromPrimitive, PartialEq)]
pub enum MsgType {
    Control = 1,
    Request = 2,
    Response = 3,
    Notification = 4,
}

#[doc = "Code for the result within a response."]
#[repr(u8)]
#[derive(Copy, Clone, Debug, FromPrimitive, PartialEq)]
pub enum RpcResultCode {
    Ok = 1,
    Failure = 2,
    InvalidOperation = 3,
}

#[doc = "Ip version for an address or prefix. None if not present."]
#[repr(u8)]
#[derive(Copy, Clone, Debug, Default, FromPrimitive, PartialEq)]
pub enum IpVer {
    #[default]
    NONE = 0,
    IPV4 = 1,
    IPV6 = 2,
}

#[doc = "The operation to perform in a request."]
#[repr(u8)]
#[derive(Copy, Clone, Debug, FromPrimitive, PartialEq)]
pub enum RpcOp {
    Connect = 1,
    Add = 2,
    Del = 3,
    Update = 4,
    Get = 5,
}

#[doc = "The type of object that a request operation refers to, such as a route."]
#[repr(u8)]
#[derive(Copy, Clone, Debug, Default, FromPrimitive, PartialEq)]
pub enum ObjType {
    #[default]
    None = 0,
    VerInfo = 1,
    IfAddress = 2,
    Rmac = 3,
    IpRoute = 4,
}

#[doc = "A type of route."]
#[repr(u8)]
#[derive(Copy, Clone, Debug, Default, FromPrimitive, PartialEq)]
pub enum RouteType {
    Connected = 1,
    Static = 2,
    Bgp = 3,
    #[default]
    Other = 4,
}

#[doc = "The type of encapsulation towards some next-hop. NoEncap if no encapsulation is used."]
#[repr(u8)]
#[derive(Copy, Clone, Debug, Default, FromPrimitive, PartialEq)]
pub enum EncapType {
    #[default]
    NoEncap = 0,
    VXLAN = 1,
}

// Type aliases to be more explicit on the size of some fields on the wire.
// These types do not require any particular check.
#[doc = "The length of a message in octets"]
pub type MsgLen = u16;

#[doc = "The Id or sequence number of a message"]
pub type MsgSeqn = u64;

#[doc = "A type to indicate the number of objects within a response"]
pub type MsgNumObjects = u8;

#[doc = "The admin distance of a route"]
pub type RouteDistance = u32;

#[doc = "The metric for a route, depending on its type"]
pub type RouteMetric = u32;

#[doc = "The Id of a routing table (kernel)"]
pub type RouteTableId = u32;

#[doc = "Number of next-hops that a route has"]
pub type NumNhops = u8;

#[doc = "Ifindex of a network interface"]
pub type Ifindex = u32;

#[doc = "An IP address or prefix mask length"]
pub type MaskLen = u8;

#[doc = "An EVPN/VxLAN virtual network Id"]
pub type Vni = u32;
