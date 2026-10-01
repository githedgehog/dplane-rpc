// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::objects::MacAddress;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use num_traits::FromPrimitive;
use std::mem::size_of;
use std::net::IpAddr;
use tracing::{error, trace};

use crate::msg::*;
use crate::proto::{EncapType, IpVer, MsgType, ObjType, RouteType, RpcOp, RpcResultCode};
use crate::proto::{IPV4_ADDR_LEN, IPV6_ADDR_LEN, MAC_LEN};

#[doc = "Errors returned by the decoding and encoding trait methods.
Note: these are local error codes, not present on the wire. However, we may
use those to send notifications to the sender, be it for logging and troubleshooting."]
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum WireError {
    #[error("The msg type is unknown {0}")]
    InvalidMsgType(u8),

    #[error("The msg length ({0}) does not match the number of octets available ({1})")]
    InconsistentMsgLen(u16, u16),

    #[error("There are not enough octets ({0}) to decode field of size {1} ({2})")]
    NotEnoughBytes(usize, usize, &'static str),

    #[error("After decoding a message, there are {0} octets left over")]
    ExcessBytes(usize),

    #[error("Unknown operation request {0}")]
    InvalidOp(u8),

    #[error("Invalid result code in response: {0}")]
    InValidResCode(u8),

    #[error("Unknown object type: {0}")]
    InvalidObjTtype(u8),

    #[error("Invalid IP version: {0}")]
    InvalidIpVersion(u8),

    #[error("Invalid IP route action: {0}")]
    InvalidForwardAction(u8),

    #[error("Mandatory IP addres is missing")]
    MissingIpAddress,

    #[error("Mandatory IP prefix is missing")]
    MissingIpPrefix,

    #[error("Invalid encapsulation type")]
    InvalidEncap(u8),

    #[error("Message is too long")]
    TooBig,

    #[error("Max number of next-hops exceeded")]
    TooManyNextHops,

    // N.B. responses do not anymore contain objects. This should not be seen
    #[error("Too many objects in response")]
    TooManyObjects,

    #[error("Attempted to encode a string that exceeds the maximum allowed size")]
    StringTooLong,
}

#[doc = "Type to represent possible errors when decoding a blob in wire format"]
pub type WireResult<T> = Result<T, WireError>;

#[doc = "Trait implemented by internal types to be encoded and decoded"]
pub trait Wire<T> {
    fn decode(buf: &mut Bytes) -> WireResult<T>;
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError>;
}

trait SafeReads {
    fn sget_u8(&mut self, hint: &'static str) -> Result<u8, WireError>;
    fn sget_u16_ne(&mut self, hint: &'static str) -> Result<u16, WireError>;
    fn sget_u32_ne(&mut self, hint: &'static str) -> Result<u32, WireError>;
    fn sget_u64_ne(&mut self, hint: &'static str) -> Result<u64, WireError>;
    fn scopy_to_slice(&mut self, dst: &mut [u8], hint: &'static str) -> Result<(), WireError>;
    fn sget_string(&mut self, hint: &'static str) -> Result<String, WireError>;
}

fn put_string(buf: &mut BytesMut, string: &String) -> Result<(), WireError> {
    if string.len() > u8::MAX as usize {
        Err(WireError::StringTooLong)
    } else {
        buf.put_u8(string.len() as u8);
        buf.extend_from_slice(string.as_bytes());
        Ok(())
    }
}

impl SafeReads for Bytes {
    #[rustfmt::skip]
    fn sget_u8(&mut self, hint: &'static str) -> Result<u8, WireError> {
        if self.remaining() < 1 {
            Err(WireError::NotEnoughBytes(self.remaining(), size_of::<u8>(), hint))
        } else {
            Ok(self.get_u8())
        }
    }
    #[rustfmt::skip]
    fn sget_u16_ne(&mut self, hint: &'static str) -> Result<u16, WireError> {
        if self.remaining() < 2 {
            Err(WireError::NotEnoughBytes(self.remaining(), size_of::<u16>(), hint))
        } else {
            Ok(self.get_u16_ne())
        }
    }
    #[rustfmt::skip]
    fn sget_u32_ne(&mut self, hint: &'static str) -> Result<u32, WireError> {
        if self.remaining() < 4 {
            Err(WireError::NotEnoughBytes(self.remaining(), size_of::<u32>(), hint))
        } else {
            Ok(self.get_u32_ne())
        }
    }
    #[rustfmt::skip]
    fn sget_u64_ne(&mut self, hint: &'static str) -> Result<u64, WireError> {
        if self.remaining() < 8 {
            Err(WireError::NotEnoughBytes(self.remaining(), size_of::<u64>(), hint))
        } else {
            Ok(self.get_u64_ne())
        }
    }
    #[rustfmt::skip]
    fn scopy_to_slice(&mut self, mut dst: &mut [u8], hint: &'static str) -> Result<(), WireError> {
        if self.remaining() < dst.len() {
            return Err(WireError::NotEnoughBytes(self.remaining(), dst.len(), hint));
        }
        while !dst.is_empty() {
            let src = self.chunk();
            let cnt = usize::min(src.len(), dst.len());
            dst[..cnt].copy_from_slice(&src[..cnt]);
            dst = &mut dst[cnt..];
            self.advance(cnt);
        }
        Ok(())
    }
    #[rustfmt::skip]
    fn sget_string(&mut self, hint: &'static str) -> Result<String, WireError> {
        let slen = self.sget_u8("string-length")? as usize;
        if self.remaining() < slen {
            return Err(WireError::NotEnoughBytes(self.remaining(), slen, hint));
        }
        let b = self.copy_to_bytes(slen);
        let string = String::from_utf8(b.to_vec()).unwrap_or_default();
        Ok(string)
    }
}

/* Sub types: sub-objects that are not standalone and reused by other objects  */
impl Wire<MacAddress> for MacAddress {
    fn decode(buf: &mut Bytes) -> WireResult<MacAddress> {
        let mut m: [u8; MAC_LEN] = [0; MAC_LEN];
        buf.scopy_to_slice(&mut m, "Mac")?;
        Ok(MacAddress::new(m))
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        buf.extend_from_slice(&self.octets());
        Ok(())
    }
}
impl Wire<IpVer> for IpVer {
    fn decode(buf: &mut Bytes) -> WireResult<IpVer> {
        let raw = buf.sget_u8("Ipver")?;
        let ipver: IpVer = IpVer::from_u8(raw).ok_or(WireError::InvalidIpVersion(raw))?;
        Ok(ipver)
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        // Even if the version is IpVer::NONE
        // we encode it. This consumes one octet.
        buf.put_u8(*self as u8);
        Ok(())
    }
}
impl Wire<Option<IpAddr>> for IpAddr {
    fn decode(buf: &mut Bytes) -> WireResult<Option<IpAddr>> {
        let ipver = IpVer::decode(buf)?;
        match ipver {
            IpVer::NONE => Ok(None),
            IpVer::IPV4 => {
                let mut ipv4 = [0_u8; IPV4_ADDR_LEN];
                buf.scopy_to_slice(&mut ipv4, "IPv4-address")?;
                Ok(Some(IpAddr::from(ipv4)))
            }
            IpVer::IPV6 => {
                let mut ipv6 = [0_u8; IPV6_ADDR_LEN];
                buf.scopy_to_slice(&mut ipv6, "IPv6-address")?;
                Ok(Some(IpAddr::from(ipv6)))
            }
        }
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        match self {
            IpAddr::V4(ipv4) => {
                let v = IpVer::IPV4;
                v.encode(buf)?;
                buf.put_u32(ipv4.to_bits());
            }
            IpAddr::V6(ipv6) => {
                let v = IpVer::IPV6;
                v.encode(buf)?;
                buf.put_u128(ipv6.to_bits());
            }
        }
        Ok(())
    }
}
impl Wire<Option<IpAddr>> for Option<IpAddr> {
    fn decode(buf: &mut Bytes) -> WireResult<Option<IpAddr>> {
        IpAddr::decode(buf)
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        if let Some(address) = &self {
            address.encode(buf)
        } else {
            IpVer::encode(&IpVer::NONE, buf)
        }
    }
}
impl Wire<VrfId> for VrfId {
    fn decode(buf: &mut Bytes) -> WireResult<VrfId> {
        let id = buf.sget_u32_ne("VrfId")?;
        Ok(id)
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        buf.put_u32_ne(*self);
        Ok(())
    }
}
impl Wire<EncapType> for EncapType {
    fn decode(buf: &mut Bytes) -> WireResult<EncapType> {
        let raw = buf.sget_u8("EncapType")?;
        let etype = EncapType::from_u8(raw).ok_or(WireError::InvalidEncap(raw))?;
        Ok(etype)
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        // Encap type is always present on the wire.
        // Nothing follows if it is EncapType::NoEncap
        buf.put_u8(*self as u8);
        Ok(())
    }
}
impl Wire<VxlanEncap> for VxlanEncap {
    fn decode(buf: &mut Bytes) -> WireResult<VxlanEncap> {
        let vni: Vni = buf.sget_u32_ne("EncapVxLAN")?;
        let mac = MacAddress::decode(buf)?;
        Ok(VxlanEncap { vni, mac })
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        buf.put_u32_ne(self.vni);
        MacAddress::encode(&self.mac, buf)?;
        Ok(())
    }
}
impl Wire<Option<NextHopEncap>> for Option<NextHopEncap> {
    fn decode(buf: &mut Bytes) -> WireResult<Option<NextHopEncap>> {
        let etype = EncapType::decode(buf)?;
        match etype {
            EncapType::NoEncap => Ok(None),
            EncapType::VXLAN => {
                let encap = VxlanEncap::decode(buf)?;
                Ok(Some(NextHopEncap::VXLAN(encap)))
            }
        }
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        match self {
            Some(NextHopEncap::VXLAN(e)) => {
                EncapType::VXLAN.encode(buf)?;
                e.encode(buf)?;
            }
            None => {
                EncapType::NoEncap.encode(buf)?;
            }
        };
        Ok(())
    }
}
impl Wire<ObjType> for ObjType {
    fn decode(buf: &mut Bytes) -> WireResult<ObjType> {
        let otype = buf.sget_u8("ObjType")?;
        let otype: ObjType = ObjType::from_u8(otype)
            .filter(|t| *t != ObjType::MaxObjType)
            .ok_or(WireError::InvalidObjTtype(otype))?;
        Ok(otype)
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        buf.put_u8(*self as u8);
        Ok(())
    }
}
impl Wire<ForwardAction> for ForwardAction {
    fn decode(buf: &mut Bytes) -> WireResult<ForwardAction> {
        let a = buf.sget_u8("fwaction")?;
        let fwaction = ForwardAction::from_u8(a).ok_or(WireError::InvalidForwardAction(a))?;
        Ok(fwaction)
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        buf.put_u8(*self as u8);
        Ok(())
    }
}

/* First-class objects */
impl Wire<VerInfo> for VerInfo {
    fn decode(buf: &mut Bytes) -> WireResult<VerInfo> {
        let major = buf.sget_u8("Ver:major")?;
        let minor = buf.sget_u8("Ver:minor")?;
        let patch = buf.sget_u8("Ver:patch")?;
        Ok(VerInfo {
            major,
            minor,
            patch,
        })
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        buf.put_u8(self.major);
        buf.put_u8(self.minor);
        buf.put_u8(self.patch);
        Ok(())
    }
}
impl Wire<ConnectInfo> for ConnectInfo {
    fn decode(buf: &mut Bytes) -> WireResult<ConnectInfo> {
        let name = buf.sget_string("name")?;
        let pid = buf.sget_u32_ne("pid")?;
        let verinfo = VerInfo::decode(buf)?;
        let synt = buf.sget_u64_ne("synt")?;
        Ok(ConnectInfo {
            name,
            pid,
            verinfo,
            synt,
        })
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        put_string(buf, &self.name)?;
        buf.put_u32_ne(self.pid);
        self.verinfo.encode(buf)?;
        buf.put_u64_ne(self.synt);
        Ok(())
    }
}
impl Wire<Rmac> for Rmac {
    fn decode(buf: &mut Bytes) -> WireResult<Rmac> {
        let address = IpAddr::decode(buf)?;
        let address = address.ok_or(WireError::MissingIpAddress)?;
        let mac = MacAddress::decode(buf)?;
        let vni: Vni = buf.sget_u32_ne("vni")?;
        Ok(Rmac { address, mac, vni })
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        IpAddr::encode(&self.address, buf)?;
        MacAddress::encode(&self.mac, buf)?;
        buf.put_u32_ne(self.vni);
        Ok(())
    }
}
impl Wire<IfAddress> for IfAddress {
    fn decode(buf: &mut Bytes) -> WireResult<IfAddress> {
        let address = IpAddr::decode(buf)?;
        let address = address.ok_or(WireError::MissingIpAddress)?;
        let mask_len: MaskLen = buf.sget_u8("mask-len")?;
        let ifindex: Ifindex = buf.sget_u32_ne("ifindex")?;
        let vrfid = VrfId::decode(buf)?;
        let ifname = buf.sget_string("ifname")?;
        Ok(IfAddress {
            ifname,
            address,
            mask_len,
            ifindex,
            vrfid,
        })
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        self.address.encode(buf)?;
        buf.put_u8(self.mask_len);
        buf.put_u32_ne(self.ifindex);
        self.vrfid.encode(buf)?;
        put_string(buf, &self.ifname)?;
        Ok(())
    }
}
impl Wire<NextHop> for NextHop {
    fn decode(buf: &mut Bytes) -> WireResult<NextHop> {
        let fwaction = ForwardAction::decode(buf)?;
        let address = IpAddr::decode(buf)?;
        let ifindex: Ifindex = buf.sget_u32_ne("ifindex")?;
        let ifindex = if ifindex != 0 { Some(ifindex) } else { None };
        let vrfid = VrfId::decode(buf)?;
        let encap = Option::<NextHopEncap>::decode(buf)?;
        Ok(NextHop {
            fwaction,
            address,
            ifindex,
            vrfid,
            encap,
        })
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        self.fwaction.encode(buf)?;
        self.address.encode(buf)?;
        if let Some(ifindex) = self.ifindex {
            buf.put_u32_ne(ifindex);
        } else {
            buf.put_u32_ne(0);
        }
        self.vrfid.encode(buf)?;
        self.encap.encode(buf)?;
        Ok(())
    }
}
impl Wire<IpRoute> for IpRoute {
    fn decode(buf: &mut Bytes) -> WireResult<IpRoute> {
        let prefix = IpAddr::decode(buf)?;
        let prefix = prefix.ok_or(WireError::MissingIpPrefix)?;
        let prefix_len: MaskLen = buf.sget_u8("pref-len")?;
        let vrfid: VrfId = VrfId::decode(buf)?;
        let tableid: RouteTableId = buf.sget_u32_ne("table-id")?;
        let rtype = buf.sget_u8("rtype")?;
        let rtype = RouteType::from_u8(rtype).unwrap_or_default();
        let distance = buf.sget_u8("distance")?;
        let metric = buf.sget_u32_ne("metric")?;
        let num_nhops: NumNhops = buf.sget_u8("num-nhops")?;

        let mut nhops: Vec<NextHop> = Vec::with_capacity(num_nhops as usize);
        for _n in 1..=num_nhops {
            let nhop = NextHop::decode(buf)?;
            nhops.push(nhop);
        }

        Ok(Self {
            prefix,
            prefix_len,
            vrfid,
            tableid,
            rtype,
            distance,
            metric,
            nhops,
        })
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        IpAddr::encode(&self.prefix, buf)?;
        buf.put_u8(self.prefix_len);
        VrfId::encode(&self.vrfid, buf)?;
        buf.put_u32_ne(self.tableid);
        buf.put_u8(self.rtype as u8);
        buf.put_u8(self.distance);
        buf.put_u32_ne(self.metric);
        let num_nhops =
            NumNhops::try_from(self.nhops.len()).map_err(|_| WireError::TooManyNextHops)?;
        buf.put_u8(num_nhops);
        for nhop in &self.nhops {
            nhop.encode(buf)?;
        }
        Ok(())
    }
}
impl Wire<Option<RpcObject>> for RpcObject {
    fn decode(buf: &mut Bytes) -> WireResult<Option<RpcObject>> {
        let otype = ObjType::decode(buf)?;
        let obj = match otype {
            ObjType::ConnectInfo => Some(RpcObject::ConnectInfo(ConnectInfo::decode(buf)?)),
            ObjType::IfAddress => Some(RpcObject::IfAddress(IfAddress::decode(buf)?)),
            ObjType::Rmac => Some(RpcObject::Rmac(Rmac::decode(buf)?)),
            ObjType::IpRoute => Some(RpcObject::IpRoute(IpRoute::decode(buf)?)),
            ObjType::None => None,
            _ => return Err(WireError::InvalidObjTtype(otype as u8)),
        };
        Ok(obj)
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        let otype: ObjType = RpcObject::wire_type(self);
        otype.encode(buf)?;
        match self {
            RpcObject::ConnectInfo(o) => o.encode(buf),
            RpcObject::IfAddress(o) => o.encode(buf),
            RpcObject::Rmac(o) => o.encode(buf),
            RpcObject::IpRoute(o) => o.encode(buf),
        }
    }
}
impl Wire<Option<RpcObject>> for Option<RpcObject> {
    fn decode(buf: &mut Bytes) -> WireResult<Option<RpcObject>> {
        RpcObject::decode(buf)
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        if let Some(obj) = self {
            obj.encode(buf)
        } else {
            ObjType::None.encode(buf)
        }
    }
}

/* RpcOp */
impl Wire<RpcOp> for RpcOp {
    fn decode(buf: &mut Bytes) -> WireResult<RpcOp> {
        let raw = buf.sget_u8("Op")?;
        let op = RpcOp::from_u8(raw)
            .filter(|op| *op != RpcOp::MaxRpcOp)
            .ok_or(WireError::InvalidOp(raw))?;
        Ok(op)
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        buf.put_u8(*self as u8);
        Ok(())
    }
}

/* RpcRequest */
impl Wire<RpcRequest> for RpcRequest {
    fn decode(buf: &mut Bytes) -> WireResult<RpcRequest> {
        let op = RpcOp::decode(buf)?;
        let seqn: MsgSeqn = buf.sget_u64_ne("seqn")?;
        let obj: Option<RpcObject> = RpcObject::decode(buf)?;
        Ok(RpcRequest { op, seqn, obj })
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        self.op.encode(buf)?;
        buf.put_u64_ne(self.seqn);
        self.obj.encode(buf)?;
        Ok(())
    }
}

/* RpcResponse */
impl Wire<RpcResultCode> for RpcResultCode {
    fn decode(buf: &mut Bytes) -> WireResult<RpcResultCode> {
        let rescode = buf.sget_u8("Rescode")?;
        let rescode = RpcResultCode::from_u8(rescode)
            .filter(|r| *r != RpcResultCode::RpcResultCodeMax)
            .ok_or(WireError::InValidResCode(rescode))?;
        Ok(rescode)
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        buf.put_u8(*self as u8);
        Ok(())
    }
}
impl Wire<RpcResponse> for RpcResponse {
    fn decode(buf: &mut Bytes) -> WireResult<RpcResponse> {
        let op = RpcOp::decode(buf)?;
        let seqn: MsgSeqn = buf.sget_u64_ne("seqn")?;
        let rescode: RpcResultCode = RpcResultCode::decode(buf)?;
        let num_objects: MsgNumObjects = buf.sget_u8("num-objects")?;
        let mut objs: Vec<RpcObject> = Vec::with_capacity(num_objects as usize);

        /* decode objects if there */
        if num_objects > 0 {
            for _n in 1..=num_objects {
                let obj: Option<RpcObject> = RpcObject::decode(buf)?;
                if let Some(obj) = obj {
                    objs.push(obj);
                }
            }
        }
        Ok(RpcResponse {
            op,
            seqn,
            rescode,
            objs,
        })
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        self.op.encode(buf)?;
        buf.put_u64_ne(self.seqn);
        self.rescode.encode(buf)?;
        let num_objects =
            MsgNumObjects::try_from(self.objs.len()).map_err(|_| WireError::TooManyObjects)?;
        buf.put_u8(num_objects);
        for obj in &self.objs {
            obj.encode(buf)?;
        }
        Ok(())
    }
}

/* RpcNotification */
impl Wire<RpcNotification> for RpcNotification {
    fn decode(_buf: &mut Bytes) -> WireResult<RpcNotification> {
        Ok(RpcNotification::default())
    }
    fn encode(&self, _buf: &mut BytesMut) -> Result<(), WireError> {
        Ok(())
    }
}

/* RpcControl */
impl Wire<RpcControl> for RpcControl {
    fn decode(buf: &mut Bytes) -> WireResult<RpcControl> {
        let refresh = buf.sget_u8("refresh")?;
        Ok(RpcControl { refresh })
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        buf.put_u8(self.refresh);
        Ok(())
    }
}

/* RpcMsg and MsgType */
impl Wire<MsgType> for MsgType {
    fn decode(buf: &mut Bytes) -> WireResult<MsgType> {
        let raw = buf.sget_u8("Msg-type")?;
        let mtype = MsgType::from_u8(raw).ok_or(WireError::InvalidMsgType(raw))?;
        Ok(mtype)
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        buf.put_u8(*self as u8);
        Ok(())
    }
}
fn encode_rpc_msg(msg: &RpcMsg, buf: &mut BytesMut, start: usize) -> Result<(), WireError> {
    msg.msg_type().encode(buf)?;
    let len_offset = buf.len();
    buf.put_u16_ne(0); // reserve space for length

    match msg {
        RpcMsg::Request(m) => m.encode(buf)?,
        RpcMsg::Response(m) => m.encode(buf)?,
        RpcMsg::Notification(m) => m.encode(buf)?,
        RpcMsg::Control(m) => m.encode(buf)?,
    };
    // set the actual length of this message
    let msglen = MsgLen::try_from(buf.len() - start).map_err(|_| WireError::TooBig)?;
    buf[len_offset..len_offset + size_of::<MsgLen>()].copy_from_slice(&msglen.to_ne_bytes());
    Ok(())
}
impl Wire<RpcMsg> for RpcMsg {
    fn decode(buf: &mut Bytes) -> WireResult<RpcMsg> {
        let rx_len = buf.len() as MsgLen;
        trace!("Decoding {rx_len} octets as RpcMsg ...");

        /* decode message type */
        let mtype = MsgType::decode(buf)?;

        /* decode length */
        let msg_len: MsgLen = buf.sget_u16_ne("msg-len")?;
        if msg_len != rx_len {
            return Err(WireError::InconsistentMsgLen(msg_len, rx_len));
        }
        /* decode message */
        let mut msg = match mtype {
            MsgType::Request => Ok(RpcMsg::Request(RpcRequest::decode(buf)?)),
            MsgType::Response => Ok(RpcMsg::Response(RpcResponse::decode(buf)?)),
            MsgType::Control => Ok(RpcMsg::Control(RpcControl::decode(buf)?)),
            MsgType::Notification => Ok(RpcMsg::Notification(RpcNotification::decode(buf)?)),
        };

        /* check if we have leftovers: this may be a bug of ours, but it could also be
           that the message was malformed internally: we checked msg-length and it matched
           the number of octets available. For the time being, we'll be conservative and err,
           discarding the message
        */
        if msg.is_ok() && buf.remaining() != 0 {
            msg = Err(WireError::ExcessBytes(buf.remaining()));
        }

        if let Err(e) = &msg {
            error!("Error decoding message: {e:?}");
        }
        msg
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        // the buffer might not be empty. We begin writing at start
        let start = buf.len();
        let res = encode_rpc_msg(self, buf, start);
        if res.is_err() {
            // leave the buffer as it was on error
            buf.truncate(start);
        }
        res
    }
}
