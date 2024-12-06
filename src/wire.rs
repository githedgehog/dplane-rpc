use bytes::{Buf, BufMut, Bytes, BytesMut};
use mac_address::MacAddress;
use num_traits::FromPrimitive;
use std::mem::size_of;
use std::net::IpAddr;

use crate::msg::*;
use crate::objects::*;
use crate::proto::{EncapType, IpVer, MsgType, ObjType, RouteType, RpcOp, RpcResultCode};
use crate::proto::{IPV4_ADDR_LEN, IPV6_ADDR_LEN, MAC_LEN, REQUEST_HDR_SIZE, RESPONSE_HDR_SIZE};

#[doc = "Errors returned by the decoding and encoding trait methods.
Note: these are local error codes, not present on the wire. However, we may
use those to send notifications to the sender, be it for logging and troubleshooting."]
#[derive(Debug, PartialEq)]
pub enum WireError {
    /// The msg type is unknown
    InvalidMsgType(u8),
    /// The msg length does not match the number of octets available
    InconsistentMsgLen(u16, u16),
    /// There are not enough octets to decode a certain field
    NotEnoughBytes(usize, usize, &'static str),
    /// After decoding a message, there are octetts left over
    ExcessBytes(usize),
    /// The operation in a request is not known
    InvalidOp(u8),
    /// The result code in a response is invalid
    InValidResCode(u8),
    /// The type of object is unknown
    InvalidObjTtype(u8),
    /// The version for an IP address is invalid
    InvalidIpVersion(u8),
    /// A mandatory IP address is missing
    MissingIpAddress,
    /// A mandatory IP prefix is missing
    MissingIpPrefix,
    /// The encapsulation type is invalid
    InvalidEncap(u8),
}

#[doc = "Type to represent possible errors when decoding a blob in wire format"]
pub type WireResult<T> = Result<T, WireError>;

#[doc = "Trait implemented by internal types to be encoded and decoded"]
pub trait Wire<T> {
    fn decode(buf: &mut Bytes) -> WireResult<T>;
    fn encode(&self, buf: &mut BytesMut);
}

#[inline(always)]
#[doc = "Utility to check if a buffer contains enough data to decode a certain field or object.
The bytes crate is such that buffer readers will panic when attempting to read more octets than
those that are available. This wrapper checks this and issues an error instead."]
pub fn check_available(field: &'static str, buf: &mut Bytes, required: usize) -> WireResult<()> {
    if buf.remaining() < required {
        Err(WireError::NotEnoughBytes(buf.remaining(), required, field))
    } else {
        Ok(())
    }
}

/* Sub types: sub-objects that are not standalone and reused by other objects  */
impl Wire<MacAddress> for MacAddress {
    fn decode(buf: &mut Bytes) -> WireResult<MacAddress> {
        check_available("Mac", buf, MAC_LEN)?;
        let mut m: [u8; MAC_LEN] = [0; MAC_LEN];
        buf.copy_to_slice(&mut m);
        Ok(MacAddress::new(m))
    }
    fn encode(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&self.bytes());
    }
}
impl Wire<IpVer> for IpVer {
    fn decode(buf: &mut Bytes) -> WireResult<IpVer> {
        check_available("Ipver", buf, 1)?;
        let raw = buf.get_u8();
        let ipver: IpVer = IpVer::from_u8(raw).ok_or(WireError::InvalidIpVersion(raw))?;
        Ok(ipver)
    }
    fn encode(&self, buf: &mut BytesMut) {
        // Even if the version is IpVer::NONE
        // we encode it. This consumes one octet.
        buf.put_u8(*self as u8);
    }
}
impl Wire<Option<IpAddr>> for IpAddr {
    fn decode(buf: &mut Bytes) -> WireResult<Option<IpAddr>> {
        let ipver = IpVer::decode(buf)?;
        match ipver {
            IpVer::NONE => Ok(None),
            IpVer::IPV4 => {
                check_available("IPv4-address", buf, IPV4_ADDR_LEN)?;
                let mut ipv4 = [0_u8; IPV4_ADDR_LEN];
                buf.copy_to_slice(&mut ipv4);
                Ok(Some(IpAddr::from(ipv4)))
            }
            IpVer::IPV6 => {
                check_available("IPv4-address", buf, IPV6_ADDR_LEN)?;
                let mut ipv6 = [0_u8; IPV6_ADDR_LEN];
                buf.copy_to_slice(&mut ipv6);
                Ok(Some(IpAddr::from(ipv6)))
            }
        }
    }
    fn encode(&self, buf: &mut BytesMut) {
        match self {
            IpAddr::V4(ipv4) => {
                let v = IpVer::IPV4;
                v.encode(buf);
                buf.put_u32(ipv4.to_bits());
            }
            IpAddr::V6(ipv6) => {
                let v = IpVer::IPV6;
                v.encode(buf);
                buf.put_u128(ipv6.to_bits());
            }
        }
    }
}
impl Wire<Option<IpAddr>> for Option<IpAddr> {
    fn decode(buf: &mut Bytes) -> WireResult<Option<IpAddr>> {
        IpAddr::decode(buf)
    }
    fn encode(&self, buf: &mut BytesMut) {
        if let Some(address) = &self {
            address.encode(buf);
        } else {
            IpVer::encode(&IpVer::NONE, buf)
        }
    }
}
impl Wire<VrfId> for VrfId {
    fn decode(buf: &mut Bytes) -> WireResult<VrfId> {
        check_available("VrfId", buf, 4)?;
        let id = buf.get_u32_ne();
        Ok(VrfId { id })
    }
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32_ne(self.id);
    }
}
impl Wire<EncapType> for EncapType {
    fn decode(buf: &mut Bytes) -> WireResult<EncapType> {
        check_available("EncapType", buf, 1)?;
        let raw = buf.get_u8();
        let etype = EncapType::from_u8(raw).ok_or(WireError::InvalidEncap(raw))?;
        Ok(etype)
    }
    fn encode(&self, buf: &mut BytesMut) {
        // Encap type is always present on the wire.
        // Nothing follows if it is EncapType::NoEncap
        buf.put_u8(*self as u8);
    }
}
impl Wire<VxlanEncap> for VxlanEncap {
    fn decode(buf: &mut Bytes) -> WireResult<VxlanEncap> {
        check_available("EncapVxLAN", buf, 4)?;
        let vni: Vni = buf.get_u32_ne();
        Ok(VxlanEncap { vni })
    }
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32_ne(self.vni);
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
    fn encode(&self, buf: &mut BytesMut) {
        match self {
            Some(NextHopEncap::VXLAN(e)) => {
                EncapType::VXLAN.encode(buf);
                e.encode(buf);
            }
            None => {
                EncapType::NoEncap.encode(buf);
            }
        };
    }
}
impl Wire<ObjType> for ObjType {
    fn decode(buf: &mut Bytes) -> WireResult<ObjType> {
        check_available("ObjType", buf, 1)?;
        let otype = buf.get_u8();
        let otype: ObjType = ObjType::from_u8(otype).ok_or(WireError::InvalidObjTtype(otype))?;
        Ok(otype)
    }
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(*self as u8);
    }
}

/* First-class objects */
impl Wire<VerInfo> for VerInfo {
    fn decode(buf: &mut Bytes) -> WireResult<VerInfo> {
        check_available("Verinfo", buf, 3)?;
        let major = buf.get_u8();
        let minor = buf.get_u8();
        let patch = buf.get_u8();
        Ok(VerInfo {
            major,
            minor,
            patch,
        })
    }
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.major);
        buf.put_u8(self.minor);
        buf.put_u8(self.patch);
    }
}
impl Wire<Rmac> for Rmac {
    fn decode(buf: &mut Bytes) -> WireResult<Rmac> {
        let address = IpAddr::decode(buf)?;
        let address = address.ok_or(WireError::MissingIpAddress)?;
        let mac = MacAddress::decode(buf)?;
        check_available("vni", buf, 4)?;
        let vni: Vni = buf.get_u32_ne();
        Ok(Rmac { address, mac, vni })
    }
    fn encode(&self, buf: &mut BytesMut) {
        IpAddr::encode(&self.address, buf);
        MacAddress::encode(&self.mac, buf);
        buf.put_u32_ne(self.vni);
    }
}
impl Wire<IfAddress> for IfAddress {
    fn decode(buf: &mut Bytes) -> WireResult<IfAddress> {
        let address = IpAddr::decode(buf)?;
        let address = address.ok_or(WireError::MissingIpAddress)?;
        check_available("mask-len", buf, 1)?;
        let mask_len: MaskLen = buf.get_u8();
        check_available("ifindex", buf, 4)?;
        let ifindex: Ifindex = buf.get_u32_ne();
        let vrfid = VrfId::decode(buf)?;
        Ok(IfAddress {
            address,
            mask_len,
            ifindex,
            vrfid,
        })
    }
    fn encode(&self, buf: &mut BytesMut) {
        self.address.encode(buf);
        buf.put_u8(self.mask_len);
        buf.put_u32_ne(self.ifindex);
        self.vrfid.encode(buf);
    }
}
impl Wire<NextHop> for NextHop {
    fn decode(buf: &mut Bytes) -> WireResult<NextHop> {
        let address = IpAddr::decode(buf)?;
        check_available("ifindex", buf, 4)?;
        let ifindex: Ifindex = buf.get_u32_ne();
        let ifindex = if ifindex != 0 { Some(ifindex) } else { None };
        let vrfid = VrfId::decode(buf)?;
        let encap = Option::<NextHopEncap>::decode(buf)?;
        Ok(NextHop {
            address,
            ifindex,
            vrfid,
            encap,
        })
    }
    fn encode(&self, buf: &mut BytesMut) {
        self.address.encode(buf);
        if let Some(ifindex) = self.ifindex {
            buf.put_u32_ne(ifindex);
        } else {
            buf.put_u32_ne(0);
        }
        self.vrfid.encode(buf);
        self.encap.encode(buf);
    }
}
impl Wire<IpRoute> for IpRoute {
    fn decode(buf: &mut Bytes) -> WireResult<IpRoute> {
        let prefix = IpAddr::decode(buf)?;
        let prefix = prefix.ok_or(WireError::MissingIpPrefix)?;
        check_available("pref-len", buf, 1)?;
        let prefix_len: MaskLen = buf.get_u8();
        let vrfid: VrfId = VrfId::decode(buf)?;
        check_available("table-id", buf, 4)?;
        let tableid: RouteTableId = buf.get_u32_ne();
        check_available("rtype", buf, 4)?;
        let rtype = buf.get_u8();
        let rtype = RouteType::from_u8(rtype).unwrap_or_default();
        check_available("distance", buf, 4)?;
        let distance: RouteDistance = buf.get_u32_ne();
        check_available("metric", buf, 4)?;
        let metric: RouteMetric = buf.get_u32_ne();
        check_available("num-nhops", buf, 1)?;
        let num_nhops: NumNhops = buf.get_u8();

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
    fn encode(&self, buf: &mut BytesMut) {
        IpAddr::encode(&self.prefix, buf);
        buf.put_u8(self.prefix_len);
        VrfId::encode(&self.vrfid, buf);
        buf.put_u32_ne(self.tableid);
        buf.put_u8(self.rtype as u8);
        buf.put_u32_ne(self.distance);
        buf.put_u32_ne(self.metric);
        buf.put_u8(self.nhops.len() as NumNhops);
        for nhop in &self.nhops {
            nhop.encode(buf);
        }
    }
}
impl Wire<Option<RpcObject>> for RpcObject {
    fn decode(buf: &mut Bytes) -> WireResult<Option<RpcObject>> {
        let otype = ObjType::decode(buf)?;
        let obj = match otype {
            ObjType::VerInfo => Some(RpcObject::VerInfo(VerInfo::decode(buf)?)),
            ObjType::IfAddress => Some(RpcObject::IfAddress(IfAddress::decode(buf)?)),
            ObjType::Rmac => Some(RpcObject::Rmac(Rmac::decode(buf)?)),
            ObjType::IpRoute => Some(RpcObject::IpRoute(IpRoute::decode(buf)?)),
            ObjType::None => None,
        };
        Ok(obj)
    }
    fn encode(&self, buf: &mut BytesMut) {
        let otype: ObjType = RpcObject::wire_type(self);
        otype.encode(buf);
        match self {
            RpcObject::VerInfo(o) => o.encode(buf),
            RpcObject::IfAddress(o) => o.encode(buf),
            RpcObject::Rmac(o) => o.encode(buf),
            RpcObject::IpRoute(o) => o.encode(buf),
        };
    }
}
impl Wire<Option<RpcObject>> for Option<RpcObject> {
    fn decode(buf: &mut Bytes) -> WireResult<Option<RpcObject>> {
        RpcObject::decode(buf)
    }
    fn encode(&self, buf: &mut BytesMut) {
        if let Some(obj) = self {
            obj.encode(buf)
        } else {
            ObjType::None.encode(buf);
        }
    }
}

/* RpcRequest */
impl Wire<RpcRequest> for RpcRequest {
    fn decode(buf: &mut Bytes) -> WireResult<RpcRequest> {
        check_available("Request-hdr", buf, REQUEST_HDR_SIZE)?;
        let op = buf.get_u8();
        let op: RpcOp = RpcOp::from_u8(op).ok_or(WireError::InvalidOp(op))?;
        let seqn: MsgSeqn = buf.get_u64_ne();
        let obj: Option<RpcObject> = RpcObject::decode(buf)?;
        Ok(RpcRequest { op, seqn, obj })
    }
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.op as u8);
        buf.put_u64_ne(self.seqn);
        self.obj.encode(buf);
    }
}

/* RpcResponse */
impl Wire<RpcResultCode> for RpcResultCode {
    fn decode(buf: &mut Bytes) -> WireResult<RpcResultCode> {
        check_available("Rescode", buf, 1)?;
        let rescode = buf.get_u8();
        let rescode = RpcResultCode::from_u8(rescode).ok_or(WireError::InValidResCode(rescode))?;
        Ok(rescode)
    }
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(*self as u8)
    }
}
impl Wire<RpcResponse> for RpcResponse {
    fn decode(buf: &mut Bytes) -> WireResult<RpcResponse> {
        check_available("Response-hdr", buf, RESPONSE_HDR_SIZE)?;
        let op = buf.get_u8();
        let op: RpcOp = RpcOp::from_u8(op).ok_or(WireError::InvalidOp(op))?;
        let seqn: MsgSeqn = buf.get_u64_ne();
        let rescode: RpcResultCode = RpcResultCode::decode(buf)?;
        let num_objects: MsgNumObjects = buf.get_u8();
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
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.op as u8);
        buf.put_u64_ne(self.seqn);
        self.rescode.encode(buf);
        buf.put_u8(self.objs.len() as MsgNumObjects);
        for obj in &self.objs {
            obj.encode(buf);
        }
    }
}

/* RpcMsg and MsgType */
impl Wire<MsgType> for MsgType {
    fn decode(buf: &mut Bytes) -> WireResult<MsgType> {
        let raw = buf.get_u8();
        let mtype = MsgType::from_u8(raw).ok_or(WireError::InvalidMsgType(raw))?;
        Ok(mtype)
    }
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(*self as u8);
    }
}
impl Wire<RpcMsg> for RpcMsg {
    fn decode(buf: &mut Bytes) -> WireResult<RpcMsg> {
        let rx_len = buf.len() as MsgLen;
        println!("Decoding {} octets as RpcMsg...", rx_len);

        /* decode message type */
        let mtype = MsgType::decode(buf)?;

        /* decode length */
        let msg_len: MsgLen = buf.get_u16_ne();
        if msg_len != rx_len {
            return Err(WireError::InconsistentMsgLen(msg_len, rx_len));
        }
        /* decode message */
        let msg = match mtype {
            MsgType::Request => Ok(RpcMsg::Request(RpcRequest::decode(buf)?)),
            MsgType::Response => Ok(RpcMsg::Response(RpcResponse::decode(buf)?)),
            MsgType::Control => unimplemented!(),
            MsgType::Notification => unimplemented!(),
        };

        /* check if we have leftovers: this may be a bug of ours, but it could also be
        that the message was malformed internally: we checked msg-length and it matched
        the number of octets available. For the time being, we'll be conservative and err,
        discarding the message */
        if buf.remaining() != 0 {
            println!(
                "Warning!, {} octets were not decoded. Msg is:\n {:#?}",
                buf.remaining(),
                msg.unwrap()
            );
            return Err(WireError::ExcessBytes(buf.remaining()));
        };
        msg
    }
    fn encode(&self, buf: &mut BytesMut) {
        self.msg_type().encode(buf);
        let len_offset = buf.len();
        buf.put_u16_ne(0); // reserve space for length

        match self {
            RpcMsg::Request(m) => m.encode(buf),
            RpcMsg::Response(m) => m.encode(buf),
            _ => (),
        };
        // set the actual length
        let bufflen: MsgLen = buf.len() as u16;
        buf[len_offset..len_offset + size_of::<MsgLen>()].copy_from_slice(&bufflen.to_ne_bytes());
    }
}
