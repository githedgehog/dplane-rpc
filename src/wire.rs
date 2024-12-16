use bytes::{Buf, BufMut, Bytes, BytesMut};
use log::{debug, error};
use mac_address::MacAddress;
use num_traits::FromPrimitive;
use std::mem::size_of;
use std::net::IpAddr;

use crate::msg::*;
use crate::objects::*;
use crate::proto::{EncapType, IpVer, MsgType, ObjType, RouteType, RpcOp, RpcResultCode};
use crate::proto::{IPV4_ADDR_LEN, IPV6_ADDR_LEN, MAC_LEN};

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
    /// The type of match is unknown
    InvalidMatchTtype(u8),
    /// The version for an IP address is invalid
    InvalidIpVersion(u8),
    /// A mandatory IP address is missing
    MissingIpAddress,
    /// A mandatory IP prefix is missing
    MissingIpPrefix,
    /// The encapsulation type is invalid
    InvalidEncap(u8),
    /// The message is too large and should be split. This error can only happen
    /// when encoding a message and it is possibly the only encoding error possible.
    TooBig,
    /// The maximum number of next-hops in a route was exceeded
    TooManyNextHops,
    /// The maximum number of objects in a response was exceeded
    TooManyObjects,
    /// The match list for a particular match type is too long
    MatchListTooLong,
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
        if self.remaining() < 1 {
            Err(WireError::NotEnoughBytes(self.remaining(), size_of::<u16>(), hint))
        } else {
            Ok(self.get_u16_ne())
        }
    }
    #[rustfmt::skip]
    fn sget_u32_ne(&mut self, hint: &'static str) -> Result<u32, WireError> {
        if self.remaining() < 1 {
            Err(WireError::NotEnoughBytes(self.remaining(), size_of::<u32>(), hint))
        } else {
            Ok(self.get_u32_ne())
        }
    }
    #[rustfmt::skip]
    fn sget_u64_ne(&mut self, hint: &'static str) -> Result<u64, WireError> {
        if self.remaining() < 1 {
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
}

/* Sub types: sub-objects that are not standalone and reused by other objects  */
impl Wire<MacAddress> for MacAddress {
    fn decode(buf: &mut Bytes) -> WireResult<MacAddress> {
        let mut m: [u8; MAC_LEN] = [0; MAC_LEN];
        buf.scopy_to_slice(&mut m, "Mac")?;
        Ok(MacAddress::new(m))
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        buf.extend_from_slice(&self.bytes());
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
        Ok(VxlanEncap { vni })
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        buf.put_u32_ne(self.vni);
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
        let otype: ObjType = ObjType::from_u8(otype).ok_or(WireError::InvalidObjTtype(otype))?;
        Ok(otype)
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        buf.put_u8(*self as u8);
        Ok(())
    }
}

impl Wire<MatchType> for MatchType {
    fn decode(buf: &mut Bytes) -> WireResult<MatchType> {
        let mtype = buf.sget_u8("MatchType")?;
        let mtype: MatchType =
            MatchType::from_u8(mtype).ok_or(WireError::InvalidMatchTtype(mtype))?;
        Ok(mtype)
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
impl Wire<GetFilter> for GetFilter {
    fn decode(buf: &mut Bytes) -> WireResult<GetFilter> {
        let num_mtypes = buf.sget_u8("num-mtypes")?;
        let mut filter = GetFilter::default();

        for _k in 1..=num_mtypes {
            let mtype = MatchType::decode(buf)?;
            let num_matches = buf.sget_u8("num-matches")?;
            match mtype {
                MatchType::MtNone => {}
                MatchType::MtObjType => {
                    for _n in 1..=num_matches {
                        filter.otype.push(ObjType::decode(buf)?);
                    }
                }
                MatchType::MtVrf => {
                    for _n in 1..=num_matches {
                        filter.vrfid.push(VrfId::decode(buf)?);
                    }
                }
            };
        }
        Ok(filter)
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        let offset = buf.len();
        let mut num_mtypes = 0_u8;
        buf.put_u8(0); // reserve

        let vec_len = self.otype.len();
        if vec_len > 0 {
            if vec_len > u8::MAX as usize {
                return Err(WireError::MatchListTooLong);
            }
            num_mtypes += 1;
            MatchType::MtObjType.encode(buf)?;
            buf.put_u8(vec_len as u8);
            for o in &self.otype {
                o.encode(buf)?;
            }
        }

        let vec_len = self.vrfid.len();
        if vec_len > 0 {
            if vec_len > u8::MAX as usize {
                return Err(WireError::MatchListTooLong);
            }
            num_mtypes += 1;
            MatchType::MtVrf.encode(buf)?;
            buf.put_u8(vec_len as u8);
            for o in &self.vrfid {
                o.encode(buf)?;
            }
        }
        buf[offset..offset + size_of::<u8>()].copy_from_slice(&num_mtypes.to_ne_bytes());
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
        Ok(IfAddress {
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
        Ok(())
    }
}
impl Wire<NextHop> for NextHop {
    fn decode(buf: &mut Bytes) -> WireResult<NextHop> {
        let address = IpAddr::decode(buf)?;
        let ifindex: Ifindex = buf.sget_u32_ne("ifindex")?;
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
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
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
        debug_assert!(self.nhops.len() <= NumNhops::MAX as usize);
        buf.put_u8(self.nhops.len() as NumNhops);
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
            ObjType::VerInfo => Some(RpcObject::VerInfo(VerInfo::decode(buf)?)),
            ObjType::IfAddress => Some(RpcObject::IfAddress(IfAddress::decode(buf)?)),
            ObjType::Rmac => Some(RpcObject::Rmac(Rmac::decode(buf)?)),
            ObjType::IpRoute => Some(RpcObject::IpRoute(IpRoute::decode(buf)?)),
            ObjType::GetFilter => Some(RpcObject::GetFilter(GetFilter::decode(buf)?)),
            ObjType::None => None,
        };
        Ok(obj)
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        let otype: ObjType = RpcObject::wire_type(self);
        otype.encode(buf)?;
        match self {
            RpcObject::VerInfo(o) => o.encode(buf),
            RpcObject::IfAddress(o) => o.encode(buf),
            RpcObject::Rmac(o) => o.encode(buf),
            RpcObject::IpRoute(o) => o.encode(buf),
            RpcObject::GetFilter(o) => o.encode(buf),
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

/* RpcRequest */
impl Wire<RpcRequest> for RpcRequest {
    fn decode(buf: &mut Bytes) -> WireResult<RpcRequest> {
        let op = buf.sget_u8("Op")?;
        let op: RpcOp = RpcOp::from_u8(op).ok_or(WireError::InvalidOp(op))?;
        let seqn: MsgSeqn = buf.sget_u64_ne("seqn")?;
        let obj: Option<RpcObject> = RpcObject::decode(buf)?;
        Ok(RpcRequest { op, seqn, obj })
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        buf.put_u8(self.op as u8);
        buf.put_u64_ne(self.seqn);
        self.obj.encode(buf)?;
        Ok(())
    }
}

/* RpcResponse */
impl Wire<RpcResultCode> for RpcResultCode {
    fn decode(buf: &mut Bytes) -> WireResult<RpcResultCode> {
        let rescode = buf.sget_u8("Rescode")?;
        let rescode = RpcResultCode::from_u8(rescode).ok_or(WireError::InValidResCode(rescode))?;
        Ok(rescode)
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        buf.put_u8(*self as u8);
        Ok(())
    }
}
impl Wire<RpcResponse> for RpcResponse {
    fn decode(buf: &mut Bytes) -> WireResult<RpcResponse> {
        let op = buf.sget_u8("Op")?;
        let op: RpcOp = RpcOp::from_u8(op).ok_or(WireError::InvalidOp(op))?;
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
        buf.put_u8(self.op as u8);
        buf.put_u64_ne(self.seqn);
        self.rescode.encode(buf)?;
        debug_assert!(self.objs.len() <= MsgNumObjects::MAX as usize);
        buf.put_u8(self.objs.len() as MsgNumObjects);
        for obj in &self.objs {
            obj.encode(buf)?;
        }
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
impl Wire<RpcMsg> for RpcMsg {
    fn decode(buf: &mut Bytes) -> WireResult<RpcMsg> {
        let rx_len = buf.len() as MsgLen;
        debug!("Decoding {rx_len} octets as RpcMsg ...");

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
            MsgType::Control => unimplemented!(),
            MsgType::Notification => unimplemented!(),
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
        self.msg_type().encode(buf)?;
        let len_offset = buf.len();
        buf.put_u16_ne(0); // reserve space for length

        match self {
            RpcMsg::Request(m) => m.encode(buf)?,
            RpcMsg::Response(m) => m.encode(buf)?,
            _ => unimplemented!(),
        };
        // set the actual length
        if buf.len() > u16::MAX as usize {
            Err(WireError::TooBig)
        } else {
            let bufflen: MsgLen = buf.len() as u16;
            buf[len_offset..len_offset + size_of::<MsgLen>()]
                .copy_from_slice(&bufflen.to_ne_bytes());
            Ok(())
        }
    }
}
