#[cfg(test)]
mod positive_tests {
    use crate::msg::*;
    use crate::wire::*;
    use bytes::{Bytes, BytesMut};
    use std::ops::Deref;

    // Main test function: encodes a message into wire, decodes it
    // and checks if resulting msg matches the original.
    fn test_encode_decode_msg(msg: &RpcMsg) {
        // Encode message into wire fmt
        println!("Message to encode:\n {:#?}", &msg);
        let mut buf = BytesMut::with_capacity(128);
        let _ = msg.encode(&mut buf);
        let wire: &[u8] = buf.deref();

        // show wire
        println!("Wire encoding has {} octets:", wire.len());
        println!("{:?}", &wire);

        // Decode message from wire
        let mut buf_rx = Bytes::copy_from_slice(wire);
        let msg_dec = RpcMsg::decode(&mut buf_rx).unwrap();

        // Compare msg created from wire with the original
        if *msg != msg_dec {
            println!("Decoded message does not match the encoded one");
            println!("Decoded Message:\n {:#?}", &msg_dec);
            assert!(false);
        }
    }

    #[test]
    fn test_rpcmsg_request_without_object() {
        let req = RpcRequest::new(RpcOp::Get, 123456);
        let msg = req.wrap_in_msg();
        test_encode_decode_msg(&msg);
    }

    #[test]
    fn test_rpcmsg_request_connect() {
        let verinfo = VerInfo {
            major: 44,
            minor: 66,
            patch: 99,
        };
        let req = RpcRequest::new(RpcOp::Connect, 999)
        .set_object(RpcObject::VerInfo(verinfo));
        let msg = req.wrap_in_msg();
        test_encode_decode_msg(&msg);
    }

    #[test]
    fn test_rpcmsg_request_rmac() {
        let rmac = Rmac::new(
            "7.0.0.1".parse().unwrap(),
            MacAddress::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
            3000,
        );
        let req = RpcRequest::new(RpcOp::Add, 98765)
        .set_object(RpcObject::Rmac(rmac));
        let msg = req.wrap_in_msg();
        test_encode_decode_msg(&msg);
    }

    #[test]
    fn test_rpcmsg_request_ifaddr() {
        let ifaddress = IfAddress::new("10.0.0.1".parse().unwrap(), 30, 987, 13);
        let req = RpcRequest::new(RpcOp::Del, 11223344)
        .set_object(RpcObject::IfAddress(ifaddress));
        let msg = req.wrap_in_msg();
        test_encode_decode_msg(&msg);
    }

    #[test]
    fn test_rpcmsg_request_iproute_overlay() {
        let mut route = IpRoute {
            prefix: "192.168.50.13".parse().unwrap(),
            prefix_len: 32,
            vrfid: 0,
            tableid: 1001,
            rtype: RouteType::Bgp,
            distance: 20,
            metric: 100,
            nhops: vec![],
        };

        let nhop = NextHop {
            address: Some("7.0.0.1".parse().unwrap()),
            ifindex: None,
            vrfid: 0,
            encap: Some(NextHopEncap::VXLAN(VxlanEncap { vni: 300 })),
        };
        assert_eq!(route.add_next_hop(nhop), Ok(()));

        let req = RpcRequest::new(RpcOp::Update, 3210)
        .set_object(RpcObject::IpRoute(route));
        let msg = req.wrap_in_msg();
        test_encode_decode_msg(&msg);
    }

    #[test]
    fn test_rpcmsg_request_iproute_underlay() {
        let mut route = IpRoute {
            prefix: "10.0.0.0".parse().unwrap(),
            prefix_len: 30,
            vrfid: 0,
            tableid: 254,
            rtype: RouteType::Connected,
            distance: 0,
            metric: 10,
            nhops: vec![],
        };

        let nhop = NextHop {
            address: None,
            ifindex: Some(123),
            vrfid: 0,
            encap: None,
        };
        assert_eq!(route.add_next_hop(nhop), Ok(()));

        let req = RpcRequest::new(RpcOp::Update, 3210)
        .set_object(RpcObject::IpRoute(route));

        let msg = req.wrap_in_msg();
        test_encode_decode_msg(&msg);
    }

    #[test]
    fn test_rpcmsg_request_iproute_underlay_ecmp() {
        let mut route = IpRoute {
            prefix: "7.0.0.1".parse().unwrap(),
            prefix_len: 32,
            vrfid: 0,
            tableid: 254,
            rtype: RouteType::Bgp,
            distance: 20,
            metric: 100,
            nhops: vec![],
        };
        let nhop = NextHop {
            address: Some("10.0.0.3".parse().unwrap()),
            ifindex: None,
            vrfid: 0,
            encap: None,
        };
        assert_eq!(route.add_next_hop(nhop), Ok(()));

        let nhop = NextHop {
            address: Some("10.0.0.6".parse().unwrap()),
            ifindex: None,
            vrfid: 0,
            encap: None,
        };
        assert_eq!(route.add_next_hop(nhop), Ok(()));

        let req = RpcRequest::new(RpcOp::Add, 7777)
        .set_object(RpcObject::IpRoute(route));

        let msg = req.wrap_in_msg();
        test_encode_decode_msg(&msg);
    }

    fn add_next_hops(route: &mut IpRoute, a: u8, b: u8) -> Result<(), WireError> {
        for i in 1..=a {
            for j in 1..=b {
                let a = format!("10.0.{}.{}", i, j);
                let vni: Vni = j as Vni * i as Vni;
                let nhop = NextHop {
                    address: Some(a.parse().unwrap()),
                    ifindex: None,
                    vrfid: 0,
                    encap: Some(NextHopEncap::VXLAN(VxlanEncap { vni })),
                };
                route.add_next_hop(nhop)?;
            }
        }
        println!("Route has {} next-hops", route.nhops.len());
        Ok(())
    }

    #[test]
    fn test_rpcmsg_request_iproute_many_nhops() {
        let mut route = IpRoute {
            prefix: "7.0.0.1".parse().unwrap(),
            prefix_len: 32,
            vrfid: 0,
            tableid: 254,
            rtype: RouteType::Bgp,
            distance: 20,
            metric: 100,
            nhops: vec![],
        };
        assert_eq!(add_next_hops(&mut route, 10, 20), Ok(()));
        let req = RpcRequest::new(RpcOp::Add, 7777)
        .set_object(RpcObject::IpRoute(route));

        let msg = req.wrap_in_msg();
        test_encode_decode_msg(&msg);
    }

    #[test]
    fn test_rpcmsg_request_iproute_too_many_nhops() {
        let mut route = IpRoute {
            prefix: "7.0.0.1".parse().unwrap(),
            prefix_len: 32,
            vrfid: 0,
            tableid: 254,
            rtype: RouteType::Bgp,
            distance: 20,
            metric: 100,
            nhops: vec![],
        };
        assert_eq!(
            add_next_hops(&mut route, 20, 20),
            Err(WireError::TooManyNextHops)
        );
    }

    #[test]
    fn test_rpcmsg_response() {
        let resp = RpcResponse::new(RpcOp::Add, 12345, RpcResultCode::Ok);
        let msg = resp.wrap_in_msg();
        test_encode_decode_msg(&msg);
    }

    #[test]
    fn test_rpcmsg_response_with_objects() {
        // create a response
        let mut resp = RpcResponse::new(RpcOp::Add, 12345, RpcResultCode::Ok);

        // create Rmac object
        let rmac = Rmac::new(
            "7.0.0.1".parse().unwrap(),
            MacAddress::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
            3000,
        );
        // crate ifaddress object
        let ifaddress = IfAddress::new("10.0.0.1".parse().unwrap(), 30, 987, 13);

        // wrap them as objects and add them to the response
        let object1 = RpcObject::Rmac(rmac);
        let object2 = RpcObject::IfAddress(ifaddress);
        assert_eq!(resp.add_object(object1), Ok(()));
        assert_eq!(resp.add_object(object2), Ok(()));

        let msg = resp.wrap_in_msg();
        test_encode_decode_msg(&msg);
    }

    #[test]
    fn test_rpcmsg_response_with_many_objects() {
        let mut resp = RpcResponse::new(RpcOp::Add, 12345, RpcResultCode::Ok);

        for n in 1..=255 {
            let addr = format!("7.0.0.{}", n);
            let rmac = Rmac::new(
                addr.parse().unwrap(),
                MacAddress::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
                3000,
            );
            let object = RpcObject::Rmac(rmac);
            assert_eq!(resp.add_object(object), Ok(()));
        }
        let msg = resp.wrap_in_msg();
        test_encode_decode_msg(&msg);
    }

    #[test]
    fn test_rpcmsg_response_with_too_many_objects() {
        let mut resp = RpcResponse::new(RpcOp::Add, 12345, RpcResultCode::Ok);

        for n in 1..=1000 {
            let rmac = Rmac::new(
                "7.0.0.1".parse().unwrap(),
                MacAddress::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
                n,
            );
            let object = RpcObject::Rmac(rmac);
            if n < 256 {
                assert_eq!(resp.add_object(object), Ok(()));
            } else {
                assert_eq!(resp.add_object(object), Err(WireError::TooManyObjects));
                break;
            }
        }
    }

    #[test]
    fn test_rpcmsg_request_get_with_empty_filter() {
        let filter = GetFilter::default();
        let req = RpcRequest::new(RpcOp::Get, 11223344)
        .set_object(RpcObject::GetFilter(filter));

        let msg = req.wrap_in_msg();
        test_encode_decode_msg(&msg);
    }

    #[test]
    fn test_rpcmsg_request_get_with_filter() {
        let filter = GetFilter {
            otype: vec![ObjType::IpRoute, ObjType::IfAddress, ObjType::Rmac],
            vrfid: vec![11, 21, 31, 41],
        };
        let req = RpcRequest::new(RpcOp::Get, 13)
        .set_object(RpcObject::GetFilter(filter));
        let msg = req.wrap_in_msg();
        test_encode_decode_msg(&msg);
    }
}

#[cfg(test)]
mod negative_tests {

    use crate::msg::*;
    use crate::wire::*;
    use bytes::Bytes;

    #[rustfmt::skip]
    #[test]
    fn neg_test_missing_rmac_vni() {
        let _wire_ok = [2, 28, 0, 2, 205, 129, 1, 0, 0, 0, 0, 0, 3, 1, 7, 0, 0, 1, 1, 2, 3, 4, 5, 6, 184, 11, 0, 0];
        let wire_bad =  [2, 24, 0, 2, 205, 129, 1, 0, 0, 0, 0, 0, 3, 1, 7, 0, 0, 1, 1, 2, 3, 4, 5, 6];
        let mut buf_rx = Bytes::copy_from_slice(&wire_bad);
        let res = RpcMsg::decode(&mut buf_rx);
        println!("{:?}",res);
        assert_eq!(res, Err(WireError::NotEnoughBytes(0, 4, "vni")));
    }

    #[rustfmt::skip]
    #[test]
    fn neg_test_bad_length_rmac_vni() {
        let _wire_ok  = [2, 28, 0, 2, 205, 129, 1, 0, 0, 0, 0, 0, 3, 1, 7, 0, 0, 1, 1, 2, 3, 4, 5, 6, 184, 11, 0, 0];
        let wire_bad = [2, 24, 0, 2, 205, 129, 1, 0, 0, 0, 0, 0, 3, 1, 7, 0, 0, 1, 1, 2, 3, 4, 5, 6, 184, 11, 0, 0];
        let mut buf_rx = Bytes::copy_from_slice(&wire_bad);
        let res = RpcMsg::decode(&mut buf_rx);
        assert_eq!(res, Err(WireError::InconsistentMsgLen(24, 28)));
    }

    #[rustfmt::skip]
    #[test]
    fn neg_test_msg_too_short() {
        let _wire_ok  = [2, 28, 0, 2, 205, 129, 1, 0, 0, 0, 0, 0, 3, 1, 7, 0, 0, 1, 1, 2, 3, 4, 5, 6, 184, 11, 0, 0];
        let wire_bad  = [2, 3, 0];
        let mut buf_rx = Bytes::copy_from_slice(&wire_bad);
        let res = RpcMsg::decode(&mut buf_rx);
        println!("{:?}", res);
        assert_eq!(res, Err(WireError::NotEnoughBytes(0, 1, "Op")));
    }

    #[rustfmt::skip]
    #[test]
    fn neg_test_msg_excess_data() {
        let _wire_ok  = [2, 28, 0, 2, 205, 129, 1, 0, 0, 0, 0, 0, 3, 1, 7, 0, 0, 1, 1, 2, 3, 4, 5, 6, 184, 11, 0, 0];
        let wire_bad  = [2, 30, 0, 2, 205, 129, 1, 0, 0, 0, 0, 0, 3, 1, 7, 0, 0, 1, 1, 2, 3, 4, 5, 6, 184, 11, 0, 0, 99, 255];
        let mut buf_rx = Bytes::copy_from_slice(&wire_bad);
        let res = RpcMsg::decode(&mut buf_rx);
        assert_eq!(res, Err(WireError::ExcessBytes(2)));
    }

    #[rustfmt::skip]
    #[test]
    fn neg_wrong_object_type() {
        let _wire_ok  = [2, 28, 0, 2, 205, 129, 1, 0, 0, 0, 0, 0, 3, 1, 7, 0, 0, 1, 1, 2, 3, 4, 5, 6, 184, 11, 0, 0];
        let wire_bad  = [2, 28, 0, 2, 205, 129, 1, 0, 0, 0, 0, 0, 99, 1, 7, 0, 0, 1, 1, 2, 3, 4, 5, 6, 184, 11, 0, 0];
        let mut buf_rx = Bytes::copy_from_slice(&wire_bad);
        let res = RpcMsg::decode(&mut buf_rx);
        assert_eq!(res, Err(WireError::InvalidObjTtype(99)));
    }

    #[rustfmt::skip]
    #[test]
    fn neg_missing_ipv4_addr() {
        let _wire_ok   = [2, 28, 0, 2, 205, 129, 1, 0, 0, 0, 0, 0, 3, 1, 7, 0, 0, 1, 1, 2, 3, 4, 5, 6, 184, 11, 0, 0];
        let wire_bad  = [2, 14, 0, 2, 205, 129, 1, 0, 0, 0, 0, 0, 3, 1];
        let mut buf_rx = Bytes::copy_from_slice(&wire_bad);
        let res = RpcMsg::decode(&mut buf_rx);
        println!("{:?}", res);
        assert_eq!(res, Err(WireError::NotEnoughBytes(0, 4, "IPv4-address")));
    }
}

#[cfg(test)]
mod buf_tests {
    use bytes::{Buf, BufMut, Bytes, BytesMut};
    use std::ops::Deref;
    #[test]
    fn buffmut_write() {
        let mut buf = BytesMut::with_capacity(0);
        for n in 1..=1000000 {
            buf.put_u8(n as u8);
        }
        println!("\ncapacity: {}", buf.capacity());
        println!("written:  {}", buf.len());
    }

    #[test]
    fn buff_read() {
        let mut buf = BytesMut::with_capacity(1000);
        for n in 1..=100000 {
            buf.put_u8(n as u8);
        }

        let wire: &[u8] = buf.deref();
        let mut buf_rx = Bytes::copy_from_slice(wire);
        for _n in 1..=100000 {
            let _v = buf_rx.get_u8();
        }
        println!("\ncapacity: {}", buf.capacity());
        println!("written:  {}", buf.len());
    }
}
