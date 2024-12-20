use log::{debug, info, warn};
use std::os::unix::net::{UnixDatagram ,SocketAddr};
use std::process;

use dplane_rpc::log::init_dplane_rpc_log;
use dplane_rpc::socks::{send_msg, ux_sock_bind};
use dplane_rpc::msg::*;
use dplane_rpc::wire::Wire;
use bytes::Bytes;

fn process_rx_data(sock: &UnixDatagram, peer: &SocketAddr, data: &[u8]) {
    let mut buf_rx = Bytes::copy_from_slice(data);
    match RpcMsg::decode(&mut buf_rx) {
        Ok(msg) => {
            if msg.msg_type() == MsgType::Notification {
                warn!("Got notification! Terminating....");
                process::exit(0)
            }
            send_msg(sock, &msg, peer)
        },
        Err(e) => panic!("Error decoding message received from {:?}: {:?}", peer, e),
    }
}

fn main() {
    init_dplane_rpc_log(tracing::Level::DEBUG);

    info!("Echo server: I will decode every message received, re-encode it and send it back...");
    let sock = ux_sock_bind("/tmp/DP.sock").expect("Unable to bind socket");

    loop {
        let mut buf = vec![0; 1000];
        match sock.recv_from(buf.as_mut_slice()) {
            Ok((len, peer)) => {
                debug!("Received {} octets of data from {:?}...", len, &peer);
                process_rx_data(&sock, &peer, &buf[..len]);
            },
            Err(e) => {
                panic!("Error receiving from unix sock: {}", e);
            }
        }
    }
}
