// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::msg::RpcMsg;
use crate::wire::Wire;
use bytes::BytesMut;
use log::{error, trace};
use mio::Interest;
use std::collections::VecDeque;
use std::fs;
use std::io::{Error, ErrorKind, Result};
use std::net::Shutdown;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::path::{Display, Path};

pub fn ux_sock_bind(path: impl AsRef<Path>) -> std::io::Result<UnixDatagram> {
    let path = path.as_ref();
    let _ = std::fs::remove_file(path);
    let sock = UnixDatagram::bind(path);
    if let Ok(_sock) = &sock {
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o777);
        /* may alternatively use perms.set_readonly(false),
        but clippy complains */
        fs::set_permissions(path, perms)?;
    }
    sock
}

pub trait Pretty {
    fn pretty(&self) -> Display;
}
impl Pretty for &SocketAddr {
    fn pretty(&self) -> Display {
        self.as_pathname()
            .unwrap_or(Path::new("anonymous"))
            .display()
    }
}

pub fn send_msg(sock: &UnixDatagram, msg: &RpcMsg, peer: &SocketAddr) -> Result<usize> {
    trace!("Sending {}", msg);
    let mut buf = BytesMut::with_capacity(128);
    match msg.encode(&mut buf) {
        Ok(_) => match sock.send_to_addr(&buf, peer) {
            Ok(len) => {
                trace!("Sent {} octets to {}", len, peer.pretty());
                Ok(len)
            }
            Err(e) => {
                if e.kind() != ErrorKind::WouldBlock {
                    error!("Failed to send data to '{}':{}", peer.pretty(), e);
                }
                Err(e)
            }
        },
        Err(e) => Err(Error::new(
            ErrorKind::Other,
            format!("Fatal: Encoding failure: {e:?}"),
        )),
    }
}

impl RpcMsg {
    pub fn send(&self, sock: &UnixDatagram, peer: &SocketAddr) -> Result<usize> {
        send_msg(sock, self, peer)
    }
}

#[derive(Debug)]
/// An RpcMsg cache to cache outgoing messages in order
struct MsgCache(VecDeque<(RpcMsg, SocketAddr)>);
#[allow(unused)]
impl MsgCache {
    pub fn new() -> Self {
        Self(VecDeque::new())
    }
    pub fn push_back(&mut self, msg: RpcMsg, peer: SocketAddr) {
        self.0.push_back((msg, peer));
    }
    pub fn pop_front(&mut self) -> Option<(RpcMsg, SocketAddr)> {
        self.0.pop_front()
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn clear(&mut self) {
        self.0.clear();
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn read_head(&self) -> Option<&(RpcMsg, SocketAddr)> {
        self.0.front()
    }
}
impl Default for MsgCache {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(unused)]
/// A unix socket wrapper tied to an outgoing message cache
pub struct RpcCachedSock {
    sock: UnixDatagram,
    cache: MsgCache,
    interests: Interest,
}

impl RpcCachedSock {
    const CACHE_THRESHOLD: usize = 500;

    /// Create an RpcCachedSock from an existing unix socket
    pub fn from_sock(sock: UnixDatagram) -> Self {
        Self {
            sock,
            cache: MsgCache::new(),
            interests: Interest::READABLE,
        }
    }

    /// Create an RpcCachedSock with a socket bound to path
    pub fn new(path: impl AsRef<Path>) -> std::io::Result<RpcCachedSock> {
        let sock = ux_sock_bind(path)?;
        Ok(Self::from_sock(sock))
    }

    /// Receive over the cached sock. This is just a wrapper to the rx method of unix sock
    pub fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        self.sock.recv_from(buf)
    }

    /// Get socket's desired poll interests. Writeable interest is set on xmit failures
    /// (ewouldblock)and cleared if set and the cache is emptied.
    pub fn interests(&self) -> Interest {
        self.interests
    }

    /// Get a reference to the inner sock
    pub fn get_sock(&self) -> &UnixDatagram {
        &self.sock
    }

    /// Get mutable reference to inner sock
    pub fn get_sock_mut(&mut self) -> &mut UnixDatagram {
        &mut self.sock
    }

    /// Get the raw fd of the inner socket
    pub fn get_raw_fd(&self) -> i32 {
        self.sock.as_raw_fd()
    }

    /// Number of messages cached
    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    /// private
    fn unix_send(&self, msg: &RpcMsg, peer: &SocketAddr) -> Result<usize> {
        send_msg(&self.sock, msg, peer)
    }

    /// Attempt to send a message. If cache is not empty, queue and send
    /// cached messages first, preserving the order.
    pub fn send_msg(&mut self, msg: RpcMsg, peer: &SocketAddr) {
        if !self.cache.is_empty() {
            self.cache.push_back(msg, peer.clone());
            self.flush_out_fast();
        } else if let Err(e) = self.unix_send(&msg, peer) {
            if e.kind() != ErrorKind::WouldBlock {
                error!("Failure sending over unix sock: {}", e);
            } else if !self.interests().is_writable() {
                trace!("Writable readiness notification is required");
                self.interests = self.interests.add(Interest::WRITABLE);
            }
            self.cache.push_back(msg, peer.clone());
            if self.cache_len() > Self::CACHE_THRESHOLD {
                error!("Cache length exceeded {}", Self::CACHE_THRESHOLD);
            }
        } else {
            // msg is consumed
        }
    }

    /// Attempt to send cached messages
    pub fn flush_out(&mut self) {
        while let Some((msg, peer)) = self.cache.pop_front() {
            if self.unix_send(&msg, &peer).is_err() {
                self.cache.0.push_front((msg, peer.clone()));
                break;
            }
        }
    }

    /// Same as flush_out(), but more efficient in case of failures since
    /// messages are only popped upon successful send.
    pub fn flush_out_fast(&mut self) {
        while let Some((msg, peer)) = self.cache.read_head() {
            if let Err(e) = self.unix_send(msg, peer) {
                if e.kind() != ErrorKind::WouldBlock {
                    error!("Failure sending over unix sock: {}", e);
                }
                return;
            } else {
                /* drop it, we sent it already */
                self.cache.pop_front();
            }
        }
        debug_assert!(self.cache.is_empty());
        if self.interests().is_writable() {
            trace!("Writable readiness notification no longer needed");
            self.interests = Interest::READABLE;
            //            let _ = self.interests.remove(Interest::WRITABLE);
            //            assert!(!self.interests.is_writable());
            //            assert!(self.interests.is_readable());
        }
    }
}

impl Drop for RpcCachedSock {
    fn drop(&mut self) {
        let _ = self.sock.shutdown(Shutdown::Both);
        if let Ok(addr) = self.sock.local_addr() {
            if let Some(path) = addr.as_pathname() {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

#[cfg(test)]
mod cached_sock_test {
    use super::ux_sock_bind;
    use super::RpcCachedSock;
    use super::*;
    use crate::log::{init_dplane_rpc_log, LogConfig};
    use crate::msg::*;
    use bytes::Bytes;
    use log::debug;
    use mio::unix::SourceFd;
    use mio::{Events, Interest, Poll, Token};
    use std::os::unix::net::SocketAddr;
    use std::thread;
    use std::time::Duration;

    /// Build a dummy response, with a certain sequence number
    fn build_dummy_msg(seqn: u64) -> RpcMsg {
        RpcResponse {
            op: RpcOp::Add,
            seqn,
            rescode: RpcResultCode::Ok,
            objs: vec![],
        }
        .wrap_in_msg()
    }

    fn init_logs() {
        let mut cfg = LogConfig::new(tracing::Level::DEBUG);
        cfg.display_thread_names = true;
        cfg.display_thread_ids = false;
        cfg.display_target = true;
        cfg.show_line_numbers = true;
        init_dplane_rpc_log(&cfg);
    }

    #[test]
    fn test_cached_sock() {
        init_logs();

        /* messages sent */
        let max_seqn = 2000;

        /* cached sock */
        let csock_path = "/tmp/test-cached-send.sock";
        let mut csock = RpcCachedSock::new(csock_path).expect("Should work");
        csock
            .get_sock_mut()
            .set_nonblocking(true)
            .expect("Should succeed");

        /* reception worker sock, which connects to main cached sock */
        let rx_address = "/tmp/test-cached-send-rx.sock";
        let rx_peer = SocketAddr::from_pathname(rx_address).expect("Should succeed");
        let rx_sock = ux_sock_bind(rx_address).expect("Should work");
        rx_sock.connect(csock_path).expect("Connect should succeed");

        /* reception worker logic */
        let rx_loop = move || {
            let mut last_response: u64 = 0;
            let mut raw = vec![0; 1000];
            loop {
                match rx_sock.recv_from(raw.as_mut_slice()) {
                    Ok((len, _)) => {
                        let mut buf_rx = Bytes::copy_from_slice(&raw[0..len]);
                        if let Ok(response) = RpcMsg::decode(&mut buf_rx).unwrap().get_response() {
                            debug!("Received msg {}", response.seqn);
                            assert_eq!(response.seqn, last_response + 1);
                            last_response = response.seqn;
                            if response.seqn == max_seqn {
                                debug!("Got {} messages. Terminating...", response.seqn);
                                break;
                            }
                        };
                    }
                    Err(_) => panic!("decoding error"),
                };
                thread::sleep(Duration::from_micros(100));
            }
        };
        /* rx worker */
        let handle = thread::Builder::new()
            .name("receiver".to_string())
            .spawn(rx_loop)
            .expect("Spawn should succeed");

        /* main thread */
        const CSOCK: Token = Token(123);
        let mut poller = Poll::new().expect("Failed to create poller");
        poller
            .registry()
            .register(
                &mut SourceFd(&csock.get_raw_fd()),
                CSOCK,
                Interest::READABLE,
            )
            .expect("Failed to register CPI sock");

        let mut seqn = 1;
        let mut events = Events::with_capacity(64);
        let mut can_send = true;
        loop {
            if can_send {
                let msg = build_dummy_msg(seqn);
                debug!("sending msg {}", seqn);
                csock.send_msg(msg, &rx_peer);
                seqn += 1;

                if csock.interests().is_writable() {
                    assert!(csock.cache_len() > 0);
                    let _ = poller.registry().reregister(
                        &mut SourceFd(&csock.get_raw_fd()),
                        CSOCK,
                        csock.interests(),
                    );
                    can_send = false;
                }
            } else {
                poller
                    .poll(&mut events, Some(Duration::from_millis(100)))
                    .expect("Poll error");

                for event in &events {
                    match event.token() {
                        CSOCK => {
                            if event.is_writable() {
                                csock.flush_out_fast();
                            }
                            if !csock.interests.is_writable() {
                                let _ = poller.registry().reregister(
                                    &mut SourceFd(&csock.get_raw_fd()),
                                    CSOCK,
                                    csock.interests(),
                                );
                                can_send = true;
                            }
                        }
                        _ => panic!(),
                    }
                }
            }

            /* stop condition: have sent max_seqn msg's and emptied the cache */
            if seqn == (max_seqn + 1) && csock.cache.is_empty() {
                println!("DONE!");
                break;
            }
        }
        handle.join().expect("Should succeed");
    }
}
