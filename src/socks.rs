// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::msg::RpcMsg;
use crate::wire::Wire;
use bytes::BytesMut;
use log::{debug, error, trace};
use std::collections::VecDeque;
use std::fs;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Result;
use std::net::Shutdown;
use std::os::unix::fs::PermissionsExt;
pub use std::os::unix::net::SocketAddr;
pub use std::os::unix::net::UnixDatagram;
use std::path::Display;
use std::path::Path;

#[cfg(test)]
use rand::distr::{Distribution, Uniform};

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
    debug!("Sending {}", msg);
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
    #[cfg(not(test))]
    pub fn send(&self, sock: &UnixDatagram, peer: &SocketAddr) -> Result<usize> {
        send_msg(sock, self, peer)
    }
    #[cfg(test)]
    pub fn send(&self, _sock: &UnixDatagram, _peer: &SocketAddr) -> Result<usize> {
        static mut LAST_OK: u64 = 0;
        static mut LAST_ATTEMPTED: u64 = 0;
        let seqn = self.get_response().unwrap().seqn;
        unsafe {
            assert!(seqn >= LAST_ATTEMPTED);
            LAST_ATTEMPTED = seqn;
        }
        let mut rng = rand::rng();
        let xmit_fate = Uniform::new(1, 100).expect("Failed to create RNG");
        if xmit_fate.sample(&mut rng) < 40 {
            unsafe {
                assert_eq!(seqn, LAST_OK + 1);
                LAST_OK = seqn;
            }
            Ok(100)
        } else {
            Err(Error::new(ErrorKind::WouldBlock, "fake error"))
        }
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
}
impl RpcCachedSock {
    /// Create an RpcCachedSock from an existing unix socket
    pub fn from_sock(sock: UnixDatagram) -> Self {
        Self {
            sock,
            cache: MsgCache::new(),
        }
    }

    /// Create an RpcCachedSock with a socket bound to path
    pub fn new(path: impl AsRef<Path>) -> std::io::Result<RpcCachedSock> {
        let sock = ux_sock_bind(path)?;
        Ok(Self::from_sock(sock))
    }

    /// Attempt to send a message. If cache is not empty, queue and send
    /// cached messages first, preserving the order.
    pub fn send_msg(&mut self, msg: RpcMsg, peer: &SocketAddr) {
        if !self.cache.is_empty() {
            self.cache.push_back(msg, peer.clone());
            self.flush_out_fast();
        } else if msg.send(&self.sock, peer).is_err() {
            assert_eq!(self.cache.len(), 0);
            self.cache.push_back(msg, peer.clone());
        } else {
            // msg is consumed
        }
    }

    /// Attempt to send cached messages
    pub fn flush_out(&mut self) {
        while let Some((msg, peer)) = self.cache.pop_front() {
            if msg.send(&self.sock, &peer).is_err() {
                self.cache.0.push_front((msg, peer.clone()));
                break;
            }
        }
    }

    /// Same as flush_out(), but more efficient in case of failures since
    /// messages are only popped upon successful send.
    pub fn flush_out_fast(&mut self) {
        while let Some((msg, peer)) = self.cache.read_head() {
            if msg.send(&self.sock, peer).is_ok() {
                self.cache.pop_front();
            } else {
                break;
            }
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
    use super::RpcCachedSock;
    use crate::msg::*;
    use std::os::unix::net::SocketAddr;

    #[test]
    fn msg_cache() {
        let mut csock =
            RpcCachedSock::new("/tmp/test.sock").expect("Should be able to create sock");

        let peer = SocketAddr::from_pathname("nowhere").expect("Should succeed");

        // send sequenced responses, starting from 1.
        let mut seqn = 1;
        loop {
            if !csock.cache.is_empty() {
                csock.flush_out_fast()
            }
            let msg = RpcResponse {
                op: RpcOp::Add,
                seqn,
                rescode: RpcResultCode::Ok,
                objs: vec![],
            }
            .wrap_in_msg();

            csock.send_msg(msg, &peer);
            seqn += 1;

            // finish if the cache is empty, but not before sending at least 100 msg's
            if seqn > 100 && csock.cache.is_empty() {
                break;
            }
        }
    }
}
