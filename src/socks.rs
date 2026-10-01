// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::msg::RpcMsg;
use crate::wire::Wire;
use bytes::{Bytes, BytesMut};
use mio::Interest;
use std::collections::VecDeque;
use std::fs;
use std::io::{Error, ErrorKind, Result};
use std::net::Shutdown;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::path::{Display, Path};
use tracing::{error, trace, warn};

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
    fn pretty(&self) -> Display<'_>;
}
impl Pretty for &SocketAddr {
    fn pretty(&self) -> Display<'_> {
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
        Err(e) => Err(Error::other(format!("Fatal: Encoding failure: {e:?}"))),
    }
}

impl RpcMsg {
    pub fn send(&self, sock: &UnixDatagram, peer: &SocketAddr) -> Result<usize> {
        send_msg(sock, self, peer)
    }
}

#[derive(Debug)]
/// A cache of encoded outgoing messages, in order
struct MsgCache(VecDeque<(Bytes, SocketAddr)>);
#[allow(unused)]
impl MsgCache {
    pub fn new() -> Self {
        Self(VecDeque::new())
    }
    pub fn push_back(&mut self, data: Bytes, peer: SocketAddr) {
        self.0.push_back((data, peer));
    }
    pub fn pop_front(&mut self) -> Option<(Bytes, SocketAddr)> {
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
    pub fn read_head(&self) -> Option<&(Bytes, SocketAddr)> {
        self.0.front()
    }
}
impl Default for MsgCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Outcome of an attempt to send an encoded message
enum SendOutcome {
    Sent,      // The msg was sent
    NeedRetry, // The msg could not be sent now
    Drop,      // The msg could not be sent and won't in the future
}

#[allow(unused)]
/// A unix socket wrapper tied to an outgoing message cache
pub struct RpcCachedSock {
    sock: UnixDatagram,
    cache: MsgCache,
    interests: Interest,
}

impl RpcCachedSock {
    /// Number of cached messages above which we warn
    const CACHE_THRESHOLD: usize = 500;
    /// Max number of cached messages. Messages beyond this are dropped.
    const CACHE_MAX_LEN: usize = 65536;

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

    /// private: attempt to send an encoded message and tell what to do with it
    fn try_send(&self, data: &[u8], peer: &SocketAddr) -> SendOutcome {
        match self.sock.send_to_addr(data, peer) {
            Ok(_) => SendOutcome::Sent,
            Err(e) => {
                if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) {
                    SendOutcome::NeedRetry
                } else {
                    error!("Dropping msg to {}: {e}", peer.pretty());
                    SendOutcome::Drop
                }
            }
        }
    }

    /// private: request writable readiness notifications
    fn set_writable(&mut self) {
        if !self.interests.is_writable() {
            self.interests = self.interests.add(Interest::WRITABLE);
        }
    }

    /// private: cache an encoded message, unless the cache is full
    fn enqueue(&mut self, data: Bytes, peer: &SocketAddr) {
        if self.cache.len() >= Self::CACHE_MAX_LEN {
            error!(
                "Cache is full ({} messages): dropping message to '{}'",
                Self::CACHE_MAX_LEN,
                peer.pretty()
            );
            return;
        }
        self.cache.push_back(data, peer.clone());
        if self.cache.len() == Self::CACHE_THRESHOLD {
            warn!("Cache length reached {}", Self::CACHE_THRESHOLD);
        }
    }

    /// Attempt to send a message. If cache is not empty, queue and send
    /// cached messages first, preserving the order. Messages that cannot be
    /// encoded, or that fail to be sent for reasons other than the socket
    /// not being ready (e.g. the peer is gone), are dropped.
    pub fn send_msg(&mut self, msg: RpcMsg, peer: &SocketAddr) {
        trace!("Sending {}", msg);
        let mut buf = BytesMut::with_capacity(128);
        if let Err(e) = msg.encode(&mut buf) {
            error!("Dropping msg to {}: encode error: {e}", peer.pretty());
            return;
        }
        let data = buf.freeze();

        if !self.cache.is_empty() {
            self.enqueue(data, peer);
            self.flush_out_fast();
        } else if let SendOutcome::NeedRetry = self.try_send(&data, peer) {
            self.set_writable();
            self.enqueue(data, peer);
        }
    }

    /// Attempt to send cached messages. Same as flush_out_fast().
    pub fn flush_out(&mut self) {
        self.flush_out_fast();
    }

    /// Attempt to send cached messages, in order. Messages are only popped when
    /// sent or dropped. If the socket is not ready, writable readiness notification
    /// is requested so that flushing can be resumed later.
    pub fn flush_out_fast(&mut self) {
        while let Some((data, peer)) = self.cache.read_head() {
            match self.try_send(data, peer) {
                SendOutcome::NeedRetry => {
                    self.set_writable(); // ensure we get awaken
                    return;
                }
                SendOutcome::Sent | SendOutcome::Drop => {
                    self.cache.pop_front();
                }
            }
        }
        debug_assert!(self.cache.is_empty());
        if self.interests().is_writable() {
            self.interests = Interest::READABLE;
        }
    }
}

impl Drop for RpcCachedSock {
    fn drop(&mut self) {
        let _ = self.sock.shutdown(Shutdown::Both);
        let Ok(addr) = self.sock.local_addr() else {
            return;
        };
        if let Some(path) = addr.as_pathname() {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod cached_sock_test {
    use super::RpcCachedSock;
    use super::ux_sock_bind;
    use super::*;
    use crate::log::{LogConfig, init_dplane_rpc_log};
    use crate::msg::*;
    use bytes::Bytes;
    use mio::unix::SourceFd;
    use mio::{Events, Interest, Poll, Token};
    use std::os::unix::net::SocketAddr;
    use std::thread;
    use std::time::Duration;
    use tracing::debug;

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

    /// Build a response that cannot be encoded (too many objects)
    fn build_unencodable_msg(seqn: u64) -> RpcMsg {
        let mut resp = RpcResponse::new(RpcOp::Add, seqn, RpcResultCode::Ok);
        for n in 1..=256 {
            resp.objs.push(RpcObject::Rmac(Rmac::new(
                "7.0.0.1".parse().unwrap(),
                MacAddress::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
                n,
            )));
        }
        resp.wrap_in_msg()
    }

    /// Receive all pending responses from sock, returning their seqns
    fn drain(sock: &UnixDatagram) -> Vec<u64> {
        let mut seqns = vec![];
        let mut raw = vec![0; 1000];
        while let Ok((len, _)) = sock.recv_from(raw.as_mut_slice()) {
            let mut buf_rx = Bytes::copy_from_slice(&raw[0..len]);
            let msg = RpcMsg::decode(&mut buf_rx).expect("Decoding should succeed");
            seqns.push(msg.get_response().expect("Should be a response").seqn);
        }
        seqns
    }

    #[test]
    fn test_cached_sock_drops_on_peer_gone() {
        init_logs();
        let mut csock = RpcCachedSock::new("/tmp/test-cached-peer-gone.sock").expect("Should work");
        csock
            .get_sock_mut()
            .set_nonblocking(true)
            .expect("Should succeed");

        /* peer whose path does not exist: ENOENT */
        let _ = std::fs::remove_file("/tmp/test-cached-peer-gone-noent.sock");
        let noent = SocketAddr::from_pathname("/tmp/test-cached-peer-gone-noent.sock").unwrap();
        csock.send_msg(build_dummy_msg(1), &noent);
        assert_eq!(csock.cache_len(), 0);

        /* peer whose socket was closed, leaving the path: ECONNREFUSED */
        let refused_path = "/tmp/test-cached-peer-gone-refused.sock";
        drop(ux_sock_bind(refused_path).expect("Should work"));
        let refused = SocketAddr::from_pathname(refused_path).unwrap();
        csock.send_msg(build_dummy_msg(2), &refused);
        assert_eq!(csock.cache_len(), 0);
        assert!(!csock.interests().is_writable());

        /* a live peer still gets messages */
        let rx_path = "/tmp/test-cached-peer-gone-rx.sock";
        let rx_sock = ux_sock_bind(rx_path).expect("Should work");
        rx_sock.set_nonblocking(true).expect("Should succeed");
        let rx_peer = SocketAddr::from_pathname(rx_path).unwrap();
        csock.send_msg(build_dummy_msg(3), &rx_peer);
        assert_eq!(csock.cache_len(), 0);
        assert_eq!(drain(&rx_sock), vec![3]);
        let _ = std::fs::remove_file(refused_path);
    }

    #[test]
    fn test_cached_sock_drops_unencodable() {
        init_logs();
        let mut csock =
            RpcCachedSock::new("/tmp/test-cached-unencodable.sock").expect("Should work");
        csock
            .get_sock_mut()
            .set_nonblocking(true)
            .expect("Should succeed");
        let rx_path = "/tmp/test-cached-unencodable-rx.sock";
        let rx_sock = ux_sock_bind(rx_path).expect("Should work");
        rx_sock.set_nonblocking(true).expect("Should succeed");
        let rx_peer = SocketAddr::from_pathname(rx_path).unwrap();

        csock.send_msg(build_unencodable_msg(1), &rx_peer);
        assert_eq!(csock.cache_len(), 0);
        csock.send_msg(build_dummy_msg(2), &rx_peer);
        assert_eq!(csock.cache_len(), 0);
        assert_eq!(drain(&rx_sock), vec![2]);
    }

    #[test]
    fn test_cached_sock_no_head_of_line_blocking() {
        init_logs();
        let mut csock = RpcCachedSock::new("/tmp/test-cached-hol.sock").expect("Should work");
        csock
            .get_sock_mut()
            .set_nonblocking(true)
            .expect("Should succeed");
        let rx_path = "/tmp/test-cached-hol-rx.sock";
        let rx_sock = ux_sock_bind(rx_path).expect("Should work");
        rx_sock.set_nonblocking(true).expect("Should succeed");
        let rx_peer = SocketAddr::from_pathname(rx_path).unwrap();

        /* send without reading until messages get cached */
        let mut seqn = 1;
        while csock.cache_len() == 0 {
            assert!(seqn < 100_000, "Messages never got cached");
            csock.send_msg(build_dummy_msg(seqn), &rx_peer);
            seqn += 1;
        }
        assert!(csock.interests().is_writable());

        /* queue a message to a gone peer: it gets cached, as it's behind others */
        let _ = std::fs::remove_file("/tmp/test-cached-hol-noent.sock");
        let noent = SocketAddr::from_pathname("/tmp/test-cached-hol-noent.sock").unwrap();
        csock.send_msg(build_dummy_msg(u64::MAX), &noent);

        /* an unencodable message never gets cached */
        let cached = csock.cache_len();
        csock.send_msg(build_unencodable_msg(u64::MAX), &rx_peer);
        assert_eq!(csock.cache_len(), cached);

        /* more messages behind */
        for _ in 0..10 {
            csock.send_msg(build_dummy_msg(seqn), &rx_peer);
            seqn += 1;
        }

        /* drain and flush: everything to the live peer must arrive, in order */
        let mut received = vec![];
        for _ in 0..100_000 {
            received.extend(drain(&rx_sock));
            if csock.cache_len() == 0 {
                break;
            }
            csock.flush_out_fast();
        }
        received.extend(drain(&rx_sock));
        assert_eq!(csock.cache_len(), 0);
        assert!(!csock.interests().is_writable());
        assert_eq!(received, (1..seqn).collect::<Vec<u64>>());
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
