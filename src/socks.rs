use crate::msg::RpcMsg;
use crate::wire::Wire;
use bytes::BytesMut;
use log::{debug, error, trace};
use std::fs;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Result;
use std::os::unix::fs::PermissionsExt;
pub use std::os::unix::net::SocketAddr;
pub use std::os::unix::net::UnixDatagram;
use std::path::Display;
use std::path::Path;

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
    pub fn send(&self, sock: &UnixDatagram, peer: &SocketAddr) -> Result<usize> {
        send_msg(sock, self, peer)
    }
}
