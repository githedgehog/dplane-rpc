use log::{debug, error};
use std::os::unix::fs::PermissionsExt;
pub use std::os::unix::net::UnixDatagram;
pub use std::os::unix::net::SocketAddr;
use std::fs;
use std::path::Path;
use bytes::BytesMut;
use crate::msg::RpcMsg;
use crate::wire::Wire;

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

pub fn send_msg(sock: &UnixDatagram, msg: &RpcMsg, peer: &SocketAddr) {
    debug!("Sending {:#?}", msg);
    let mut buf = BytesMut::with_capacity(128);
    match msg.encode(&mut buf) {
        Ok(_) => {
            match sock.send_to_addr(&buf, peer) {
                Ok(len) => {
                    debug!("Sent {} octets to {:?}", len, peer);
                },
                Err(e) => {
                    error!("Failed to send data to {:?}:{}", peer, e)
                },
            }
        },
        Err(e) => {
            error!("Failed to encode message: {:?} ", e);
        }
    }
}
