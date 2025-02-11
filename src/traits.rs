pub use crate::objects::{ConnectInfo, VerInfo};
pub use crate::proto::{RpcResultCode, VER_DP_MAJOR, VER_DP_MINOR, VER_DP_PATCH};
use log::error;

#[allow(unused)]
pub trait RpcOperation {
    type ObjectStore;
    fn connect(&self) -> RpcResultCode
    where
        Self: Sized,
    {
        RpcResultCode::Unsupported
    }
    fn add(&self, db: &mut Self::ObjectStore) -> RpcResultCode
    where
        Self: Sized,
    {
        RpcResultCode::Unsupported
    }
    fn del(&self, db: &mut Self::ObjectStore) -> RpcResultCode
    where
        Self: Sized,
    {
        RpcResultCode::Unsupported
    }
    fn update(&self, db: &mut Self::ObjectStore) -> RpcResultCode
    where
        Self: Sized,
    {
        RpcResultCode::Unsupported
    }
}

impl RpcOperation for ConnectInfo {
    type ObjectStore = ();
    fn connect(&self) -> RpcResultCode {
        if self.verinfo == VerInfo::default() {
            // we require full match for the time being
            RpcResultCode::Ok
        } else {
            error!("Got connection request with incompatible RPC version!!");
            error!(
                "Requested version is v{}{}{}",
                self.verinfo.major, self.verinfo.minor, self.verinfo.patch
            );
            error!("Supported version is v{VER_DP_MAJOR}{VER_DP_MINOR}{VER_DP_PATCH}");
            RpcResultCode::Failure
        }
    }
}
