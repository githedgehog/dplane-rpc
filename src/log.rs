pub use log::{debug, error, info, warn};
pub use tracing::Level;

pub fn init_dplane_rpc_log(loglevel: tracing::Level)
{
    if loglevel == tracing::Level::DEBUG {
        tracing_subscriber::fmt()
        .with_level(true)
        .with_max_level(loglevel)
        .with_target(true)
        .with_thread_ids(true)
        .pretty()
        .compact()
        .init();
    } else {
        tracing_subscriber::fmt()
        .with_level(true)
        .with_max_level(loglevel)
        .with_target(false)
        .with_thread_ids(false)
        .with_line_number(false)
        .compact()
        .init();
    }

}