// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

pub use log::{debug, error, info, warn};
pub use tracing::Level;

pub struct LogConfig {
    pub display_level: bool,
    pub loglevel: tracing::Level,
    pub display_target: bool,
    pub display_thread_names: bool,
    pub display_thread_ids: bool,
    pub show_line_numbers: bool,
}
impl Default for LogConfig {
    fn default() -> Self {
        LogConfig {
            display_level: true,
            loglevel: tracing::Level::ERROR,
            display_target: false,
            display_thread_names: false,
            display_thread_ids: false,
            show_line_numbers: false,
        }
    }
}

impl LogConfig {
    pub fn new(loglevel: Level) -> Self {
        Self {
            loglevel,
            ..Default::default()
        }
    }
}

pub fn init_dplane_rpc_log(cfg: &LogConfig) {
    tracing_subscriber::fmt()
        .with_level(cfg.display_level)
        .with_max_level(cfg.loglevel)
        .with_target(cfg.display_target)
        .with_thread_ids(cfg.display_thread_ids)
        .with_thread_names(cfg.display_thread_names)
        .with_line_number(cfg.show_line_numbers)
        .compact()
        .init();
}
