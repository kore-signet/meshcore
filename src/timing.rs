use core::time::Duration;

#[derive(Clone, Copy)]
pub struct AirtimeEstConfig {
    pub spreading_factor: i32,
    pub bandwidth: i32, // in hz
    pub coding_rate: i32,
    pub preamble_length: i32,
}

pub fn estimate_airtime(length: i32, cfg: &AirtimeEstConfig) -> Duration {
    let symbol_time = (cfg.spreading_factor * cfg.spreading_factor) as f32 / cfg.bandwidth as f32;
    let preamble_time = cfg.preamble_length as f32 * symbol_time;
    let payload_symbols = 8 + i32::max(
        0,
        (length * 8 - 4 * cfg.spreading_factor + 28) / (4 * (cfg.spreading_factor - 2)),
    ) * (cfg.coding_rate + 4);

    let payload_time = payload_symbols as f32 * symbol_time;
    Duration::from_micros((preamble_time + payload_time) as u64).max(Duration::from_millis(50))
}

pub fn flood_timeout_ms(packet_airtime_ms: Duration) -> Duration {
    const FLOOD_TIMEOUT_BASE: Duration = Duration::from_millis(500);
    FLOOD_TIMEOUT_BASE + (packet_airtime_ms * 16)
}
//     Formula: 500ms + ((airtime × 6 + 250ms) × (path_len + 1))

pub fn direct_timeout_ms(packet_airtime_ms: Duration, path_len: u32) -> Duration {
    const DIRECT_TIMEOUT_BASE: Duration = Duration::from_millis(500);
    const DIRECT_SEND_PERHOP_FACTOR: u32 = 6;
    const DIRECT_SEND_PERHOP_EXTRA: Duration = Duration::from_millis(250);

    DIRECT_TIMEOUT_BASE
        + ((packet_airtime_ms * DIRECT_SEND_PERHOP_FACTOR + DIRECT_SEND_PERHOP_EXTRA)
            * (path_len + 1))
}
// @staticmethod
// def calc_direct_timeout_ms(packet_airtime_ms: float, path_len: int) -> float:
//     """
//     Calculate timeout for direct packets.

//     Args:
//         packet_airtime_ms: Estimated packet airtime in milliseconds
//         path_len: Number of hops in the path (0 for direct)

//     Returns:
//         Timeout in milliseconds
//     """
//     SEND_TIMEOUT_BASE_MILLIS = 500
//     DIRECT_SEND_PERHOP_FACTOR = 6.0
//     DIRECT_SEND_PERHOP_EXTRA_MILLIS = 250
//     return SEND_TIMEOUT_BASE_MILLIS + (
//         (packet_airtime_ms * DIRECT_SEND_PERHOP_FACTOR + DIRECT_SEND_PERHOP_EXTRA_MILLIS)
//         * (path_len + 1)
//     )
