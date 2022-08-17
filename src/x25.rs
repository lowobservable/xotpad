pub const MIN_PACKET_LEN: usize = 3;

// Maximum packet length based on a super extended header (7 bytes) and maximum
// data field length (4096 bytes).
pub const MAX_PACKET_LEN: usize = 7 + 4096;
