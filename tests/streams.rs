//! A stream end to end over a lossy, reordering, duplicating channel with
//! stream and connection flow control (see `support/channel.rs`, shared
//! with the `streams` fuzz target).

#[path = "support/channel.rs"]
mod channel;

#[test]
fn test_streams_survive_a_hostile_channel() {
    let mut seed = 0x1234_5678_9abc_def0u64;
    let mut total_lost = 0;
    for case in 0..300 {
        let input: Vec<u8> = (0..4096)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed as u8
            })
            .collect();
        let len = [0, 1, 999, 4_000, 6_001, 20_000][case % 6];
        let out = channel::run(&input, len).unwrap_or_else(|e| panic!("case {case}: {e}"));
        total_lost += out.lost;
    }
    assert!(
        total_lost > 1000,
        "the channel lost only {total_lost} packets"
    );
}

#[test]
fn test_a_clean_channel() {
    let out = channel::run(&[], 50_000).expect("clean run");
    assert_eq!(out.lost, 0);
}
