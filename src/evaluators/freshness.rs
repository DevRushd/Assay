pub fn evaluate_offchain_freshness(last_updated: u64, current_time: u64, max_staleness: u64) -> bool {
    // Fix: Implements an off-chain freshness evaluator to check if data is too stale
    current_time.saturating_sub(last_updated) <= max_staleness
}
