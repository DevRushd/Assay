pub fn validate_timestamp(timestamp: u64, current_time: u64) -> Result<(), &'static str> {
    // Fix: Validate timestamps by strictly rejecting future and deeply implausible past values
    if timestamp > current_time {
        return Err("Timestamp cannot be in the future");
    }
    if current_time - timestamp > 315360000 { // older than 10 years
        return Err("Timestamp is implausibly old");
    }
    Ok(())
}
