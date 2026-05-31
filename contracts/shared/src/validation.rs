use crate::errors::KoraError;
use soroban_sdk::{Bytes, Env, String};

/// Validate that an amount is strictly positive (> 0).
///
/// **Parameters:** `amount` — The amount to validate.
///
/// **Returns:** `Ok(())` if amount > 0, or `KoraError::InvalidAmount` otherwise.
///
/// **Use Case:** Minting invoices, funding pools, or any operation requiring a strictly positive amount.
pub fn require_non_zero_amount(amount: i128) -> Result<(), KoraError> {
    if amount <= 0 {
        return Err(KoraError::InvalidAmount);
    }
    Ok(())
}

/// Validate that an amount is non-negative (>= 0).
///
/// **Parameters:** `amount` — The amount to validate.
///
/// **Returns:** `Ok(())` if amount >= 0, or `KoraError::InvalidAmount` otherwise.
///
/// **Use Case:** Operations that allow zero (e.g., yield calculations, zero-value transfers).
pub fn require_positive_amount(amount: i128) -> Result<(), KoraError> {
    if amount < 0 {
        return Err(KoraError::InvalidAmount);
    }
    Ok(())
}

/// Validate that a timestamp is in the future.
///
/// **Parameters:**
/// - `env` — Soroban environment (provides current ledger timestamp)
/// - `ts` — The timestamp to validate (Unix seconds)
///
/// **Returns:** `Ok(())` if ts > current_timestamp, or `KoraError::InvalidDueDate` otherwise.
///
/// **Use Case:** Invoice due dates, funding deadlines, or any deadline that must be in the future.
pub fn require_future_timestamp(env: &Env, ts: u64) -> Result<(), KoraError> {
    if ts <= env.ledger().timestamp() {
        return Err(KoraError::InvalidDueDate);
    }
    Ok(())
}

/// Validate that a risk score is in the valid range (0–100).
///
/// **Parameters:** `score` — The risk score to validate.
///
/// **Returns:** `Ok(())` if score <= 100, or `KoraError::InvalidRiskScore` otherwise.
///
/// **Use Case:** Risk assessment in invoice minting and SME profile updates.
pub fn require_valid_risk_score(score: u32) -> Result<(), KoraError> {
    if score > 100 {
        return Err(KoraError::InvalidRiskScore);
    }
    Ok(())
}

/// Validate that a string is non-empty.
///
/// **Parameters:** `s` — The string to validate.
///
/// **Returns:** `Ok(())` if string.len() > 0, or `KoraError::EmptyString` otherwise.
///
/// **Use Case:** IPFS CIDs, currencies, or any required text field.
pub fn require_non_empty_string(s: &String) -> Result<(), KoraError> {
    if s.len() == 0 {
        return Err(KoraError::EmptyString);
    }
    Ok(())
}

/// Validate that a byte array is non-empty.
///
/// **Parameters:** `b` — The byte array to validate.
///
/// **Returns:** `Ok(())` if bytes.len() > 0, or `KoraError::EmptyBytes` otherwise.
///
/// **Use Case:** Debtor hashes (SHA-256 digests), public keys, or any required binary data.
// AUDIT FIX: Changed error from EmptyString to EmptyBytes for semantic correctness
pub fn require_non_empty_bytes(b: &Bytes) -> Result<(), KoraError> {
    if b.len() == 0 {
        return Err(KoraError::EmptyBytes);
    }
    Ok(())
}

/// Validate that a fee basis-point rate is valid (≤ 10,000 = 100%).
///
/// **Parameters:** `bps` — The fee rate in basis points.
///
/// **Returns:** `Ok(())` if bps <= 10,000, or `KoraError::InvalidFeeRate` otherwise.
///
/// **Use Case:** Protocol fee validation, late penalty rates, or investor yields.
pub fn require_valid_fee_bps(bps: u32) -> Result<(), KoraError> {
    if bps > 10_000 {
        return Err(KoraError::InvalidFeeRate);
    }
    Ok(())
}

/// Validate that an amount is within a specified bound.
///
/// **Parameters:**
/// - `amount` — The amount to validate.
/// - `max` — The maximum allowed value (inclusive).
///
/// **Returns:** `Ok(())` if 0 <= amount <= max, or `KoraError::InvalidAmount` otherwise.
///
/// **Use Case:** Ensuring amounts don't exceed pool capacity, funding targets, or user balances.
pub fn require_amount_within_bounds(amount: i128, max: i128) -> Result<(), KoraError> {
    if amount > max || amount < 0 {
        return Err(KoraError::InvalidAmount);
    }
    Ok(())
}

/// Safe basis-point multiplication: (amount × bps) / 10,000.
///
/// **Parameters:**
/// - `amount` — The base amount.
/// - `bps` — The basis-point rate (10,000 = 100%).
///
/// **Returns:** The result of (amount × bps) / 10,000, or `KoraError::ArithmeticOverflow` on overflow.
///
/// **Security:** Uses Rust's checked arithmetic to detect overflow. This is the canonical
/// implementation for all fee and yield calculations in the protocol.
///
/// **Example:** `bps_of(1_000_000, 50)` returns `5_000` (0.5% of 1 million).
pub fn bps_of(amount: i128, bps: u32) -> Result<i128, KoraError> {
    amount
        .checked_mul(bps as i128)
        .and_then(|v| v.checked_div(10_000))
        .ok_or(KoraError::ArithmeticOverflow)
}

/// Safe addition with overflow check.
///
/// **Parameters:**
/// - `a`, `b` — The values to add.
///
/// **Returns:** `a + b`, or `KoraError::ArithmeticOverflow` on overflow.
///
/// **Security:** Uses Rust's checked arithmetic. Never silently wraps or overflows.
pub fn safe_add(a: i128, b: i128) -> Result<i128, KoraError> {
    a.checked_add(b).ok_or(KoraError::ArithmeticOverflow)
}

/// Safe subtraction with underflow check.
///
/// **Parameters:**
/// - `a`, `b` — The values to subtract (`a - b`).
///
/// **Returns:** `a - b`, or `KoraError::ArithmeticOverflow` on underflow.
///
/// **Security:** Uses Rust's checked arithmetic. Never silently wraps or underflows.
pub fn safe_sub(a: i128, b: i128) -> Result<i128, KoraError> {
    a.checked_sub(b).ok_or(KoraError::ArithmeticOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Ledger, Env, String as SorobanString};

    #[test]
    fn test_require_non_zero_amount() {
        assert!(require_non_zero_amount(0).is_err());
        assert!(require_non_zero_amount(-1).is_err());
        assert!(require_non_zero_amount(1).is_ok());
    }

    #[test]
    fn test_require_positive_amount() {
        assert!(require_positive_amount(-1).is_err());
        assert!(require_positive_amount(0).is_ok());
        assert!(require_positive_amount(1).is_ok());
    }

    #[test]
    fn test_require_future_timestamp() {
        let env = Env::default();
        env.ledger().set_timestamp(1_000_000);

        assert!(require_future_timestamp(&env, 1_000_000).is_err()); // equal (not future)
        assert!(require_future_timestamp(&env, 999_999).is_err()); // past
        assert!(require_future_timestamp(&env, 1_000_001).is_ok()); // future
    }

    #[test]
    fn test_require_valid_risk_score() {
        assert!(require_valid_risk_score(0).is_ok());
        assert!(require_valid_risk_score(50).is_ok());
        assert!(require_valid_risk_score(100).is_ok());
        assert!(require_valid_risk_score(101).is_err());
    }

    #[test]
    fn test_require_non_empty_string() {
        let env = Env::default();
        let empty_str = SorobanString::from_str(&env, "");
        let non_empty_str = SorobanString::from_str(&env, "test");

        assert!(require_non_empty_string(&empty_str).is_err());
        assert!(require_non_empty_string(&non_empty_str).is_ok());
    }

    #[test]
    // AUDIT FIX: Test for new EmptyBytes error variant
    fn test_require_non_empty_bytes() {
        let env = Env::default();
        let empty_bytes = Bytes::from_slice(&env, &[]);
        let non_empty_bytes = Bytes::from_slice(&env, &[1, 2, 3]);

        let empty_result = require_non_empty_bytes(&empty_bytes);
        assert!(empty_result.is_err());
        assert_eq!(
            empty_result.unwrap_err(),
            KoraError::EmptyBytes,
            "Empty bytes should return EmptyBytes error"
        );

        assert!(require_non_empty_bytes(&non_empty_bytes).is_ok());
    }

    #[test]
    fn test_require_valid_fee_bps() {
        assert!(require_valid_fee_bps(0).is_ok());
        assert!(require_valid_fee_bps(50).is_ok());
        assert!(require_valid_fee_bps(10_000).is_ok());
        assert!(require_valid_fee_bps(10_001).is_err());
    }

    #[test]
    fn test_require_amount_within_bounds() {
        assert!(require_amount_within_bounds(0, 1_000).is_ok());
        assert!(require_amount_within_bounds(500, 1_000).is_ok());
        assert!(require_amount_within_bounds(1_000, 1_000).is_ok());
        assert!(require_amount_within_bounds(1_001, 1_000).is_err());
        assert!(require_amount_within_bounds(-1, 1_000).is_err());
    }

    #[test]
    fn test_bps_of_safe() {
        assert_eq!(bps_of(10_000, 100).unwrap(), 100);
        assert_eq!(bps_of(1_000_000, 50).unwrap(), 5_000);
        assert!(bps_of(i128::MAX, 10_000).is_err());
    }

    #[test]
    fn test_safe_add() {
        assert_eq!(safe_add(100, 200).unwrap(), 300);
        assert!(safe_add(i128::MAX, 1).is_err());
    }

    #[test]
    fn test_safe_sub() {
        assert_eq!(safe_sub(300, 100).unwrap(), 200);
        assert!(safe_sub(100, 200).is_err());
    }
}
