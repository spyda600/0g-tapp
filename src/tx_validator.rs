use crate::error::TappError;
use ethers::types::{Address, U256};
use std::str::FromStr;

/// Minimum gas limit for any Ethereum transaction (simple transfer).
const MIN_GAS_LIMIT: u64 = 21_000;

/// Maximum gas limit we allow (block gas limit ballpark).
const MAX_GAS_LIMIT: u64 = 30_000_000;

/// Maximum gas price: 10,000 gwei (10^13 wei).
/// Prevents fund drain via exorbitant gas fees.
/// At max gas_limit (30M) * max gas_price (10k gwei) = 0.3 ETH max gas cost.
const MAX_GAS_PRICE_WEI: &str = "10000000000000"; // 10^13

/// Maximum calldata size: 128 KB.
const MAX_CALLDATA_SIZE: usize = 128 * 1024;

/// Validated transaction parameters ready for signing.
pub struct ValidatedTxParams {
    pub to_address: Address,
    pub value: U256,
    pub chain_id: u64,
    pub gas_limit: u64,
    pub gas_price: Option<U256>,
    pub nonce: Option<u64>,
    pub data: Vec<u8>,
}

/// Validate a `SignTransactionRequest` and return strongly typed parameters.
///
/// Checks performed:
/// - `to_address` is a valid Ethereum address (20 bytes, hex)
/// - `value` parses as U256
/// - `chain_id` is non-zero
/// - `gas_limit` is within [21_000, 30_000_000]
/// - `gas_price`, if provided, parses as U256
pub fn validate_transaction_request(
    to_address: &str,
    value: &str,
    chain_id: u64,
    gas_limit: u64,
    gas_price: &str,
    nonce: u64,
    data: &[u8],
) -> Result<ValidatedTxParams, TappError> {
    // --- to_address ---
    if to_address.is_empty() {
        return Err(TappError::InvalidParameter {
            field: "to_address".to_string(),
            reason: "must not be empty".to_string(),
        });
    }
    let to = Address::from_str(to_address).map_err(|_| TappError::InvalidParameter {
        field: "to_address".to_string(),
        reason: format!("invalid Ethereum address: {}", to_address),
    })?;

    // --- value ---
    let val = if value.is_empty() {
        U256::zero()
    } else {
        U256::from_dec_str(value).map_err(|_| TappError::InvalidParameter {
            field: "value".to_string(),
            reason: format!("cannot parse as U256: {}", value),
        })?
    };

    // --- chain_id ---
    if chain_id == 0 {
        return Err(TappError::InvalidParameter {
            field: "chain_id".to_string(),
            reason: "must be non-zero".to_string(),
        });
    }

    // --- gas_limit ---
    if gas_limit < MIN_GAS_LIMIT || gas_limit > MAX_GAS_LIMIT {
        return Err(TappError::InvalidParameter {
            field: "gas_limit".to_string(),
            reason: format!(
                "must be between {} and {}, got {}",
                MIN_GAS_LIMIT, MAX_GAS_LIMIT, gas_limit
            ),
        });
    }

    // --- gas_price (optional, capped to prevent fund drain via fees) ---
    let max_gp = U256::from_dec_str(MAX_GAS_PRICE_WEI).unwrap();
    let gp = if gas_price.is_empty() {
        None
    } else {
        let parsed = U256::from_dec_str(gas_price).map_err(|_| TappError::InvalidParameter {
            field: "gas_price".to_string(),
            reason: format!("cannot parse as U256: {}", gas_price),
        })?;
        if parsed > max_gp {
            return Err(TappError::InvalidParameter {
                field: "gas_price".to_string(),
                reason: format!(
                    "exceeds maximum allowed gas price ({} wei / ~10000 gwei)",
                    MAX_GAS_PRICE_WEI
                ),
            });
        }
        Some(parsed)
    };

    // --- calldata size ---
    if data.len() > MAX_CALLDATA_SIZE {
        return Err(TappError::InvalidParameter {
            field: "data".to_string(),
            reason: format!(
                "calldata too large: {} bytes (max {})",
                data.len(),
                MAX_CALLDATA_SIZE
            ),
        });
    }

    // --- nonce (0 means "caller must provide", treated as optional) ---
    // Protobuf uint64 defaults to 0. We treat 0 as "not set".
    // For fresh wallets needing nonce=0, callers should use a bool flag or
    // handle nonce externally. This is a known limitation documented in the proto.
    let nonce_opt = if nonce == 0 { None } else { Some(nonce) };

    Ok(ValidatedTxParams {
        to_address: to,
        value: val,
        chain_id,
        gas_limit,
        gas_price: gp,
        nonce: nonce_opt,
        data: data.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_request() {
        let result = validate_transaction_request(
            "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18",
            "1000000000000000000",
            1,
            21000,
            "",
            0,
            &[],
        );
        assert!(result.is_ok());
        let params = result.unwrap();
        assert_eq!(params.chain_id, 1);
        assert_eq!(params.gas_limit, 21000);
        assert!(params.gas_price.is_none());
        assert!(params.nonce.is_none());
    }

    #[test]
    fn test_invalid_address() {
        let result = validate_transaction_request("not-an-address", "0", 1, 21000, "", 0, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_zero_chain_id() {
        let result = validate_transaction_request(
            "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18",
            "0",
            0,
            21000,
            "",
            0,
            &[],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_gas_limit_too_low() {
        let result = validate_transaction_request(
            "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18",
            "0",
            1,
            100,
            "",
            0,
            &[],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_gas_limit_too_high() {
        let result = validate_transaction_request(
            "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18",
            "0",
            1,
            50_000_000,
            "",
            0,
            &[],
        );
        assert!(result.is_err());
    }
}
