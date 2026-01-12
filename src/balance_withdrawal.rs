use anyhow::{anyhow, Result};
use ethers::prelude::*;
use ethers::providers::{Http, Provider};
use ethers::types::{TransactionRequest, U256 as EthU256};
use std::str::FromStr;

/// Withdraw all balance from app address to recipient
pub async fn withdraw_balance(
    app_private_key: &[u8],
    rpc_url: &str,
    chain_id: u64,
    recipient: &str,
) -> Result<WithdrawResult> {
    // Validate RPC URL
    if rpc_url.is_empty() || (!rpc_url.starts_with("http://") && !rpc_url.starts_with("https://")) {
        return Err(anyhow!("Invalid RPC URL"));
    }

    // Create provider
    let provider = Provider::<Http>::try_from(rpc_url)
        .map_err(|e| anyhow!("Failed to create provider: {}", e))?;

    // Create wallet from private key
    let wallet = LocalWallet::from_bytes(app_private_key)
        .map_err(|e| anyhow!("Invalid private key: {}", e))?
        .with_chain_id(chain_id);

    let from_address = wallet.address();

    // Parse recipient address
    let to_address =
        Address::from_str(recipient).map_err(|_| anyhow!("Invalid recipient address"))?;

    // Get balance
    let balance = provider
        .get_balance(from_address, None)
        .await
        .map_err(|e| anyhow!("Failed to get balance: {}", e))?;

    if balance.is_zero() {
        return Err(anyhow!("Zero balance"));
    }

    // Get gas price
    let gas_price = provider
        .get_gas_price()
        .await
        .map_err(|e| anyhow!("Failed to get gas price: {}", e))?;

    // Simple transfer gas limit
    let gas_limit = EthU256::from(21000u64);

    // Calculate gas cost
    let gas_cost = gas_price * gas_limit;

    if balance <= gas_cost {
        return Err(anyhow!("Insufficient balance for gas"));
    }

    // Calculate transfer amount
    let amount = balance - gas_cost;

    // Build transaction
    let tx = TransactionRequest::new()
        .from(from_address)
        .to(to_address)
        .value(amount)
        .gas(gas_limit)
        .gas_price(gas_price)
        .chain_id(chain_id);

    // Sign transaction
    let signature = wallet
        .sign_transaction(&tx.clone().into())
        .await
        .map_err(|e| anyhow!("Failed to sign transaction: {}", e))?;

    // Encode signed transaction
    let signed_tx = tx.rlp_signed(&signature);

    // Send raw transaction
    let pending_tx = provider
        .send_raw_transaction(signed_tx)
        .await
        .map_err(|e| anyhow!("Failed to broadcast transaction: {}", e))?;

    let tx_hash = format!("{:?}", pending_tx.tx_hash());

    Ok(WithdrawResult {
        transaction_hash: tx_hash,
        from_address: format!("{:?}", from_address),
        to_address: format!("{:?}", to_address),
        amount: amount.to_string(),
        gas_used: gas_limit.as_u64(),
        gas_price: gas_price.to_string(),
    })
}

#[derive(Debug)]
pub struct WithdrawResult {
    pub transaction_hash: String,
    pub from_address: String,
    pub to_address: String,
    pub amount: String,
    pub gas_used: u64,
    pub gas_price: String,
}
