//! Faucet ERC20 tokens module.

use color_eyre::{eyre::eyre, Result};
use derive_new::new;
use tracing::{error, info};

use secp256k1::SecretKey;
use std::sync::RwLock;
use web3::api::Eth;
use web3::contract::{Contract, Options};
use web3::signing::Key;
use web3::types::U256;
use web3::Transport;

use crate::{config, ethereum};

/// Represents packet of information needed for single airdrop operation.
#[derive(Debug, serde::Deserialize)]
pub struct Airdrop {
    /// Ethereum address of the recipient.
    wallet: String,
    /// Amount of a token to be received.
    amount: u64,
}

/// Processes the airdrop: sends needed transactions into Ethereum.
pub async fn airdrop(params: Airdrop) -> Result<()> {
    info!("Processing ERC20 {:?}...", params);

    if params.amount > config::web3_max_amount() {
        return Err(eyre!(
            "Requested value {} exceeds the limit {}",
            params.amount,
            config::web3_max_amount()
        ));
    }

    let admin_key: SecretKey = config::web3_private_key().parse()?;
    let http = web3::transports::Http::new(&config::web3_rpc_url())?;
    let web3 = web3::Web3::new(http);

    if TOKENS.write().unwrap().is_empty() {
        init(web3.eth().clone(), config::tokens()).await?;
    }

    let recipient = ethereum::address_from_str(&params.wallet)?;
    let amount = U256::from(params.amount);

    for token in &config::tokens() {
        let factor = U256::from(multiplication_factor(token)?);
        let internal_amount = amount
            .checked_mul(factor)
            .ok_or_else(|| eyre!("Overflow {} * {}", amount, factor))?;
        transfer(
            web3.eth(),
            ethereum::address_from_str(token)?,
            token,
            &admin_key,
            recipient,
            internal_amount,
        )
        .await
        .map_err(|e| {
            error!("Failed transfer of token {}: {}", token, e);
            e
        })?;
    }

    Ok(())
}

/// Initializes local cache of tokens properties.
async fn init<T: Transport>(eth: Eth<T>, addresses: Vec<String>) -> Result<()> {
    info!("Checking tokens...");

    for token_address in addresses {
        let a = ethereum::address_from_str(&token_address)?;
        TOKENS.write().unwrap().insert(
            token_address,
            Token::new(get_decimals(eth.clone(), a).await?),
        );
    }

    info!("All tokens are deployed and sane");
    Ok(())
}

/// Creates and sends a transfer transaction.
async fn transfer<T: Transport>(
    eth: Eth<T>,
    token: ethereum::Address,
    token_name: &str,
    admin_key: impl Key + std::fmt::Debug,
    recipient: ethereum::Address,
    amount: U256,
) -> web3::contract::Result<()> {
    info!(
        "Transfer {} of token {} -> {}",
        amount, token_name, recipient
    );
    let token =
        Contract::from_json(eth, token, include_bytes!("../erc20/ERC20.abi")).map_err(|e| {
            error!("Failed reading ERC20.abi: {}", e);
            e
        })?;

    info!(
        "Sending transaction for transfer of token {}...",
        token_name
    );
    token
        .signed_call_with_confirmations(
            "transfer",
            (recipient, amount),
            Options::default(),
            0, // confirmations
            admin_key,
        )
        .await
        .map_err(|e| {
            error!("Failed signed_call_with_confirmations: {}", e);
            e
        })?;

    info!("OK");
    Ok(())
}

async fn get_decimals<T: Transport>(
    eth: Eth<T>,
    token_address: ethereum::Address,
) -> web3::contract::Result<u32> {
    let token = Contract::from_json(eth, token_address, include_bytes!("../erc20/ERC20.abi"))
        .map_err(|e| {
            error!("Failed reading ERC20.abi: {}", e);
            e
        })?;

    let decimals = token
        .query("decimals", (), None, Options::default(), None)
        .await?;
    info!("ERC20 token {} has decimals {}", token_address, decimals);

    Ok(decimals)
}

/// Returns multiplication factor to convert whole token value to fractions.
fn multiplication_factor(token_address: &str) -> Result<u64> {
    let decimals = {
        TOKENS
            .read()
            .unwrap()
            .get(token_address)
            .ok_or_else(|| eyre!("Token info in cache not found: {}", token_address))?
            .decimals
    };
    let factor = 10_u64
        .checked_pow(decimals)
        .ok_or_else(|| eyre!("Token {} overflow 10^{}", token_address, decimals))?;
    Ok(factor)
}

#[derive(new, Debug, Default, Clone)]
struct Token {
    decimals: u32,
}

type Tokens = std::collections::HashMap<String, Token>;

lazy_static::lazy_static! {
    static ref TOKENS: RwLock<Tokens> = RwLock::new(Tokens::default());
}
