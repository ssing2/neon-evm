//! Faucet ETH token module.

use color_eyre::eyre::eyre;
use color_eyre::Result;
use tracing::info;

use crate::{config, ethereum, solana};

/// Represents packet of information needed for single airdrop operation.
#[derive(Debug, serde::Deserialize)]
pub struct Airdrop {
    /// Ethereum address of the recipient.
    wallet: String,
    /// Amount of a token to be received.
    amount: u64,
    /// Specifies amount in whole tokens (false, default) or in 10E-9 fractions (true).
    #[serde(default)]
    pub in_fractions: bool,
}

/// Processes the airdrop: sends needed transactions into Solana.
pub async fn airdrop(params: Airdrop) -> Result<()> {
    info!("Processing ETH {:?}...", params);

    let limit = if !params.in_fractions {
        config::solana_max_amount()
    } else {
        solana::convert_whole_to_fractions(config::solana_max_amount())?
    };

    if params.amount > limit {
        return Err(eyre!(
            "Requested value {} exceeds the limit {}",
            params.amount,
            limit
        ));
    }

    let operator = config::solana_operator_keypair()
        .map_err(|e| eyre!("config::solana_operator_keypair: {:?}", e))?;
    let ether_address = ethereum::address_from_str(&params.wallet)
        .map_err(|e| eyre!("ethereum::address_from_str({}): {:?}", &params.wallet, e))?;
    solana::transfer_token(operator, ether_address, params.amount, params.in_fractions)
        .await
        .map_err(|e| {
            eyre!(
                "solana::transfer_token(operator, {}): {:?}",
                ether_address,
                e
            )
        })?;
    Ok(())
}
