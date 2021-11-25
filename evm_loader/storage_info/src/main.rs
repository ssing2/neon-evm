mod cmd_args;
use solana_program::{keccak::{hash,}};
use solana_sdk::{pubkey::Pubkey, commitment_config::{CommitmentConfig, CommitmentLevel}};
use std::{sync::Arc};
use solana_client::{rpc_client::RpcClient};
use evm_loader::{ account_data::{AccountData,}};
use std::str::FromStr;
use evm::H160;

type Error = Box<dyn std::error::Error>;

#[must_use]
fn keccak256(data: &[u8]) -> [u8; 32] {
    hash(data).to_bytes()
}

fn get_storage_info(
    rpc_client: &Arc<RpcClient>,
    account: &Pubkey
) -> Result<((H160, u64)), Error> {

    let data : Vec<u8>;
    match rpc_client.get_account_with_commitment(account, CommitmentConfig::confirmed())?.value{
        Some(acc) =>   data = acc.data,
        None => return Err("account doesn't exist".into())
    }

    let data = match evm_loader::account_data::AccountData::unpack(&data) {
        Ok(acc_data) =>
            match acc_data {
                AccountData::Storage(acc) => acc,
                AccountData::Empty => return Err ("Account is empty".into()),
                AccountData::FinalizedStorage(acc) => {
                    let msg = "Account is finalized ".to_string() + &acc.sender.to_string();
                    return Err (msg.into())
                },
                _ => return Err("Account is not storage account".into())
            },
        Err(_) => return Err("Account unpack error".into())
    };

    Ok((data.caller, data.nonce))
}


fn main() {

     let (evm_loader,
         json_rpc_url,
         operator
     )
    = cmd_args::parse_program_args();

    let rpc_client = Arc::new(RpcClient::new_with_commitment(json_rpc_url,
                                                             CommitmentConfig::confirmed()));

    println!("");
    for index in 0..8{
        let mut bit_length = 0;

        for pos in  0..8{
            let mask = 1 << pos;
            if index & mask !=0 {
                bit_length +=1;
            }
        }


        let mut seed :Vec<u8> =vec![];
        let str = "storage".to_ascii_lowercase();
        let str_bin = str.as_bytes();
        seed.resize(str_bin.len(), 0);
        seed.copy_from_slice(str_bin);
        if bit_length !=0 {
            seed.push(index);
        }
        let seed_hash: [u8; 32] = keccak256(seed.as_slice());
        let seed_hash_hex = hex::encode(&seed_hash[0..16]).to_ascii_lowercase();

        let storage_sol = Pubkey::create_with_seed(
            &operator,
            &seed_hash_hex,
            &evm_loader).unwrap();

        match get_storage_info(&rpc_client, &storage_sol){
            Ok((caller, nonce)) => println!("{}: {}, {}", storage_sol, caller.to_string(), nonce),
            Err(err) => println!("{}: {}", storage_sol, err)
        }

    }
}
