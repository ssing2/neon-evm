import os, subprocess, unittest
from web3 import Web3
from solana.publickey import PublicKey
from solcx import compile_source
from solcx import install_solc
from solana.rpc.api import Client
from solana.rpc.commitment import Confirmed
from solana_utils import *
from tools import init_wallet, init_senders, accounts_file, get_trx
from eth_utils import abi
from uniswap import periphery_contracts

CONTRACT='''
pragma solidity >=0.5.16;

    contract UserTools{
    event Salt(bytes32 a);

    function get_salt(address tokenA, address tokenB) public  {
        require(tokenA != tokenB, 'UniswapV2: IDENTICAL_ADDRESSES');
        (address token0, address token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        require(token0 != address(0), 'UniswapV2: ZERO_ADDRESS');
        bytes32 salt = keccak256(abi.encodePacked(token0, token1));
        emit Salt(salt);
    }
}
'''

proxy_url = os.environ.get('PROXY_URL', 'http://127.0.0.1:9090/solana')
solana_url = os.environ.get("SOLANA_URL", "http://127.0.0.1:8899")
evm_loader_id = PublicKey(os.environ.get("EVM_LOADER"))
ETH_TOKEN_MINT_ID: PublicKey = PublicKey(os.environ.get("ETH_TOKEN_MINT", "HPsV9Deocecw3GeZv1FkAPNCBRfuVyfw9MMwjwRe1xaU"))

proxy = Web3(Web3.HTTPProvider(proxy_url))
install_solc(version='0.7.0')

def deploy_user_tools(instance):
    print("\n\ndeploy_user_tools")

    compiled = compile_source(CONTRACT)
    id, interface = compiled.popitem()
    contract = proxy.eth.contract(abi=interface['abi'], bytecode=interface['bin'])
    trx = proxy.eth.account.sign_transaction(dict(
        nonce=proxy.eth.get_transaction_count(instance.caller_ether),
        chainId=proxy.eth.chain_id,
        gas=987654321,
        gasPrice=0,
        to='',
        value=0,
        data=contract.bytecode),
        instance.caller_eth_pr_key.privateKey
    )

    signature = proxy.eth.send_raw_transaction(trx.rawTransaction)
    receipt = proxy.eth.wait_for_transaction_receipt(signature)
    return receipt.contractAddress


def add_liquidity_proxy(args):
    print("\nadd_liquidity_proxy")
    instance = init_wallet()
    sum = 10**18

    # user_tool_address = deploy_user_tools(instance)

    contracts = json.loads(periphery_contracts(instance))
    (router_sol, router_eth, router_code) = contracts['router']

    accounts = []
    with open(accounts_file+args.postfix, mode='r') as f:
        for line in f:
            accounts.append(line)

    total = 0
    for line in accounts:

        if total >= args.count:
            break
        total = total + 1

        info = json.loads(line)
        print(info["token_a_sol"], info["token_a_eth"], info["token_a_code"], info["token_b_sol"], info["token_b_eth"],  info["token_b_code"])

        print (" ")
        print ("add_liquidity:", total)
        print (" token_a_eth", info["token_a_eth"])
        print (" token_b_eth", info["token_b_eth"])

        func_name = abi.function_signature_to_4byte_selector(
            'addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)')

        input = func_name + \
                   bytes().fromhex("%024x" % 0 + info["token_a_eth"]) + \
                   bytes().fromhex("%024x" % 0 + info["token_b_eth"]) + \
                   bytes().fromhex("%064x" % sum) +\
                   bytes().fromhex("%064x" % sum) +\
                   bytes().fromhex("%064x" % sum) +\
                   bytes().fromhex("%064x" % sum) + \
                   bytes().fromhex("%024x" % 0 + info["address"]) + \
                   bytes().fromhex("%064x" % 10**18)

        trx = proxy.eth.account.sign_transaction(dict(
            nonce=proxy.eth.get_transaction_count(bytes.fromhex(info["address"])),
            chainId=proxy.eth.chain_id,
            gas=987654321,
            gasPrice=0,
            to=bytes.fromhex(router_eth),
            value=0,
            data=input),
            bytes.fromhex(info["pr_key"])
        )

        signature = proxy.eth.send_raw_transaction(trx.rawTransaction)
        receipt = proxy.eth.wait_for_transaction_receipt(signature)

