import os, subprocess, unittest
from web3 import Web3
from solana.publickey import PublicKey
from solcx import compile_source
from solcx import install_solc
from solana.rpc.api import Client
from solana.rpc.commitment import Confirmed
from solana_utils import *
from tools import init_wallet, init_senders, accounts_file, get_trx, liquidity_file
from eth_utils import abi
from uniswap import periphery_contracts
import statistics

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

    (router_sol, router_eth, router_code) = json.loads(periphery_contracts(instance))['router']

    accounts = []
    with open(accounts_file+args.postfix, mode='r') as f:
        for line in f:
            accounts.append(line)

    sum = 10**17
    total = 0
    func_name = abi.function_signature_to_4byte_selector(
        'addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)')
    to_file=[]

    for line in accounts:

        if total >= args.count:
            break
        total = total + 1

        info = json.loads(line)
        print ("\nadd_liquidity:", total, ", token_a:", info["token_a_eth"], ", token_b:", info["token_b_eth"], ", msg.sender:", info["address"])
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

        to_file.append((info["address"], info["pr_key"], info["token_a_eth"], info["token_b_eth"]))

    print("total", total)
    with open(liquidity_file + args.postfix, mode='w') as f:
        for (address, pr_key, token_a_eth, token_b_eth) in to_file:
            line = {}
            line["address"] = address
            line['pr_key'] = pr_key
            line["token_a_eth"] = token_a_eth
            line["token_b_eth"] = token_b_eth
            f.write(json.dumps(line) + '\n')



def swap_proxy(args):
    print("\nswap_proxy")
    instance = init_wallet()

    (router_sol, router_eth, router_code) = json.loads(periphery_contracts(instance))['router']

    liquidity = []
    with open(liquidity_file+args.postfix, mode='r') as f:
        for line in f:
            liquidity.append(line)

    sum = 10**17
    total = 0
    func_name = abi.function_signature_to_4byte_selector('swapExactTokensForTokens(uint256,uint256,address[],address,uint256)')

    start = time.time()
    cycle_times = []

    for line in liquidity:

        if total >= args.count:
            break
        total = total + 1

        cycle_start = time.time()

        info = json.loads(line)
        print ("\nswap:", total, ", token_a:", info["token_a_eth"], ", token_b:", info["token_b_eth"], ", msg.sender:", info["address"])
        input = func_name + \
                bytes().fromhex("%064x" % sum) +\
                bytes().fromhex("%064x" % 0) +\
                bytes().fromhex("%064x" % 0xa0) +\
                bytes().fromhex("%024x" % 0 + info["address"]) + \
                bytes().fromhex("%064x" % 10**18) + \
                bytes().fromhex("%064x" % 2) + \
                bytes().fromhex("%024x" % 0 + info["token_a_eth"]) + \
                bytes().fromhex("%024x" % 0 + info["token_b_eth"])


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

        cycle_end = time.time()
        cycle_times.append(cycle_end - cycle_start)


    print("total:", total)
    print("time:", time.time() - start, "sec")
    print("avg cycle time:", statistics.mean(cycle_times), "sec")
