from solana.transaction import AccountMeta, TransactionInstruction, Transaction
from solana.rpc.types import TxOpts
from solana.rpc.api  import SendTransactionError
import unittest
from base58 import b58decode
from solana_utils import *
from spl.token.constants import TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID, ACCOUNT_LEN
from spl.token.instructions import get_associated_token_address
from eth_tx_utils import make_keccak_instruction_data, make_instruction_data_from_tx
from eth_utils import abi
from web3.auto import w3

solana_url = os.environ.get("SOLANA_URL", "http://localhost:8899")
client = Client(solana_url)
CONTRACTS_DIR = os.environ.get("CONTRACTS_DIR", "load_testnet.py")
evm_loader_id = os.environ.get("EVM_LOADER")
ETH_TOKEN_MINT_ID: PublicKey = PublicKey(os.environ.get("ETH_TOKEN_MINT"))


contract = "6Uu6eoTeAEZf7vfaZW2qN1ZHvvtT4zsn3mp5cukjnnoK"
contract_code = "8DLZZPX2heYJQnTLkqFCE8CjMZm7t8xkFn2SYp78A34K"
contract_token = "6avLgmDaPoQaSSwYhsF6jypZzVFL4v8VH45SfDXtNkDD"
contract_eth = "94067940c13f9aac69be38c66dd1e0265f98193e"
chain_id_testnet = 245022940

class init_wallet():
    def __init__(cls):
        print("\nload_testnet init")

        wallet = OperatorAccount()
        assert (getBalance(wallet.get_acc().public_key()) > 0)

        cls.loader = EvmLoader(wallet, evm_loader_id)
        cls.acc = wallet.get_acc()
        cls.keypath = wallet.get_path()

        cls.caller_eth_pr_key = w3.eth.account.from_key(cls.acc.secret_key())
        cls.caller_ether = bytes.fromhex(cls.caller_eth_pr_key.address[2:])
        (cls.caller, cls.caller_nonce) = cls.loader.ether2program(cls.caller_ether)

        if getBalance(cls.caller) == 0:
            print("Create caller account...")
            _ = cls.loader.createEtherAccount(cls.caller_ether)
            print("Done\n")

        print('Account:', cls.acc.public_key(), bytes(cls.acc.public_key()).hex())
        print("Caller:", cls.caller_ether.hex(), cls.caller_nonce, "->", cls.caller,"({})".format(bytes(PublicKey(cls.caller)).hex()))
        print("Contract:", contract)
        print("Contract code:", contract_code)
        print("Contract token:", contract_token)
        print("Contract eth:", contract_eth)


def get_call_parameters(input, acc, caller, caller_ether):
    nonce = getTransactionCount(client, caller)
    tx = {'to': bytes.fromhex(contract_eth), 'value': 0, 'gas': 99999999, 'gasPrice': 1_000_000_000,
          'nonce': nonce, 'data': input, 'chainId': chain_id_testnet}
    (from_addr, sign, msg) = make_instruction_data_from_tx(tx, acc.secret_key())
    assert (from_addr == caller_ether)
    return (from_addr, sign, msg, nonce)


def create_storage_account( seed, acc):
    storage = PublicKey(sha256(bytes(acc.public_key()) + bytes(seed, 'utf8') + bytes(PublicKey(evm_loader_id))).digest())
    print("Storage", storage)

    if getBalance(storage) == 0:
        trx = Transaction()
        trx.add(createAccountWithSeed(acc.public_key(), acc.public_key(), seed, 10**9, 128*1024, PublicKey(evm_loader_id)))
        send_transaction(client, trx, acc)

    return storage


wallet = init_wallet()

func_name = abi.function_signature_to_4byte_selector('unchange_storage(uint8,uint8)')
input = (func_name + bytes.fromhex("%064x" % 0x1) + bytes.fromhex("%064x" % 0x1))

(from_addr, sign, msg, _) = get_call_parameters(input, wallet.acc, wallet.caller, wallet.caller_ether)

instruction = from_addr + sign + msg

storage = create_storage_account(sign[:8].hex(), wallet.acc)

