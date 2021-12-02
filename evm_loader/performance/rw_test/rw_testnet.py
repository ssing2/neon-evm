import argparse

from solana_utils import *
from web3.auto import w3

solana_url = os.environ.get("SOLANA_URL", "http://localhost:8899")
client = Client(solana_url)
CONTRACTS_DIR = os.environ.get("CONTRACTS_DIR", "")
evm_loader_id = os.environ.get("EVM_LOADER")
ETH_TOKEN_MINT_ID: PublicKey = PublicKey(os.environ.get("ETH_TOKEN_MINT"))
senders_file = "sender.json"
wallet_file = "wallet.json"
chain_id_testnet = 245022940

class init_wallet():
    def __init__(cls, count):

        senders = []
        with open(senders_file, mode='r') as f:
            keypairs = f.readlines()
            for keypair in keypairs:
                acc = Account(bytes.fromhex(keypair[0:64]))
                senders.append(acc)
                # print(acc.public_key())

        private_key = senders[count].secret_key()
        public_key = senders[count].public_key()
        keypair = []
        for i in private_key:
            keypair.append(i)
        for i in bytes(public_key):
            keypair.append(i)
        with open(wallet_file+args.postfix, mode='w') as f:
            f.write(f"{keypair}")

        print("\nload_testnet init")
        print("sender:", senders[count].public_key())
        print("postfix:", count)
        wallet = PreparedAccount(senders[count])

        assert (getBalance(wallet.get_acc().public_key()) > 0)
        cls.loader = EvmLoader(wallet, evm_loader_id)

        cls.acc = wallet.acc

        cls.caller_eth_pr_key = w3.eth.account.from_key(cls.acc.secret_key())
        cls.caller_ether = bytes.fromhex(cls.caller_eth_pr_key.address[2:])
        (cls.caller, cls.caller_nonce) = cls.loader.ether2program(cls.caller_ether)

        if getBalance(cls.caller) == 0:
            print("Create caller account...")
            _ = cls.loader.createEtherAccount(cls.caller_ether)
            print("Done\n")


        print('Account:', cls.acc.public_key(), bytes(cls.acc.public_key()).hex())
        print("Caller:", cls.caller_ether.hex(), cls.caller_nonce, "->", cls.caller,"({})".format(bytes(PublicKey(cls.caller)).hex()))

        res = solana_cli().call("config set --keypair " + wallet_file+args.postfix + " -C config.yml" + args.postfix + " --commitment=confirmed")

        res = cls.loader.deploy(CONTRACTS_DIR+"rw_lock.binary", config="config.yml" + args.postfix)
        (cls.reId, cls.reId_eth, cls.re_code) = (res['programId'], bytes.fromhex(res['ethereum'][2:]), res['codeId'])

        print ('contract', cls.reId)
        print ('contract_eth', cls.reId_eth.hex())
        print ('contract_code', cls.re_code)



parser = argparse.ArgumentParser(description='rw test.')
parser.add_argument('--postfix', metavar="filename postfix", type=str,  help='0,1,2..', default='')
args = parser.parse_args()

isinstance = init_wallet(int(args.postfix))
code_size = 524288
min_balance = client.get_minimum_balance_for_rent_exemption(code_size, commitment=Confirmed)["result"]
print("Minimum balance required for account {}".format(min_balance))
count = 0
code_account_current = isinstance.re_code

while (True):
    count = count + 1
    print("count", count)
    seed_bin = b58encode(ACCOUNT_SEED_VERSION + os.urandom(20))
    seed = seed_bin.decode('utf8')
    code_account_new = accountWithSeed(isinstance.acc.public_key(), seed, PublicKey(evm_loader_id))


    trx = Transaction()
    trx.add( createAccountWithSeed(isinstance.acc.public_key(), isinstance.acc.public_key(), seed, min_balance, code_size, PublicKey(evm_loader_id)) )
    print("new code account:", code_account_new)

    resize_instr = TransactionInstruction(
        keys=[
            AccountMeta(pubkey=isinstance.reId, is_signer=False, is_writable=True),
            AccountMeta(pubkey=code_account_current, is_signer=False, is_writable=True),
            AccountMeta(pubkey=code_account_new, is_signer=False, is_writable=True),
            AccountMeta(pubkey=isinstance.acc.public_key(), is_signer=True, is_writable=False)
        ],
        program_id=evm_loader_id,
        data=bytearray.fromhex("11") + bytes(seed_bin)  # 17- ResizeStorageAccount
    )

    trx.add(resize_instr)
    res = send_transaction(client, trx, isinstance.acc)
    print(res['result'])
    print("")
    code_account_current = code_account_new
