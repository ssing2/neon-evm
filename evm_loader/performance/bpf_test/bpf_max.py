import argparse

from solana_utils import *

solana_url = os.environ.get("SOLANA_URL", "http://localhost:8899")
client = Client(solana_url)
evm_loader_id = os.environ.get("EVM_LOADER")
senders_file = "sender.json"

class init_wallet():
    def __init__(cls, count):
        print("\nbpf_max.py init")

        senders = []
        with open(senders_file, mode='r') as f:
            keypairs = f.readlines()
            for keypair in keypairs:
                acc = Account(bytes.fromhex(keypair[0:64]))
                senders.append(acc)
                # print(acc.public_key())

        wallet = PreparedAccount(senders[count])
        cls.acc = wallet.acc
        print("postfix:", count)

        assert (getBalance(cls.acc.public_key()) > 8*10**9)


parser = argparse.ArgumentParser(description='bpf_max.')
parser.add_argument('--postfix', metavar="filename postfix", type=str,  help='0,1,2..', default='')
args = parser.parse_args()

instance = init_wallet(int(args.postfix))
code_size = 565000
min_balance = client.get_minimum_balance_for_rent_exemption(code_size, commitment=Confirmed)["result"]
print("Minimum balance required for account {}".format(min_balance))

seed_bin1 = b58encode(ACCOUNT_SEED_VERSION + os.urandom(20))
seed1 = seed_bin1.decode('utf8')
account1 = accountWithSeed(instance.acc.public_key(), seed1, PublicKey(evm_loader_id))

seed_bin2 = b58encode(ACCOUNT_SEED_VERSION + os.urandom(20))
seed2 = seed_bin2.decode('utf8')
account2 = accountWithSeed(instance.acc.public_key(), seed2, PublicKey(evm_loader_id))

trx = Transaction()
trx.add(createAccountWithSeed(instance.acc.public_key(), instance.acc.public_key(), seed1, min_balance, code_size, PublicKey(evm_loader_id)))
trx.add(createAccountWithSeed(instance.acc.public_key(), instance.acc.public_key(), seed2, min_balance, code_size, PublicKey(evm_loader_id)))
send_transaction(client, trx, instance.acc)
assert (getBalance(account1) >0)
assert (getBalance(account2) >0)
print("src_account, dst_account were created:", account1, account2)

count = 0

while True:
    count = count + 1
    print("count", count)

    instrucion_cnt = 0
    trx = Transaction()

    while instrucion_cnt < 143:
        instrucion_cnt = instrucion_cnt + 1

        resize_instr = TransactionInstruction(
            keys=[
                AccountMeta(pubkey=account1, is_signer=False, is_writable=False),
                AccountMeta(pubkey=account2, is_signer=False, is_writable=True),
                AccountMeta(pubkey=instance.acc.public_key(), is_signer=True, is_writable=False)
            ],
            program_id=evm_loader_id,
            data=bytearray.fromhex("17")  # 23- MaxBpfInstruction
        )

        trx.add(resize_instr)

    res = send_transaction(client, trx, instance.acc)
    print(res['result'])
    print("")
