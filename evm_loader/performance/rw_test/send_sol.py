import argparse
from solana.system_program import TransferParams, transfer
from solana_utils import *

solana_url = os.environ.get("SOLANA_URL", "http://localhost:8899")
client = Client(solana_url)
senders_file = "sender.json"

class init_wallet():
    def __init__(cls):

        wallet = OperatorAccount()
        assert (getBalance(wallet.get_acc().public_key()) > 0)
        cls.acc = wallet.acc
        print('Account:', cls.acc.public_key(), bytes(cls.acc.public_key()).hex())



parser = argparse.ArgumentParser(description='transfer SOL')
parser.add_argument('--count', metavar="count senders", type=str,  help='0,1,2..', default='')
args = parser.parse_args()

instance = init_wallet()

senders=[]
with open(senders_file, mode='r') as f:
    keypairs = f.readlines()
    for keypair in keypairs:
        acc = Account(bytes.fromhex(keypair[0:64]))
        senders.append(acc)
        # print(acc.public_key())


for sender in senders[0:int(args.count)]:
    param = TransferParams(from_pubkey= instance.acc.public_key(), to_pubkey=sender.public_key(), lamports=13000000000)
    tx = Transaction()
    tx.add(transfer(param))
    res = send_transaction(client, tx, instance.acc)

for sender in senders[0:int(args.count)]:
    print(sender.public_key(), getBalance(sender.public_key())/10**9)

