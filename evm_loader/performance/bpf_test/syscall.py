import argparse

from solana_utils import *
from web3.auto import w3

solana_url = os.environ.get("SOLANA_URL", "http://localhost:8899")
client = Client(solana_url)
evm_loader_id = os.environ.get("EVM_LOADER")
senders_file = "sender.json"
chain_id = 245022940

class init_wallet():
    def __init__(cls, count):
        print("\nsyscall.py init")

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


def get_trx(to, caller_eth, input, pr_key, value):
    tx = {'to': to, 'value': value, 'gas': 9999999999, 'gasPrice': 10**9,
          'nonce': 0, 'data': input, 'chainId': chain_id}
    (from_addr, sign, msg) = make_instruction_data_from_tx(tx, pr_key)

    assert (from_addr == caller_eth)
    return (from_addr, sign, msg)


parser = argparse.ArgumentParser(description='sending transactions contained a max_bpf instructions consumed by syscalls.')
parser.add_argument('--postfix', metavar="filename postfix", type=str,  help='0,1,2..', default='')
args = parser.parse_args()

instance = init_wallet(int(args.postfix))

count = 0


# while True:
while count < 1:
    count = count + 1
    print("count", count)

    instrucion_cnt = 0
    trx = Transaction()

    caller_eth_pr_key = w3.eth.account.from_key(os.urandom(32))
    caller_ether = bytes.fromhex(caller_eth_pr_key.address[2:])

    (from_addr, sign, unsigned_msg) = get_trx(
        os.urandom(20),
        caller_ether,
        '',
        bytes.fromhex(caller_eth_pr_key.privateKey.hex()[2:]),
        0)

    while instrucion_cnt < 1:
        instrucion_cnt = instrucion_cnt + 1

        resize_instr = TransactionInstruction(
            keys=[
                AccountMeta(pubkey=instance.acc.public_key(), is_signer=True, is_writable=False)
            ],
            program_id=evm_loader_id,
            # 0x18 = 24- MaxBpfInstructionConsumedBySyscalls
            data=bytearray.fromhex("18") + sign + len(unsigned_msg).to_bytes(8, byteorder="little") + unsigned_msg
        )

        trx.add(resize_instr)

    res = send_transaction(client, trx, instance.acc)
    print(res['result'])
    print("")
