from solana.rpc.api import Client
from solana.rpc.types import TxOpts
from solana.account import Account
from solana.transaction import AccountMeta, TransactionInstruction, Transaction

solana_url = "http://neon.testnet.rpcpool.com/c7710a7b633cbadb9be9900c7946/"
evm_loader_id = "eeLSJgWzzxrqKv1UxtRVVH8FX3qCQWUs9QuAjJpETGU"
client = Client(solana_url)

sender = Account(bytes.fromhex("1338c8c2f08198a70df3a0b80d873fe7b3fdbedc18836754400a27d797fc2c0e"))
print("sender:", sender.public_key())
print("balance:", client.get_balance(sender.public_key())['result']['value']/10**9, "SOL")

trx_count = 0

# while True:
while trx_count < 1:
    trx_count = trx_count + 1
    print("trx count", trx_count)

    trx = Transaction()
    instr_count = 0
    while instr_count < 213:
    # while instr_count < 100:
        instr_count = instr_count + 1

        instr = TransactionInstruction(
            keys=[AccountMeta(pubkey=sender.public_key(), is_signer=True, is_writable=False)],
            program_id=evm_loader_id,
            data=bytearray.fromhex("18")    # 0x18 = 24- MaxBpfInstructionConsumedBySyscalls
        )
        trx.add(instr)

    res = client.send_transaction(trx, sender, opts=TxOpts(skip_confirmation=False))
    print(res)
