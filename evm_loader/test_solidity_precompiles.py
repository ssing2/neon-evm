from solana.publickey import PublicKey
from solana.transaction import AccountMeta, TransactionInstruction, Transaction
import unittest
from eth_utils import abi
from base58 import b58decode
import re

from eth_tx_utils import make_keccak_instruction_data, make_instruction_data_from_tx
from solana_utils import *

CONTRACTS_DIR = os.environ.get("CONTRACTS_DIR", "evm_loader/")
evm_loader_id = os.environ.get("EVM_LOADER")

class EvmLoaderTestsNewAccount(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\ntest_delete_account.py setUpClass")

        wallet = WalletAccount(wallet_path())
        cls.loader = EvmLoader(wallet, evm_loader_id)
        cls.acc = wallet.get_acc()

        # Create ethereum account for user account
        cls.caller_ether = eth_keys.PrivateKey(cls.acc.secret_key()).public_key.to_canonical_address()
        (cls.caller, cls.caller_nonce) = cls.loader.ether2program(cls.caller_ether)

        if getBalance(cls.caller) == 0:
            print("Create caller account...")
            _ = cls.loader.createEtherAccount(cls.caller_ether)
            print("Done\n")

        print('Account:', cls.acc.public_key(), bytes(cls.acc.public_key()).hex())
        print("Caller:", cls.caller_ether.hex(), cls.caller_nonce, "->", cls.caller,
              "({})".format(bytes(PublicKey(cls.caller)).hex()))

        print("deploy contract: ")
        program_and_code = cls.loader.deployChecked(
                CONTRACTS_DIR+'SolidityPrecompilesTest.binary',
                cls.caller,
                cls.caller_ether
            )
        cls.owner_contract = program_and_code[0]
        cls.contract_code = program_and_code[2]
        print("contract id: ", cls.owner_contract, solana2ether(cls.owner_contract).hex())
        print("code id: ", cls.contract_code)

        with open(CONTRACTS_DIR+"precompiles_testdata.json") as json_data:
            cls.test_data = json.load(json_data)
            json_data.close()

    def extract_measurements_from_receipt(self, receipt):
        log_messages = receipt['result']['meta']['logMessages']
        transaction = receipt['result']['transaction']
        accounts = transaction['message']['accountKeys']
        instructions = []
        for instr in transaction['message']['instructions']:
            program = accounts[instr['programIdIndex']]
            instructions.append({
                'accs': [accounts[acc] for acc in instr['accounts']],
                'program': accounts[instr['programIdIndex']],
                'data': b58decode(instr['data']).hex()
            })

        pattern = re.compile('Program ([0-9A-Za-z]+) (.*)')
        messages = []
        for log in log_messages:
            res = pattern.match(log)
            if res:
                (program, reason) = res.groups()
                if reason == 'invoke [1]': messages.append({'program':program,'logs':[]})
            messages[-1]['logs'].append(log)

        for instr in instructions:
            if instr['program'] in ('KeccakSecp256k11111111111111111111111111111',): continue
            if messages[0]['program'] != instr['program']:
                raise Exception('Invalid program in log messages: expect %s, actual %s' % (messages[0]['program'], instr['program']))
            instr['logs'] = messages.pop(0)['logs']
            exit_result = re.match(r'Program %s (success)'%instr['program'], instr['logs'][-1])
            if not exit_result: raise Exception("Can't get exit result")
            instr['result'] = exit_result.group(1)

            if instr['program'] == evm_loader_id:
                memory_result = re.match(r'Program log: Total memory occupied: ([0-9]+)', instr['logs'][-3])
                instruction_result = re.match(r'Program %s consumed ([0-9]+) of ([0-9]+) compute units'%instr['program'], instr['logs'][-2])
                if not (memory_result and instruction_result):
                    raise Exception("Can't parse measurements for evm_loader")
                instr['measurements'] = {
                        'instructions': instruction_result.group(1),
                        'memory': memory_result.group(1)
                    }

        result = []
        for instr in instructions:
            if instr['program'] == evm_loader_id:
                result.append({
                        'program':instr['program'],
                        'measurements':instr['measurements'],
                        'result':instr['result'],
                        'data':instr['data']
                    })
        return result

    def get_measurements(self, result):
        measurements = self.extract_measurements_from_receipt(result)
        for m in measurements: print(json.dumps(m))

    def make_transactions(self, call_data):
        eth_tx = {
            'to': solana2ether(self.owner_contract),
            'value': 0,
            'gas': 9999999,
            'gasPrice': 1,
            'nonce': getTransactionCount(client, self.caller),
            'data': call_data,
            'chainId': 111
        }

        (_from_addr, sign, msg) = make_instruction_data_from_tx(eth_tx, self.acc.secret_key())
        trx_data = self.caller_ether + sign + msg
        keccak_instruction = make_keccak_instruction_data(1, len(msg))
        
        solana_trx = Transaction().add(
                self.sol_instr_keccak(keccak_instruction) 
            ).add( 
                self.sol_instr_call(trx_data) 
            )

        return solana_trx

    def sol_instr_keccak(self, keccak_instruction):
        return  TransactionInstruction(program_id="KeccakSecp256k11111111111111111111111111111", data=keccak_instruction, keys=[
                    AccountMeta(pubkey=self.caller, is_signer=False, is_writable=False),
                ])

    def sol_instr_call(self, trx_data):
        return TransactionInstruction(program_id=self.loader.loader_id, data=bytearray.fromhex("05") + trx_data, keys=[
                    AccountMeta(pubkey=self.owner_contract, is_signer=False, is_writable=True),
                    AccountMeta(pubkey=self.contract_code, is_signer=False, is_writable=True),
                    AccountMeta(pubkey=self.caller, is_signer=False, is_writable=True),
                    AccountMeta(pubkey=PublicKey("Sysvar1nstructions1111111111111111111111111"), is_signer=False, is_writable=False),
                    AccountMeta(pubkey=self.loader.loader_id, is_signer=False, is_writable=False),
                    AccountMeta(pubkey=PublicKey("SysvarC1ock11111111111111111111111111111111"), is_signer=False, is_writable=False),
                ])

    def make_ecrecover(self, data):
        return abi.function_signature_to_4byte_selector('test_01_ecrecover(bytes32, uint8, bytes32, bytes32)')\
                + bytes.fromhex("%062x" % 0x0 + "20") \
                + bytes.fromhex("%064x" % len(data))\
                + data.to_bytes()

    def make_sha256(self, data):
        return abi.function_signature_to_4byte_selector('test_02_sha256(bytes)')\
                + bytes.fromhex("%062x" % 0x0 + "20") \
                + bytes.fromhex("%064x" % len(data))\
                + str.encode(data)

    def make_ripemd160(self, data):
        return abi.function_signature_to_4byte_selector('test_03_ripemd160(bytes)')\
                + bytes.fromhex("%062x" % 0x0 + "20") \
                + bytes.fromhex("%064x" % len(data))\
                + str.encode(data)

    def make_callData(self, data):
        return abi.function_signature_to_4byte_selector('test_04_dataCopy(bytes)')\
                + bytes.fromhex("%062x" % 0x0 + "20") \
                + bytes.fromhex("%064x" % len(data))\
                + str.encode(data)

    def make_blake2F(self, data):
        return abi.function_signature_to_4byte_selector('test_09_blake2F(bytes)')\
                + bytes.fromhex("%062x" % 0x0 + "20") \
                + bytes.fromhex("%064x" % len(data)) \
                + data

    def test_09_blake2F_contract(self):
        for test_case in self.test_data["blake2F"]:
            print("make_blake2F() - test case ", test_case["Name"])
            bin_input = bytes.fromhex(test_case["Input"])
            trx = self.make_transactions(self.make_blake2F(bin_input))
            result = send_transaction(client, trx, self.acc)
            self.get_measurements(result)
            result = result["result"]
            result_data = b58decode(result['meta']['innerInstructions'][0]['instructions'][0]['data'])[2:].hex()
            self.assertEqual(result_data, test_case["Expected"])

if __name__ == '__main__':
    unittest.main()
