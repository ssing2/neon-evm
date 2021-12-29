from tools import *

account_unminted_file = "account_unminted.json"
pair_file =  "contracts/uniswap/pair.bin"
user_tools_file = "contracts/uniswap/UserTools.binary"

factory_eth = "12993d55b96db38947d12753F6CE09Ab9Fe721A7"
router_eth = "F9Ae97799ceFe456130CC9F3e4deB817Cf7869ab"
weth_eth = "9D6A7a98721437Ae59D4b8253e80eBc642196d56"


def periphery_contracts(instance):

    (weth_sol, _)  = instance.loader.ether2program(weth_eth)
    (factory_sol, _)  = instance.loader.ether2program(factory_eth)
    (router_sol, _)  = instance.loader.ether2program(router_eth)

    data = getAccountData(client, weth_sol, ACCOUNT_INFO_LAYOUT.sizeof())
    weth_code = PublicKey(ACCOUNT_INFO_LAYOUT.parse(data).code_account)

    data = getAccountData(client, factory_sol, ACCOUNT_INFO_LAYOUT.sizeof())
    factory_code = PublicKey(ACCOUNT_INFO_LAYOUT.parse(data).code_account)

    data = getAccountData(client, router_sol, ACCOUNT_INFO_LAYOUT.sizeof())
    router_code = PublicKey(ACCOUNT_INFO_LAYOUT.parse(data).code_account)

    info = {}
    info['weth'] = (weth_sol, weth_eth, str(weth_code))
    info['factory'] = (factory_sol, factory_eth, str(factory_code))
    info['router'] = (router_sol, router_eth, str(router_code))
    return json.dumps(info)


def create_account_swap(args):
    print ("create_account_swap")
    instance = init_wallet()

    ether_accounts = []
    receipt_list = []
    pr_key_list = {}

    total = 0
    confirmed = 0

    to_file = []
    while confirmed < args.count:

        pr_key = w3.eth.account.from_key(os.urandom(32))
        acc_eth = bytes().fromhex(pr_key.address[2:])

        (transaction, acc_sol) = instance.loader.createEtherAccountTrx(acc_eth)
        param = spl_token.TransferParams(
            program_id=TOKEN_PROGRAM_ID,
            source=instance.wallet_token,
            dest=get_associated_token_address(PublicKey(acc_sol), ETH_TOKEN_MINT_ID),
            owner=instance.acc.public_key(),
            amount=10 ** 9
        )

        trx = Transaction()
        trx.add(transaction)
        trx.add(spl_token.transfer(param))

        res = client.send_transaction(trx, instance.acc,
                                      opts=TxOpts(skip_confirmation=True, skip_preflight=False, preflight_commitment="confirmed"))
        receipt_list.append((acc_sol, acc_eth, pr_key, res['result']))

        total = total + 1
        if total % 5 == 0 :
            for (acc_sol, acc_eth, pr_key, receipt) in receipt_list:
                try:
                    confirm_transaction_(client, receipt)
                    res = client.get_confirmed_transaction(receipt)
                    if res['result'] == None:
                        print("createEtherAccount, get_confirmed_transaction() error")
                    else:
                        # print( acc_sol, acc_eth.hex())
                        to_file.append((acc_sol, acc_eth, pr_key))
                        confirmed = confirmed + 1;
                except:
                    print(f"transaction is lost {receipt}")
            receipt_list = []

    print("\ncreated accounts:", len(to_file))
    print("total requests:", total)

    with open(account_unminted_file + args.postfix, mode='w') as f:
        for (acc_sol, acc_eth, pr_key) in to_file:
            line = {}
            line['address'] = acc_eth.hex()
            line['pr_key'] = pr_key.privateKey.hex()[2:]
            line['account'] = acc_sol
            f.write(json.dumps(line)+ "\n")


def mint_trx(erc20_sol, erc20_eth, erc20_code, account_eth,  sum, instance):
    func_name = abi.function_signature_to_4byte_selector('mint(address,uint256)')

    trx_data = func_name + \
               bytes().fromhex("%024x" % 0 + account_eth) + \
               bytes().fromhex("%064x" % sum)

    (from_addr, sign, msg) = get_trx(
        erc20_eth,
        instance.caller,
        instance.caller_ether,
        trx_data,
        bytes(instance.caller_eth_pr_key),
        0,
    )

    evm_instruction = from_addr + sign + msg

    trx = Transaction()
    trx.add(sol_instr_keccak(make_keccak_instruction_data(1, len(msg), 5)))
    trx.add(
        sol_instr_05(
            evm_loader_id,
            instance.caller,
            instance.acc.public_key(),
            erc20_sol,
            erc20_code,
            (collateral_pool_index_buf).to_bytes(4, 'little'),
            create_collateral_pool_address(collateral_pool_index_buf),
            evm_instruction,
        )
    )
    return trx


def approve_trx(erc20_sol, erc20_eth, erc20_code, spender, sum, caller, caller_eth, caller_pr_key, instance):
    func_name = abi.function_signature_to_4byte_selector('approve(address,uint256)')
    input = func_name +  bytes().fromhex("%024x" % 0 + spender) + bytes().fromhex("%064x" % sum)

    (from_addr, sign, msg) = get_trx(
        erc20_eth,
        caller,
        bytes().fromhex(caller_eth),
        input,
        bytes().fromhex(caller_pr_key),
        0
    )
    evm_instruction = from_addr + sign + msg

    trx = Transaction()
    trx.add(sol_instr_keccak(make_keccak_instruction_data(3, len(msg), 5)))
    trx.add(
        sol_instr_05(
            evm_loader_id,
            caller,
            instance.acc.public_key(),
            erc20_sol,
            erc20_code,
            (collateral_pool_index_buf).to_bytes(4, 'little'),
            create_collateral_pool_address(collateral_pool_index_buf),
            evm_instruction,
        )
    )
    return trx

def check_mint_event(result, erc20_eth, acc_from, acc_to, sum, return_code):
    # assert(result['meta']['err'] == None)

    if (len(result['meta']['innerInstructions']) != 2):
        print("check event Transfer")
        print("len(result['meta']['innerInstructions']) != 2", len(result['meta']['innerInstructions']))
        return False

    if (len(result['meta']['innerInstructions'][0]['instructions']) != 4):
        print(result)
        print("check event Transfer")
        print("len(result['meta']['innerInstructions'][0]['instructions']) != 4",
              len(result['meta']['innerInstructions'][0]['instructions']))
        return False

    data = b58decode(result['meta']['innerInstructions'][0]['instructions'][3]['data'])
    if (data[:1] != b'\x06'):  #  OnReturn
        print("check event Transfer")
        print("data[:1] != x06", data[:1].hex())
        return False

    if(data[1:2] != return_code):    # 11 - Machine encountered an explict stop,  # 12 - Machine encountered an explict return
        print("check event Transfer")
        print("data[1:2] != return_code", data[1:2].hex(), return_code.hex())
        return False

    data = b58decode(result['meta']['innerInstructions'][0]['instructions'][2]['data'])
    if(data[:1] != b'\x07'):  # 7 means OnEvent
        print("check event Transfer")
        print("data[:1] != x07", data[:1].hex())
        return  False


    if (data[1:21] != bytes.fromhex(erc20_eth)):
        print("check event Transfer")
        print("data[1:21] != bytes.fromhex(erc20_eth)", data[1:21].hex(), erc20_eth)
        return False

    if(data[21:29] != bytes().fromhex('%016x' % 3)[::-1]):  # topics len
        print("check event Transfer")
        print("data[21:29] != bytes().fromhex('%016x' % 3)[::-1]", data[21:29].hex())
        return False

    if(data[29:61] != abi.event_signature_to_log_topic('Transfer(address,address,uint256)')):  # topics
        print("check event Transfer")
        print("data[29:61] != abi.event_signature_to_log_topic('Transfer(address,address,uint256)')",
              data[29:61].hex(),
              abi.event_signature_to_log_topic('Transfer(address,address,uint256)').hex())
        return False

    if (data[61:93] != bytes().fromhex("%024x" % 0) + bytes.fromhex(acc_from)):
        print("check event Transfer")
        print("data[61:93] != bytes().fromhex('%024x' % 0) + bytes.fromhex(acc_from)",
              data[61:93].hex(),
              (bytes().fromhex('%024x' % 0) + bytes.fromhex(acc_from)).hex())
        return False

    if(data[93:125] != bytes().fromhex("%024x" % 0) + bytes.fromhex(acc_to)):  # from
        print("check event Transfer")
        print("data[93:125] != bytes().fromhex('%024x' % 0) + bytes.fromhex(acc_to)",
              data[93:125].hex(),
              (bytes().fromhex('%024x' % 0) + bytes.fromhex(acc_to)).hex()
              )
        return False

    if (data[125:157] != bytes().fromhex("%064x" % sum)):  # value
        print("check event Transfer")
        print("data[125:157] != bytes().fromhex('%064x' % sum)",
              data[125:157].hex(),
              '%064x' % sum)
        return False

    return True

def check_approve_event(result, erc20_eth, acc_from, acc_to, sum, return_code):
    # assert(result['meta']['err'] == None)

    if (len(result['meta']['innerInstructions']) != 2):
        print("check event Approval")
        print("len(result['meta']['innerInstructions']) != 2", len(result['meta']['innerInstructions']))
        return False

    if (len(result['meta']['innerInstructions'][1]['instructions']) != 4):
        print("check event Approval")
        print("len(result['meta']['innerInstructions'][1]['instructions']) != 4",
              len(result['meta']['innerInstructions'][1]['instructions']))
        return False

    data = b58decode(result['meta']['innerInstructions'][1]['instructions'][3]['data'])
    if (data[:1] != b'\x06'):  #  OnReturn
        print("check event Approval")
        print("data[:1] != x06", data[:1].hex())
        return False

    if(data[1:2] != return_code):    # 11 - Machine encountered an explict stop,  # 12 - Machine encountered an explict return
        print("check event Approval")
        print("data[1:2] != return_code", data[1:2].hex(), return_code.hex())
        return False

    data = b58decode(result['meta']['innerInstructions'][1]['instructions'][2]['data'])
    if(data[:1] != b'\x07'):  # 7 means OnEvent
        print("check event Approval")
        print("data[:1] != x07", data[:1].hex())
        return  False


    if (data[1:21] != bytes.fromhex(erc20_eth)):
        print("check event Approval")
        print("data[1:21] != bytes.fromhex(erc20_eth)", data[1:21].hex(), erc20_eth)
        return False

    if(data[21:29] != bytes().fromhex('%016x' % 3)[::-1]):  # topics len
        print("check event Approval")
        print("data[21:29] != bytes().fromhex('%016x' % 3)[::-1]", data[21:29].hex())
        return False

    if(data[29:61] != abi.event_signature_to_log_topic('Approval(address,address,uint256)')):  # topics
        print("check event Approval")
        print("data[29:61] != abi.event_signature_to_log_topic('Approval(address,address,uint256)')",
              data[29:61].hex(),
              abi.event_signature_to_log_topic('Approval(address,address,uint256)').hex())
        return False

    if (data[61:93] != bytes().fromhex("%024x" % 0) + bytes.fromhex(acc_from)):
        print(result)
        print("check event Approval")
        print("data[61:93] != bytes().fromhex('%024x' % 0) + bytes.fromhex(acc_from)",
              data[61:93].hex(),
              (bytes().fromhex('%024x' % 0) + bytes.fromhex(acc_from)).hex())
        return False

    if(data[93:125] != bytes().fromhex("%024x" % 0) + bytes.fromhex(acc_to)):  # from
        print("check event Approval")
        print("data[93:125] != bytes().fromhex('%024x' % 0) + bytes.fromhex(acc_to)",
              data[93:125].hex(),
              (bytes().fromhex('%024x' % 0) + bytes.fromhex(acc_to)).hex()
              )
        return False

    if (data[125:157] != bytes().fromhex("%064x" % sum)):  # value
        print("check event Approval")
        print("data[125:157] != bytes().fromhex('%064x' % sum)",
              data[125:157].hex(),
              '%064x' % sum)
        return False

    return True



def mint_account_swap(args):
    instance = init_wallet()
    accounts = []
    contracts = []
    sum = 10**18


    swap_contracts = json.loads(periphery_contracts(instance))
    (router_sol, router_eth, router_code) = swap_contracts['router']


    with open(account_unminted_file+args.postfix, mode='r') as f:
        for line in f:
            accounts.append(line)
    with open(contracts_file+args.postfix, mode='r') as f:
        for line in f:
            contracts.append(line)

    ia = iter(accounts)
    ic = iter(contracts)

    event_error = 0
    total = 0
    to_file = []
    while total < args.count:
        (address, pr_key, account) = get_acc(accounts, ia)
        success = True
        token_pair = []
        for count in range(2): # token_a, token_b
            (erc20_id, erc20_ether, erc20_code) = get_erc20(contracts, ic)
            trx = Transaction()
            trx.add(mint_trx(erc20_id, bytes.fromhex(erc20_ether) , erc20_code, address, sum, instance))
            trx.add(approve_trx(
                    erc20_sol = erc20_id,
                    erc20_eth = bytes().fromhex(erc20_ether),
                    erc20_code = erc20_code,
                    spender = router_eth,
                    sum = sum,
                    caller = account,
                    caller_eth = address,
                    caller_pr_key= pr_key,
                    instance = instance
                    )
            )

            res = client.send_transaction(trx, instance.acc, opts=TxOpts(skip_confirmation=False,  preflight_commitment="confirmed"))

            success = success and  \
            check_mint_event(res['result'], erc20_ether, bytes(20).hex(), address, sum, b'\x11') and \
                      check_approve_event(res['result'], erc20_ether, address, router_eth, sum, b'\x12')

            token_pair.append((erc20_id, erc20_ether, erc20_code))

        if success:
            to_file.append((address, pr_key, account, token_pair))
        else:
            event_error +=1

        total = total + 1
    print("\ntotal", total)
    print("event_error", event_error)

    with open(accounts_file + args.postfix, mode='w') as f:
        for (address, pr_key, account, token_pair) in to_file:
            (token_a_sol, token_a_eth, token_a_code) = token_pair[0]
            (token_b_sol, token_b_eth, token_b_code) = token_pair[1]
            line = {}
            line['address'] = address
            line['pr_key'] = pr_key
            line['account'] = account

            line['token_a_sol'] = token_a_sol
            line['token_a_eth'] = token_a_eth
            line['token_a_code'] = token_a_code

            line['token_b_sol'] = token_b_sol
            line['token_b_eth'] = token_b_eth
            line['token_b_code'] = token_b_code
            f.write(json.dumps(line)+ "\n")



def sol_instr_10_continue(meta, step_count):
    return TransactionInstruction(program_id=evm_loader_id,
                                  data=bytearray.fromhex("0A") + step_count.to_bytes(8, byteorder='little'),
                                  keys=meta)

def create_storage_account(seed, acc):
    storage = PublicKey(
        sha256(bytes(acc.public_key()) + bytes(seed, 'utf8') + bytes(PublicKey(evm_loader_id))).digest())
    print("Storage", storage)

    if getBalance(storage) == 0:
        trx = Transaction()
        trx.add(createAccountWithSeed(acc.public_key(), acc.public_key(), seed, 10 ** 9, 128 * 1024,
                                      PublicKey(evm_loader_id)))
        send_transaction(client, trx, acc)

    return storage


def get_salt(tool_sol, tool_code, tool_eth, token_a, token_b, acc):
    input = bytearray.fromhex("03") + \
            abi.function_signature_to_4byte_selector('get_salt(address,address)') + \
            bytes().fromhex("%024x" % 0 + token_a) + \
            bytes().fromhex("%024x" % 0 + token_b)

    trx = Transaction()
    trx.add(
        TransactionInstruction(
            program_id=evm_loader_id,
            data=input,
            keys=[
                AccountMeta(pubkey=tool_sol, is_signer=False, is_writable=True),
                AccountMeta(pubkey=get_associated_token_address(PublicKey(tool_sol), ETH_TOKEN_MINT_ID), is_signer=False,
                            is_writable=True),
                AccountMeta(pubkey=tool_code, is_signer=False, is_writable=True),
                AccountMeta(pubkey=acc.public_key(), is_signer=True, is_writable=False),
                AccountMeta(pubkey=evm_loader_id, is_signer=False, is_writable=False),
                AccountMeta(pubkey=ETH_TOKEN_MINT_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=PublicKey(sysvarclock), is_signer=False, is_writable=False),
            ]))
    result = send_transaction(client, trx, acc)['result']
    # print(result)
    if result['meta']['err'] != None:
        print(result)
        print("Error: result['meta']['err'] != None")
        exit(1)

    if result == None:
        print("Error: result == None")
        exit(1)

    assert (result['meta']['err'] == None)
    assert (len(result['meta']['innerInstructions']) == 1)
    assert (len(result['meta']['innerInstructions'][0]['instructions']) == 2)
    data = b58decode(result['meta']['innerInstructions'][0]['instructions'][1]['data'])
    assert (data[:1] == b'\x06')  # OnReturn
    assert (data[1] == 0x11)  # 11 - Machine encountered an explict stop

    data = b58decode(result['meta']['innerInstructions'][0]['instructions'][0]['data'])
    assert (data[:1] == b'\x07')  # 7 means OnEvent
    assert (data[1:21] == tool_eth)
    assert (data[21:29] == bytes().fromhex('%016x' % 1)[::-1])  # topics len
    hash = data[61:93]
    return hash


def create_account_with_seed (acc, seed, storage_size):
    account = accountWithSeed(acc.public_key(), seed, PublicKey(evm_loader_id))
    print("HOLDER ACCOUNT:", account)
    if getBalance(account) == 0:
        trx = Transaction()
        trx.add(createAccountWithSeed(acc.public_key(), acc.public_key(), seed, 10 ** 9, storage_size,
                                      PublicKey(evm_loader_id)))
        send_transaction(client, trx, acc)
    return account


def write_layout(offset, data):
    return (bytes.fromhex("00000000")+
            offset.to_bytes(4, byteorder="little")+
            len(data).to_bytes(8, byteorder="little")+
            data)


def write_trx_to_holder_account(acc, holder, sign, unsigned_msg):
    msg = sign + len(unsigned_msg).to_bytes(8, byteorder="little") + unsigned_msg

    # Write transaction to transaction holder account
    offset = 0
    receipts = []
    rest = msg
    while len(rest):
        (part, rest) = (rest[:1000], rest[1000:])
        trx = Transaction()
        # logger.debug("sender_sol %s %s %s", sender_sol, holder, acc.public_key())
        trx.add(TransactionInstruction(program_id=evm_loader_id,
                                       data=write_layout(offset, part),
                                       keys=[
                                           AccountMeta(pubkey=holder, is_signer=False, is_writable=True),
                                           AccountMeta(pubkey=acc.public_key(), is_signer=True, is_writable=False),
                                       ]))
        receipts.append(client.send_transaction(trx, acc, opts=TxOpts(skip_confirmation=True, preflight_commitment=Confirmed))["result"])
        offset += len(part)
    print("receipts %s", receipts)
    for rcpt in receipts:
        confirm_transaction(client, rcpt)
        print("confirmed: %s", rcpt)

    return holder


def create_pair(tools_sol, tools_code, tools_eth, token_a_eth, token_b_eth, instance):
    with open(pair_file, mode='rb') as f:
        hash = Web3.keccak(f.read())
    salt = get_salt(tools_sol, tools_code, tools_eth, token_a_eth, token_b_eth, instance.acc)

    pair_eth = bytes(Web3.keccak(b'\xff' + bytes.fromhex(factory_eth) + salt + hash)[-20:])
    (pair_sol, _) = instance.loader.ether2program(pair_eth)

    if getBalance(pair_sol) == 0:
        seed = b58encode(bytes.fromhex(pair_eth.hex()))
        pair_code = accountWithSeed(instance.acc.public_key(), str(seed, 'utf8'), PublicKey(evm_loader_id))
    else:
        data = getAccountData(client, pair_sol, ACCOUNT_INFO_LAYOUT.sizeof())
        pair_code = PublicKey(ACCOUNT_INFO_LAYOUT.parse(data).code_acc)
    print("\npair_info.code_acc",pair_code, "\n")



    # (pair_code, _) = instance.loader.ether2seed(pair_eth)
    print("")
    print("pair_sol", pair_sol)
    print("pair_eth", pair_eth.hex())
    print("pair_code", pair_code)
    print("")

    trx = Transaction()
    if getBalance(pair_code) == 0:
        trx.add(
            createAccountWithSeed(
                instance.acc.public_key(),
                instance.acc.public_key(),
                str(seed, 'utf8'),
                10 ** 9,
                20000,
                PublicKey(evm_loader_id))
        )
    if getBalance(pair_sol) == 0:
        trx.add(instance.loader.createEtherAccountTrx(pair_eth, code_acc=pair_code)[0])

    if len(trx.instructions):
        res = send_transaction(client, trx, instance.acc)

    return (pair_sol, pair_eth, pair_code)


def call_signed(self, input):
    (from_addr, sign, msg, nonce) = self.get_call_parameters(input)

    trx = Transaction()
    trx.add(self.sol_instr_keccak(make_keccak_instruction_data(1, len(msg), 5)))
    trx.add(self.sol_instr_05(from_addr + sign + msg))
    return send_transaction(client, trx, self.acc)["result"]


def create_storage_account(self, seed):
    storage = PublicKey(sha256(bytes(self.acc.public_key()) + bytes(seed, 'utf8') + bytes(PublicKey(evm_loader_id))).digest())
    print("Storage", storage)

    if getBalance(storage) == 0:
        trx = Transaction()
        trx.add(createAccountWithSeed(self.acc.public_key(), self.acc.public_key(), seed, 10**9, 128*1024, PublicKey(evm_loader_id)))
        send_transaction(client, trx, self.acc)

    return storage


def add_liquidity(args):
    instance = init_wallet()
    senders = init_senders(args)

    res = solana_cli().call("config set --keypair " + instance.keypath + " -C config.yml"+args.postfix)

    contracts = json.loads(periphery_contracts(instance))
    (weth_sol, weth_eth, weth_code) = contracts['weth']
    (factory_sol, factory_eth, factory_code)= contracts['factory']
    (router_sol, router_eth, router_code) = contracts['router']


    res = solana_cli().call("config set --keypair " + instance.keypath + " -C config.yml" + args.postfix)
    res = instance.loader.deploy(user_tools_file, caller=instance.caller, config="config.yml" + args.postfix)

    (tools_sol, tools_eth, tools_code) = (res['programId'], bytes.fromhex(res['ethereum'][2:]), res['codeId'])

    holder = create_account_with_seed(instance.acc, os.urandom(5).hex(), 128 * 1024)

    with open(accounts_file+args.postfix, mode='r') as f:
        accounts = json.loads(f.read())

    total = 0
    ok  = 0
    func_name = abi.function_signature_to_4byte_selector('addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)')

    sum = 10**18
    to_file = []

    storage = create_storage_account(os.urandom(10).hex(), instance.acc)
    for (msg_sender_eth, msg_sender_prkey, msg_sender_sol, token_a_sol, token_a_eth, token_a_code, token_b_sol, token_b_eth, token_b_code) in accounts:
        if total >= args.count:
            break
        total = total + 1

        print (" ")
        print ("add_liquidity:", total)
        print (" token_a_eth",token_a_eth)
        print (" token_b_eth",token_b_eth)

        input = func_name + \
                   bytes().fromhex("%024x" % 0 + token_a_eth) + \
                   bytes().fromhex("%024x" % 0 + token_b_eth) + \
                   bytes().fromhex("%064x" % sum) +\
                   bytes().fromhex("%064x" % sum) +\
                   bytes().fromhex("%064x" % sum) +\
                   bytes().fromhex("%064x" % sum) + \
                   bytes().fromhex("%024x" % 0 + msg_sender_eth) + \
                   bytes().fromhex("%064x" % 10**18)

        (from_addr, sign, msg) = get_trx(
            bytes().fromhex(router_eth),
            msg_sender_sol,
            bytes().fromhex(msg_sender_eth),
            input,
            bytes.fromhex(msg_sender_prkey),
            0)

        acc = senders.next_acc()

        print("WRITE TO HOLDER ACCOUNT")
        write_trx_to_holder_account(instance.acc, holder, sign, msg)

        (pair_sol, pair_eth, pair_code) = create_pair(
            tools_sol, tools_code, tools_eth, token_a_eth, token_b_eth, instance)

        meta = [
            AccountMeta(pubkey=holder, is_signer=False, is_writable=True),
            AccountMeta(pubkey=storage, is_signer=False, is_writable=True),

            AccountMeta(pubkey=router_sol, is_signer=False, is_writable=True),
            AccountMeta(pubkey=get_associated_token_address(PublicKey(router_sol), ETH_TOKEN_MINT_ID), is_signer=False, is_writable=True),
            AccountMeta(pubkey=router_code, is_signer=False, is_writable=True),

            AccountMeta(pubkey=msg_sender_sol, is_signer=False, is_writable=True),
            AccountMeta(pubkey=get_associated_token_address(PublicKey(msg_sender_sol), ETH_TOKEN_MINT_ID), is_signer=False, is_writable=True),

            AccountMeta(pubkey=token_a_sol, is_signer=False, is_writable=True),
            AccountMeta(pubkey=get_associated_token_address(PublicKey(token_a_sol), ETH_TOKEN_MINT_ID), is_signer=False, is_writable=True),
            AccountMeta(pubkey=token_a_code, is_signer=False, is_writable=True),

            AccountMeta(pubkey=token_b_sol, is_signer=False, is_writable=True),
            AccountMeta(pubkey=get_associated_token_address(PublicKey(token_b_sol), ETH_TOKEN_MINT_ID), is_signer=False,is_writable=True),
            AccountMeta(pubkey=token_b_code, is_signer=False, is_writable=True),

            AccountMeta(pubkey=factory_sol, is_signer=False, is_writable=True),
            AccountMeta(pubkey=get_associated_token_address(PublicKey(factory_sol), ETH_TOKEN_MINT_ID), is_signer=False,is_writable=True),
            AccountMeta(pubkey=factory_code, is_signer=False, is_writable=True),

            AccountMeta(pubkey=pair_sol, is_signer=False, is_writable=True),
            AccountMeta(pubkey=get_associated_token_address(PublicKey(pair_sol), ETH_TOKEN_MINT_ID), is_signer=False,is_writable=True),
            AccountMeta(pubkey=pair_code, is_signer=False, is_writable=True),

            AccountMeta(pubkey=PublicKey(sysinstruct), is_signer=False, is_writable=False),
            AccountMeta(pubkey=evm_loader_id, is_signer=False, is_writable=False),
            AccountMeta(pubkey=PublicKey(sysvarclock), is_signer=False, is_writable=False),
        ]

        print("Begin", total)
        step = 0
        trx = Transaction()
        trx.add(TransactionInstruction(program_id=evm_loader_id, data=bytearray.fromhex("0B") + step.to_bytes(8, byteorder="little"), keys=meta))
        print("ExecuteTrxFromAccountDataIterative:")
        res = send_transaction(client, trx, instance.acc)

        while (True):
            print("Continue")
            trx = Transaction()
            trx.add(sol_instr_10_continue(meta[1:], 2000))
            trx.add(sol_instr_10_continue(meta[1:], 2000))
            # trx.add(sol_instr_10_continue(meta[1:], 2000))
            # trx.add(sol_instr_10_continue(meta[1:], 1000))
            res = send_transaction(client, trx, instance.acc)
            result = res["result"]

            print(result)
            if (result['meta']['innerInstructions'] and result['meta']['innerInstructions'][0]['instructions']):
                data = b58decode(result['meta']['innerInstructions'][0]['instructions'][-1]['data'])
                if (data[0] == 6):
                    print("ok")
                    ok = ok + 1
                    to_file.append((msg_sender_eth, msg_sender_prkey, msg_sender_sol,
                                    token_a_sol, token_a_eth, token_a_code,
                                    token_b_sol, token_b_eth, token_b_code,
                                    str(pair_sol), pair_eth.hex(), str(pair_code)))
                    break;

    print("total", total)
    print("success", ok)
    with open(liquidity_file + args.postfix, mode='w') as f:
        f.write(json.dumps(to_file))


def create_transactions_swap(args):
    instance = init_wallet()
    senders = init_senders(args)

    contracts = json.loads(periphery_contracts(instance))
    (weth_sol, weth_eth, weth_code) = contracts['weth']
    (factory_sol, factory_eth, factory_code)= contracts['factory']
    (router_sol, router_eth, router_code) = contracts['router']


    with open(liquidity_file+args.postfix, mode='r') as f:
        accounts = json.loads(f.read())

    total = 0
    func_name = abi.function_signature_to_4byte_selector('swapExactTokensForTokens(uint256,uint256,address[],address,uint256)')

    storage = create_storage_account(os.urandom(5).hex(), instance.acc)

    sum = 10**18
    transactions = []
    for (msg_sender_eth, msg_sender_prkey, msg_sender_sol, token_a_sol, token_a_eth, token_a_code, token_b_sol, token_b_eth, token_b_code,
         pair_sol, pair_eth, pair_code) in accounts:
        if total >= args.count:
            break
        total = total + 1
        input = func_name + \
                bytes().fromhex("%064x" % sum) +\
                bytes().fromhex("%064x" % 0) +\
                bytes().fromhex("%064x" % 0xa0) +\
                bytes().fromhex("%024x" % 0 + msg_sender_eth) + \
                bytes().fromhex("%064x" % 10**18) + \
                bytes().fromhex("%064x" % 2) + \
                bytes().fromhex("%024x" % 0 + token_a_eth) + \
                bytes().fromhex("%024x" % 0 + token_b_eth)
        print("")
        print("input:", input.hex())
        print("")

        (from_addr, sign, msg) = get_trx(
            bytes().fromhex(router_eth),
            msg_sender_sol,
            bytes().fromhex(msg_sender_eth),
            input,
            bytes.fromhex(msg_sender_prkey),
            0)

        acc = senders.next_acc()
        print("CREATE TO HOLDER ACCOUNT")
        holder = create_account_with_seed(instance.acc, os.urandom(5).hex(), 128 * 1024)
        print("WRITE TO HOLDER ACCOUNT")

        write_trx_to_holder_account(instance.acc, holder, sign, msg)
        transactions.append((holder, msg_sender_eth, msg_sender_prkey, msg_sender_sol, token_a_sol, token_a_eth, token_a_code, token_b_sol, token_b_eth, token_b_code,
         pair_sol, pair_eth, pair_code))


    print("EXECUTE TRX FROM HOLDER ACCOUNT")
    total = 0
    ok  = 0
    start = time.time()
    cycle_times = []


    for (holder, msg_sender_eth, msg_sender_prkey, msg_sender_sol, token_a_sol, token_a_eth, token_a_code, token_b_sol, token_b_eth, token_b_code,
         pair_sol, pair_eth, pair_code) in transactions:
        cycle_start = time.time()

        meta = [
            AccountMeta(pubkey=holder, is_signer=False, is_writable=True),
            AccountMeta(pubkey=storage, is_signer=False, is_writable=True),

            AccountMeta(pubkey=router_sol, is_signer=False, is_writable=True),
            AccountMeta(pubkey=get_associated_token_address(PublicKey(router_sol), ETH_TOKEN_MINT_ID), is_signer=False, is_writable=True),
            AccountMeta(pubkey=router_code, is_signer=False, is_writable=True),

            AccountMeta(pubkey=msg_sender_sol, is_signer=False, is_writable=True),
            AccountMeta(pubkey=get_associated_token_address(PublicKey(msg_sender_sol), ETH_TOKEN_MINT_ID), is_signer=False, is_writable=True),

            AccountMeta(pubkey=token_a_sol, is_signer=False, is_writable=True),
            AccountMeta(pubkey=get_associated_token_address(PublicKey(token_a_sol), ETH_TOKEN_MINT_ID), is_signer=False, is_writable=True),
            AccountMeta(pubkey=token_a_code, is_signer=False, is_writable=True),

            AccountMeta(pubkey=token_b_sol, is_signer=False, is_writable=True),
            AccountMeta(pubkey=get_associated_token_address(PublicKey(token_b_sol), ETH_TOKEN_MINT_ID), is_signer=False,is_writable=True),
            AccountMeta(pubkey=token_b_code, is_signer=False, is_writable=True),

            AccountMeta(pubkey=factory_sol, is_signer=False, is_writable=True),
            AccountMeta(pubkey=get_associated_token_address(PublicKey(factory_sol), ETH_TOKEN_MINT_ID), is_signer=False,is_writable=True),
            AccountMeta(pubkey=factory_code, is_signer=False, is_writable=True),

            AccountMeta(pubkey=pair_sol, is_signer=False, is_writable=True),
            AccountMeta(pubkey=get_associated_token_address(PublicKey(pair_sol), ETH_TOKEN_MINT_ID), is_signer=False,is_writable=True),
            AccountMeta(pubkey=pair_code, is_signer=False, is_writable=True),

            AccountMeta(pubkey=PublicKey(sysinstruct), is_signer=False, is_writable=False),
            AccountMeta(pubkey=evm_loader_id, is_signer=False, is_writable=False),
            AccountMeta(pubkey=PublicKey(sysvarclock), is_signer=False, is_writable=False),
        ]

        instruction = from_addr + sign + msg
        print("Begin", total)
        step = 0
        trx = Transaction()
        trx.add(TransactionInstruction(program_id=evm_loader_id, data=bytearray.fromhex("0B") + step.to_bytes(8, byteorder="little"), keys=meta))
        print("ExecuteTrxFromAccountDataIterative:")
        # res = send_transaction(client, trx, instance.acc, 0)

        while (True):
            print("Continue")
            # trx = Transaction()
            trx.add(sol_instr_10_continue(meta[1:], 1000))
            trx.add(sol_instr_10_continue(meta[1:], 1000))
            trx.add(sol_instr_10_continue(meta[1:], 1000))
            trx.add(sol_instr_10_continue(meta[1:], 1000))
            trx.add(sol_instr_10_continue(meta[1:], 1000))
            res = send_transaction(client, trx, instance.acc, 0)
            result = res["result"]

            print(result)
            if (result['meta']['innerInstructions'] and result['meta']['innerInstructions'][0]['instructions']):
                data = b58decode(result['meta']['innerInstructions'][0]['instructions'][-1]['data'])
                if (data[0] == 6):
                    print("ok")
                    ok = ok + 1
                    break;
        cycle_end = time.time()
        cycle_times.append(cycle_end - cycle_start)


    print("total", total)
    print("success", ok)
    end = time.time()
    print("time:", end - start, "sec")
    print("avg cycle time:                 ", statistics.mean(cycle_times), "sec")



