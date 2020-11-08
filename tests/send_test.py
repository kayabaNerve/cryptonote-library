# Types.
from typing import Dict, List, Tuple, Any

# urandom standard function.
from os import urandom

# sleep standard function.
from time import sleep

# JSON standard lib.
import json

# Transaction/Block classes.
from cryptonote.classes.blockchain import OutputIndex, Transaction, Block

# Address class.
from cryptonote.classes.wallet.address import Address

# Crypto class.
from cryptonote.crypto.monero_crypto import OutputInfo, MoneroCrypto

# RPC class.
from cryptonote.rpc.monero_rpc import MoneroRPC

# Wallet classes.
from cryptonote.classes.wallet.wallet import Wallet, WatchWallet

# Key.
key: bytes = urandom(32)

# Crypto.
crypto: MoneroCrypto = MoneroCrypto(False)

# RPC.
rpc: MoneroRPC = MoneroRPC("127.0.0.1", 28081)

# Wallet.
wallet: Wallet = Wallet(crypto, key)
print("The private spend key is " + wallet.private_spend_key.hex() + ".")
print("The private view key is " + wallet.private_view_key.hex() + ".")

# WatchWallet.
watch: WatchWallet = WatchWallet(
    crypto,
    rpc,
    wallet.private_view_key,
    wallet.public_spend_key,
    rpc.get_block_count() - 1,
)

print("Please specify what account index to use. ")
account: int = int(input())
print("Please specify what address index to use. ")
address: int = int(input())

last: int = rpc.get_block_count()
print("Please deposit to " + watch.new_address((account, address)).address + ".")

spendable: Tuple[List[bytes], Dict[OutputIndex, OutputInfo]]
available: int = 0
waiting: bool = True
while waiting:
    sleep(10)
    current: int = rpc.get_block_count()
    for block in range(last, current):
        for tx in rpc.get_block(rpc.get_block_hash(block)).hashes:
            spendable = watch.can_spend(rpc.get_transaction(tx))
            if spendable[1]:
                for index in spendable[1]:
                    print(
                        index.tx_hash.hex()
                        + " had a deposit at index "
                        + str(index.index)
                        + " for "
                        + str(spendable[1][index].amount)
                        + "."
                    )
                    available += spendable[1][index].amount
                waiting = False
                break
    last = current

# Wait 10 more blocks.
print("Waiting for the output to unlock.")
while rpc.get_block_count() != last + 10:
    sleep(10)

print(
    "Where would you like to forward it? 0.0001 XMR will be ignored to make room for the fee. "
)
dest: Address = Address.parse(crypto, input())

# Prepare the Transaction.
# Leave 1 off the fee to allow a change output.
context: Dict[str, Any] = watch.prepare_send(dest, available - 100000000, 100000000 - 1)

# Sign it.
publishable: List[str] = json.loads(
    json.dumps(wallet.sign(json.loads(json.dumps(context))))
)

# Publish it.
watch.finalize_send(True, context, publishable[1])

# Print the hash.
print("The hash is " + publishable[0] + ".")
