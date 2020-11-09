# Types.
from typing import Dict, List, Tuple, Any

# urandom standard function.
from os import urandom

# randint standard function.
from random import randint

# JSON standard lib.
import json

# Ed25519 lib.
from cryptonote.lib.ed25519 import Hs, public_from_secret

# VarInt lib.
from cryptonote.lib.var_int import to_var_int

# OutputIndex and Transaction classes.
from cryptonote.classes.blockchain import OutputIndex, Transaction

# OutputInfo and Crypto classes.
from cryptonote.crypto.crypto import OutputInfo

# Wallet classes.
from cryptonote.classes.wallet.wallet import Wallet, WatchWallet

# Test fixtures.
from tests.regnet_tests.conftest import Harness

# 1 XMR.
ATOMIC_XMR: int = 1000000000000


def multiple_Rs_test(harness: Harness) -> None:
    # Wallet.
    wallet: Wallet = Wallet(harness.crypto, urandom(32))

    # WatchWallet.
    watch: WatchWallet = WatchWallet(
        harness.crypto,
        harness.rpc,
        wallet.private_view_key,
        wallet.public_spend_key,
        harness.rpc.get_block_count() - 1,
    )

    # Test multiple Rs.
    indexes: List[Tuple[int, int]] = [(0, 0)]
    amounts: List[int] = []
    txs: List[bytes] = []
    for _ in range(5):
        indexes.append((randint(0, 300), randint(0, 300)))
        amounts.append(randint(ATOMIC_XMR, 40 * ATOMIC_XMR))
        txs.append(harness.send(watch.new_address(indexes[-1]), amounts[-1]))

        # Get the Transaction.
        tx: Transaction = watch.rpc.get_transaction(txs[-1])

        # Add multiple other Rs to the Transaction.
        for _ in range(3):
            tx.Rs.append(public_from_secret(Hs(urandom(32))))

        # Check the other Rs had no affect.
        spendable: Tuple[List[bytes], Dict[OutputIndex, OutputInfo]] = watch.can_spend(
            tx
        )
        assert not spendable[0]
        assert len(spendable[1]) == 1
        assert list(spendable[1].keys())[0].tx_hash == txs[-1]
        assert spendable[1][list(spendable[1].keys())[0]].amount == amounts[-1]

    # Test multiple identical Rs.
    for _ in range(5):
        # Send to a random index.
        indexes.append((randint(0, 300), randint(0, 300)))
        amounts.append(randint(ATOMIC_XMR, 5 * ATOMIC_XMR))
        txs.append(harness.send(watch.new_address(indexes[-1]), amounts[-1]))

        # Manually get the Transaction's JSON.
        tx_json: Dict[str, Any] = json.loads(
            watch.rpc.rpc_request(
                "get_transactions",
                {"txs_hashes": [txs[-1].hex()], "decode_as_json": True},
            )["txs"][0]["as_json"]
        )

        # Create a Transaction from it.
        tx: Transaction = Transaction(txs[-1], tx_json)

        # Get a duplicate list of Rs.
        Rs: List[bytes] = tx.Rs * 2
        # Use the Rs and tx to craft a new extra in tx_json.
        extra: bytes = bytes([0x01]) + Rs[0]
        # Add the other Rs.
        extra += bytes([0x04]) + to_var_int(len(Rs) - 1)
        for R in Rs[1:]:
            extra += R
        # Store it in tx_json.
        tx_json["extra"] = []
        for b in range(len(extra)):
            tx_json["extra"].append(extra[b])

        # Parse the modified JSON.
        modified_tx: Transaction = Transaction(txs[-1], tx_json)

        # Check the duplicate Rs were stripped.
        assert tx.Rs == modified_tx.Rs
        spendable: Tuple[List[bytes], Dict[OutputIndex, OutputInfo]] = watch.can_spend(
            tx
        )
        assert not spendable[0]
        assert len(spendable[1]) == 1
        assert list(spendable[1].keys())[0].tx_hash == txs[-1]
        assert spendable[1][list(spendable[1].keys())[0]].amount == amounts[-1]

    # Send back to the master wallet.
    harness.return_funds(wallet, watch, sum(amounts))
