# Types.
from typing import Dict, List, Tuple

# urandom standard function.
from os import urandom

# randint standard function.
from random import randint

# OutputIndex class.
from cryptonote.classes.blockchain import OutputIndex

# OutputInfo and Crypto classes.
from cryptonote.crypto.crypto import OutputInfo

# Wallet classes.
from cryptonote.classes.wallet.wallet import Wallet, WatchWallet

# Test fixtures.
from tests.regnet_tests.conftest import Harness

# 1 XMR.
ATOMIC_XMR: int = 1000000000000


def subaddress_test(harness: Harness) -> None:
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

    # Send to random indexes (with the first index being the root index).
    indexes: List[Tuple[int, int]] = [(0, 0)]
    amounts: List[int] = []
    txs: List[bytes] = []
    for _ in range(10):
        amounts.append(randint(ATOMIC_XMR, 40 * ATOMIC_XMR))
        txs.append(harness.send(watch.new_address(indexes[-1]), amounts[-1]))

        indexes.append((randint(0, 300), randint(0, 300)))
    del indexes[-1]

    # Verify them via can_spend.
    for t in range(len(txs)):
        spendable: Tuple[List[bytes], Dict[OutputIndex, OutputInfo]] = watch.can_spend(
            watch.rpc.get_transaction(txs[t])
        )
        assert not spendable[0]
        assert len(spendable[1]) == 1
        assert list(spendable[1].keys())[0].tx_hash == txs[t]
        assert spendable[1][list(spendable[1].keys())[0]].amount == amounts[t]

    # Send back to the master wallet.
    harness.return_funds(wallet, watch, sum(amounts))
