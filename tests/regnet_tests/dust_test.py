# Types.
from typing import Dict, List, Tuple

# urandom standard function.
from os import urandom

# pytest lib.
import pytest

# OutputIndex class.
from cryptonote.classes.blockchain import OutputIndex

# OutputInfo class.
from cryptonote.crypto.crypto import OutputInfo

# Wallet classes.
from cryptonote.classes.wallet.wallet import BalanceError, Wallet, WatchWallet

# Test fixtures.
from tests.regnet_tests.conftest import Harness

# 1 XMR.
ATOMIC_XMR: int = 1000000000000


def dust_test(harness: Harness) -> None:
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

    # Send to self.
    tx: bytes = harness.send(watch.new_address((0, 0)), ATOMIC_XMR)
    # Verify it via can_spend.
    spendable: Tuple[List[bytes], Dict[OutputIndex, OutputInfo]] = watch.can_spend(
        watch.rpc.get_transaction(tx)
    )
    assert not spendable[0]
    assert len(spendable[1]) == 1
    assert list(spendable[1].keys())[0].tx_hash == tx
    assert spendable[1][list(spendable[1].keys())[0]].amount == ATOMIC_XMR

    # 'Send' back to the master wallet.
    with pytest.raises(BalanceError):
        watch.prepare_send(
            watch.new_address((0, 0)),
            (ATOMIC_XMR // 10) * 9,
            (ATOMIC_XMR // 10) - 1,
            minimum_input=(2 * ATOMIC_XMR),
        )

    # Still call return_funds so the post-test functions can be run.
    harness.return_funds(wallet, watch, 0)
