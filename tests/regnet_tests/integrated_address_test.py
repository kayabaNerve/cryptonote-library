# Types.
from typing import Dict, List, Tuple, Any

# urandom standard function.
from os import urandom

# randint standard function.
from random import randint

# JSON standard lib.
import json

# OutputIndex class.
from cryptonote.classes.blockchain import OutputIndex

# Crypto classes.
from cryptonote.crypto.monero_crypto import OutputInfo
from cryptonote.crypto.monero_payment_id_crypto import MoneroPaymentIDCrypto

# Address class.
from cryptonote.classes.wallet.address import Address

# Wallet classes.
from cryptonote.classes.wallet.wallet import Wallet, WatchWallet

# RPC class.
from cryptonote.rpc.rpc import RPC

# Test fixtures.
from tests.regnet_tests.conftest import Harness

# 1 XMR.
ATOMIC_XMR: int = 1000000000000


def integrated_address_test(
    harness: Harness, monero_payment_id_crypto: MoneroPaymentIDCrypto
) -> None:
    # Override the oldest TXO.
    monero_payment_id_crypto.oldest_txo_property = 1

    # Wallet.
    wallet: Wallet = Wallet(monero_payment_id_crypto, urandom(32))

    # WatchWallet.
    watch: WatchWallet = WatchWallet(
        monero_payment_id_crypto,
        harness.rpc,
        wallet.private_view_key,
        wallet.public_spend_key,
        harness.rpc.get_block_count() - 1,
    )

    # Send to random payment IDs.
    payment_IDs: List[bytes] = [urandom(8)]
    amounts: List[int] = []
    txs: List[bytes] = []
    for i in range(10):
        amounts.append(randint(ATOMIC_XMR, 40 * ATOMIC_XMR))
        txs.append(harness.send(watch.new_address(payment_IDs[-1]), amounts[-1]))

        payment_IDs.append(urandom(8))
    del payment_IDs[-1]

    # Verify them via can_spend.
    for t in range(len(txs)):
        # Verify them via can_spend.
        for t in range(len(txs)):
            spendable: Tuple[
                List[bytes], Dict[OutputIndex, OutputInfo]
            ] = watch.can_spend(watch.rpc.get_transaction(txs[t]))
            assert len(spendable[0]) == 1
            assert spendable[0][0] == payment_IDs[t]
            assert len(spendable[1]) == 1
            assert list(spendable[1].keys())[0].tx_hash == txs[t]
            assert spendable[1][list(spendable[1].keys())[0]].amount == amounts[t]

    # Send back to the master wallet.
    harness.return_funds(wallet, watch, sum(amounts))
