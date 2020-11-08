# Types.
from typing import Callable, Dict, List, Tuple, IO, Any

# Format Exception standard function.
from traceback import format_exc

# urandom standard function.
from os import urandom

# sleep standard function.
from time import sleep

# JSON standard lib.
import json

# pytest lib.
import pytest

# Ed25519 lib.
import cryptonote.lib.ed25519 as ed

# Transaction/Block classes.
from cryptonote.classes.blockchain import OutputIndex, Transaction, Block

# Crypto classes.
from cryptonote.crypto.monero_crypto import InputState, OutputInfo, Crypto, MoneroCrypto
from cryptonote.crypto.monero_payment_id_crypto import MoneroPaymentIDCrypto
from cryptonote.crypto.turtlecoin_crypto import TurtlecoinCrypto

# Address and Wallet classes.
from cryptonote.classes.wallet.address import Address
from cryptonote.classes.wallet.wallet import Wallet, WatchWallet

# RPC classes.
from cryptonote.rpc.monero_rpc import RPC, MoneroRPC

# 1 XMR.
ATOMIC_XMR: int = 1000000000000


class Harness:
    def __init__(self):
        """Construct a new test environment."""

        self.rpc: RPC = MoneroRPC("127.0.0.1", 18081)

        self.crypto: MoneroCrypto = MoneroCrypto()
        self.crypto.oldest_txo_property = 1

        key: bytes = urandom(32)
        self.wallet: Wallet = Wallet(self.crypto, key)
        self.watch: WatchWallet = WatchWallet(
            self.crypto,
            self.rpc,
            self.wallet.private_view_key,
            self.wallet.public_spend_key,
            1,
        )
        self.inputs: Dict[OutputIndex, OutputInfo] = {}

        self.rpc.generate_blocks(100, self.watch.new_address((0, 0)).address)

    def verify_inputs(self):
        """Verify our inputs is the same as the WatchWallet's."""

        assert self.inputs == self.watch.inputs

    def poll_blocks(self):
        """Update our WatchWallet with the latest inputs."""

        # Update with the newly found inputs.
        self.inputs = {**self.inputs, **self.watch.poll_blocks()}

        # Verify inputs.
        self.verify_inputs()

    def wait_for_unlock(self):
        """Wait for any new Transactions to unlock."""

        sleep(2)
        self.rpc.generate_blocks(
            self.crypto.confirmations + 1, self.watch.new_address((0, 0)).address
        )
        self.poll_blocks()

    def send(self, address: Address, amount: int) -> bytes:
        """Provide the specified address with the specified amount."""

        # Update the available inputs.
        self.poll_blocks()

        # Prepare the spend.
        context: Dict[str, Any] = self.watch.prepare_send(
            address, amount, ATOMIC_XMR // 10
        )

        # Mark the spent inputs as spent in our copy of inputs.
        for input_i in context["inputs"]:
            self.inputs[
                OutputIndex(bytes.fromhex(input_i["hash"]), input_i["index"])
            ].state = InputState.Spent

        # Sign it.
        publishable: List[str] = json.loads(
            json.dumps(self.wallet.sign(json.loads(json.dumps(context))))
        )

        # Publish it.
        self.watch.finalize_send(True, context, publishable[1])

        # Verify the WatchWallet's inputs equals our list.
        self.verify_inputs()

        # Wait for the outputs to unlock.
        self.wait_for_unlock()

        # Return the hash.
        return bytes.fromhex(publishable[0])

    def return_funds(
        self, test_wallet: Wallet, test_watch: WatchWallet, amount: int
    ) -> None:
        """Return sent funds back to the master wallet."""

        if amount != 0:
            context: Dict[str, Any] = test_watch.prepare_send(
                self.watch.new_address((0, 0)),
                amount - (ATOMIC_XMR // 10),
                (ATOMIC_XMR // 10) - 1,
            )
            publishable: List[str] = test_wallet.sign(json.loads(json.dumps(context)))
            test_watch.finalize_send(True, context, publishable[1])

            # Wait for the return TXs to unlock.
            self.wait_for_unlock()

            # Verify we can spend the returned funds.
            returned: Tuple[
                List[bytes], Dict[OutputIndex, OutputInfo]
            ] = self.watch.can_spend(
                self.rpc.get_transaction(bytes.fromhex(publishable[0]))
            )
            assert not returned[0]
            assert len(returned[1]) == 1
            assert list(returned[1].keys())[0].tx_hash == bytes.fromhex(publishable[0])
            assert returned[1][list(returned[1].keys())[0]].amount == amount - (
                ATOMIC_XMR // 10
            )

        # Poll the blockchain.
        # This gets us the miner Transactions and change outputs.
        # Since inputs are stored as a Dict, this will not create duplicates.
        self.poll_blocks()

        # Verify inputs.
        self.verify_inputs()


@pytest.fixture(scope="session")
def harness() -> Harness:
    return Harness()


@pytest.fixture
def monero_payment_id_crypto() -> MoneroPaymentIDCrypto:
    return MoneroPaymentIDCrypto()
