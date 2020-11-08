"""Wallet file. Provides classes to watch incoming funds and send funds."""

# Types.
from typing import Dict, Deque, List, Set, Tuple, Optional, Union, Any

# Deque standard type.
from collections import deque

# urandom standard function.
from os import urandom

# Ed25519 lib.
from cryptonote.lib import ed25519 as ed

# Address class.
from cryptonote.classes.wallet.address import Address

# Blockchain classes.
from cryptonote.classes.blockchain import OutputIndex, Transaction, Block

# Crypto class.
from cryptonote.crypto.crypto import (
    InputState,
    OutputInfo,
    SpendableOutput,
    SpendableTransaction,
    Crypto,
)

# RPC class.
from cryptonote.rpc.rpc import RPCError, RPC


class BalanceError(Exception):
    """
    BalanceError Exception.
    Used when there's not enough enough of a balance to cover the transaction.
    """


class MixinError(Exception):
    """MixinError Exception. Used when there's not enough mixins."""


class FeeError(Exception):
    """FeeError Exception. Used when the fee is too low."""


class WatchWallet:
    """
    WatchWallet class.
    Enables generating addresses and checking if a Transaction sends to us.
    """

    def poll_blocks(self) -> Dict[OutputIndex, OutputInfo]:
        """Updates the inputs with Transactions in new Blocks."""

        height: int = self.rpc.get_block_count()
        for b in range(self.last_block + 1, height):
            self.confirmation_queue.append(
                self.rpc.get_block(self.rpc.get_block_hash(b))
            )
        self.last_block = max(self.last_block, height - 1)

        result: Dict[OutputIndex, OutputInfo] = {}
        while len(self.confirmation_queue) > self.crypto.confirmations:
            usable: Block = self.confirmation_queue.popleft()
            for tx in usable.hashes + [usable.header.miner_tx_hash]:
                new_inputs: Dict[OutputIndex, OutputInfo] = self.can_spend(
                    self.rpc.get_transaction(tx)
                )[1]
                for index in new_inputs:
                    result[index] = new_inputs[index]
        return dict(result)

    def load_state(self, state: Union[int, Dict[str, Any]],) -> None:
        """Load the state."""

        self.last_block: int
        if isinstance(state, int):
            self.last_block = state
        else:
            self.last_block = state["last_block"] - 10

            for json_output in state["inputs"]:
                output: OutputInfo = self.crypto.output_from_json(json_output)
                self.inputs[output.index] = output

            for unique_factor in state["unique_factors"]:
                self.unique_factors[bytes.fromhex(unique_factor)] = (
                    state["unique_factors"][unique_factor][0],
                    state["unique_factors"][unique_factor][1],
                )

        # Poll blocks to rebuild the cache.
        # -1 is a value used in the unit tests in order to not make any RPC calls.
        if self.last_block != -1:
            self.poll_blocks()

    def __init__(
        self,
        crypto: Crypto,
        rpc: RPC,
        private_view_key: bytes,
        public_spend_key: bytes,
        state: Union[int, Dict[str, Any]],
    ) -> None:
        """Constructor."""

        # Set the Crypto class.
        self.crypto: Crypto = crypto

        # Set the RPC class.
        self.rpc: RPC = rpc

        # Set the spend key.
        self.public_spend_key: bytes = public_spend_key

        # Set the view keys.
        self.private_view_key: bytes = private_view_key
        self.public_view_key: bytes = ed.public_from_secret(self.private_view_key)

        # Blocks whose Transactions have yet to confirm.
        self.confirmation_queue: Deque[Block] = deque([])
        # Inputs.
        self.inputs: Dict[OutputIndex, OutputInfo] = {}

        # Unique factors.
        self.unique_factors: Dict[bytes, Tuple[int, int]] = {
            self.public_spend_key: (0, 0)
        }

        # Reload the state.
        self.load_state(state)

    def save_state(self) -> Dict[str, Any]:
        """Convert the state to a writable format."""

        result: Dict[str, Any] = {
            "last_block": self.last_block,
            "inputs": [],
            "unique_factors": {},
        }

        for index in self.inputs:
            result["inputs"].append(self.inputs[index].to_json())

        for unique_factor in self.unique_factors:
            result["unique_factors"][unique_factor.hex()] = [
                self.unique_factors[unique_factor][0],
                self.unique_factors[unique_factor][1],
            ]

        return result

    def regenerate_unique_factors(self, index: Tuple[int, int]) -> None:
        """Regenerates the unique factors for X from 0 .. Y."""

        for addr in range(index[1] + 1):
            properties: Tuple[
                Tuple[bytes, bytes], Optional[bytes], bytes, bytes
            ] = self.crypto.new_address(
                (self.public_view_key, self.public_spend_key), (index[0], addr)
            )

            if properties[0][1] not in self.unique_factors:
                self.unique_factors[properties[0][1]] = (index[0], addr)

    def new_address(self, unique_factor: Union[Tuple[int, int], bytes]) -> Address:
        """Creates a new address."""

        properties: Tuple[
            Tuple[bytes, bytes], Optional[bytes], bytes, bytes
        ] = self.crypto.new_address(
            (self.private_view_key, self.public_spend_key), unique_factor
        )

        if properties[0][1] not in self.unique_factors:
            if not isinstance(unique_factor, bytes):
                self.unique_factors[properties[0][1]] = unique_factor

        return Address(
            self.crypto, properties[0], properties[1], network_byte=properties[2]
        )

    def can_spend(
        self, tx: Transaction,
    ) -> Tuple[List[bytes], Dict[OutputIndex, OutputInfo]]:
        """
        Returns the found payment IDs and spendable outputs (OutputInfos indexed by OutputIndexes).

        The output destination must be determined through looking up the unique factor.
        This is the payment ID on payment ID networks, although the amount of IDs is not guaranteed.
        Any amount other than one causes the deposit destination to not be determinable.

        On subaddress networks, the unique factor is the spend key contained in the OutputInfo.
        """

        # Create the shared keys.
        shared_keys: List[bytes] = []
        for R in tx.Rs:
            shared_keys.append(self.crypto.create_shared_key(self.private_view_key, R))

        # Get the payment IDs.
        payment_IDs: List[bytes] = self.crypto.get_payment_IDs(
            shared_keys, tx.payment_IDs
        )

        # Found spendable outputs.
        spendable_outputs: Set[int] = set()

        # Result.
        result: Dict[OutputIndex, OutputInfo] = {}

        for shared_key in shared_keys:
            # Check each output unless it's already been found spendable.
            for o in range(len(tx.outputs)):
                if o in spendable_outputs:
                    continue

                can_spend_res: Optional[OutputInfo] = self.crypto.can_spend_output(
                    self.unique_factors, shared_key, tx, o
                )
                if can_spend_res is not None:
                    spendable_outputs.add(o)
                    result[OutputIndex(tx.tx_hash, o)] = can_spend_res

        # Merge the new TXOs into the Wallet's TXOs.
        for txo in result:
            if txo in self.inputs:
                continue

            self.inputs[txo] = result[txo]

        # Return the payment IDs + result.
        return (payment_IDs, result)

    def rebuild_input_states(self, key_images: List[Dict[str, Any]]) -> None:
        """Marks spent inputs as spent."""

        for image in key_images:
            if self.rpc.is_key_image_spent(bytes.fromhex(image["image"])):
                self.inputs[
                    OutputIndex(bytes.fromhex(image["hash"]), image["index"])
                ].state = InputState.Spent

    def prepare_send(
        self,
        dest: Address,
        amount: int,
        fee: int,
        minimum_input: int = 0,
        inputs_override: Optional[Dict[OutputIndex, OutputInfo]] = None,
    ) -> Dict[str, Any]:
        """
        Prepares a send to the destination for the specified amount with the specified fee.
        Skip inputs with a value less than minimum_input.
        If inputs are passed in, those inputs are used.
        Else, the WatchWallet's inputs are used.
        The selected inputs from the list of inputs have their state updated to Transmitted.

        Creates two outputs: one to the destination and a change address.
        The change address is the root view and spend key as a standard address.
        Also finds valid mixins and gets the needed information surrounding them.

        Returns the context to be passed to the cold wallet's sign.

        Raises BalanceError if there isn't enough of a balance to cover the transaction.
        Raises MixinError if there aren't enough mixins to use.
        Raises FeeError if the the fee is too low.
        """

        # Grab the inputs to use.
        inputs: Dict[OutputIndex, OutputInfo] = self.inputs
        if inputs_override is not None:
            inputs = inputs_override

        # Create the context.
        context: Dict[str, Any] = {
            "inputs": [],
            "mixins": [],
            "ring": [],
            "outputs": [],
            "fee": fee,
        }

        # Grab the height:
        height: int = self.rpc.get_block_count()

        # Grab the newest TXO.
        newest_unlocked_block: Block = self.rpc.get_block(
            self.rpc.get_block_hash(height - self.crypto.miner_lock_blocks)
        )
        newest_tx: bytes = newest_unlocked_block.header.miner_tx_hash
        if newest_unlocked_block.hashes:
            newest_tx = newest_unlocked_block.hashes[-1]
        newest_txo: int = self.rpc.get_o_indexes(newest_tx)[-1]

        # Check there's enough mixins available.
        mixins_available: int = newest_txo - self.crypto.oldest_txo
        if mixins_available < self.crypto.required_mixins:
            raise MixinError("Not enough mixins available.")
        mixin_bytes: int = ((mixins_available.bit_length() // 8) + 1) * 8

        # Needed transaction value.
        value: int = amount + fee
        for index in inputs:
            if (
                # Skip the Input if it's not spendable.
                (inputs[index].state != InputState.Spendable)
                or
                # Skip the Input if it's timelocked.
                (inputs[index].timelock >= height)
                or
                # Skip the Input if it's dust.
                (inputs[index].amount < minimum_input)
            ):
                continue

            # Add the input.
            context["inputs"].append(inputs[index].to_json())

            # Grab mixins.
            # Start by getting and adding the Input's actual index.
            actual: int = self.rpc.get_o_indexes(inputs[index].index.tx_hash)[
                inputs[index].index.index
            ]
            context["mixins"].append([actual])

            # Add the other mixins.
            while len(context["mixins"][-1]) != self.crypto.required_mixins:
                new_mixin = self.crypto.oldest_txo + (
                    int.from_bytes(urandom(mixin_bytes), byteorder="little")
                    % mixins_available
                )
                if new_mixin in context["mixins"][-1]:
                    continue
                context["mixins"][-1].append(new_mixin)

            # Sort the mixins.
            context["mixins"][-1].sort()
            # Specify the input's index to the mixins.
            context["inputs"][-1]["mixin_index"] = context["mixins"][-1].index(actual)

            # Add the ring info..
            context["ring"].append([])
            for m in range(len(context["mixins"][-1])):
                outs: Dict[str, Any] = self.rpc.get_outs(context["mixins"][-1][m])
                context["ring"][-1].append([outs["key"].hex(), outs["mask"].hex()])

            # Subtract the amount from the needed value.
            value -= inputs[index].amount

            # Break if we have enough funds.
            if value <= 0:
                break

        # Make sure we have enough funds.
        if value > 0:
            raise BalanceError(
                "Didn't have enough of a balance to cover the transaction."
            )

        # Make sure the fee is high enough.
        if fee < self.crypto.get_minimum_fee(
            self.rpc.get_fee_estimate(),
            len(context["inputs"]),
            2,
            context["mixins"],
            255,
            fee,
        ):
            raise Exception(FeeError, "Fee is too low.")

        # Mark the inputs as transmitted.
        for input in context["inputs"]:
            inputs[
                OutputIndex(bytes.fromhex(input["hash"]), input["index"])
            ].state = InputState.Transmitted

        # Add the output.
        address: Address = dest
        context["outputs"].append({"address": address.address, "amount": amount})

        # Return the context and amount of used Transactions.
        return context

    def finalize_send(
        self, success: bool, context: Dict[str, Any], serialization: str
    ) -> bool:
        """
        Publishes a signed transaction if success is true.
        Marks used inputs as spent if the transaction is successfully published.
        Else, marks used inputs as spendable.
        """

        if success:
            try:
                self.rpc.publish_transaction(bytes.fromhex(serialization))
            except RPCError:
                success = False

        state = InputState.Spent if success else InputState.Spendable
        for input_i in context["inputs"]:
            self.inputs[
                OutputIndex(bytes.fromhex(input_i["hash"]), input_i["index"])
            ].state = state
        return success


class Wallet:
    """
    Wallet class.
    Enables decoding output amounts balances and spending received funds.
    """

    def __init__(self, crypto: Crypto, key: bytes) -> None:
        """Constructor."""

        # Set the Crypto class.
        self.crypto: Crypto = crypto

        # Set the keys.
        self.private_spend_key: bytes = ed.encodeint(ed.decodeint(key) % ed.l)
        self.public_spend_key: bytes = ed.public_from_secret(self.private_spend_key)
        self.private_view_key: bytes = ed.Hs(self.private_spend_key)
        self.public_view_key: bytes = ed.public_from_secret(self.private_view_key)

    def generate_key_images(self, inputs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate a key image for every passed in input."""

        result: List[Dict[str, Any]] = []
        for input_i in inputs:
            result.append(
                {
                    "hash": input_i["hash"],
                    "index": input_i["index"],
                    "image": self.crypto.generate_key_image(
                        self.crypto.output_from_json(input_i),
                        self.private_view_key,
                        self.private_spend_key,
                    ).hex(),
                }
            )
        return result

    def sign(self, context: Dict[str, Any]) -> List[str]:
        """
        Creates a Transaction with a context prepared by a view-only Wallet.
        Returns a List of the Transaction hash (as hex) and serialized raw Transaction (as hex).
        """

        # Extract the inputs.
        inputs: List[OutputInfo] = []
        for input_i in context["inputs"]:
            inputs.append(self.crypto.output_from_json(input_i))
            inputs[-1].index.index = input_i["mixin_index"]

        # Extract the outputs.
        outputs: List[SpendableOutput] = []
        for output in context["outputs"]:
            address: Address = Address.parse(self.crypto, output["address"])
            outputs.append(
                SpendableOutput(
                    address.network,
                    address.view_key,
                    address.spend_key,
                    address.payment_id,
                    output["amount"],
                )
            )

        # Convert the ring to binary.
        ring: List[List[List[bytes]]] = []
        for i in range(len(context["ring"])):
            ring.append([])
            for v in range(len(context["ring"][i])):
                ring[i].append([])
                ring[i][v].append(bytes.fromhex(context["ring"][i][v][0]))
                ring[i][v].append(bytes.fromhex(context["ring"][i][v][1]))

        # Construct a SpendableTransaction from the context.
        sending: SpendableTransaction = self.crypto.spendable_transaction(
            inputs,
            context["mixins"],
            outputs,
            ring,
            SpendableOutput(
                self.crypto.network_bytes[0],
                self.public_view_key,
                self.public_spend_key,
                None,
                0,
            ),
            context["fee"],
        )

        # Sign it.
        self.crypto.sign(sending, self.private_view_key, self.private_spend_key)

        result: Tuple[bytes, bytes] = sending.serialize()
        return [result[0].hex(), result[1].hex()]
