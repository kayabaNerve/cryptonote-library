"""MoneroCrypto class file."""

# Types.
from typing import Dict, Set, List, Tuple, Optional, Union, Any

# urandom standard function.
from os import urandom

# Shuffle standard function.
from random import shuffle

# Regex standard lib.
import re

# VarInt lib.
from cryptonote.lib.var_int import to_var_int

# Ed25519 lib.
import cryptonote.lib.ed25519 as ed

# RingCT lib.
import cryptonote.lib.monero_rct as _
from cryptonote.lib.monero_rct.c_monero_rct import (
    RingCTSignatures,
    generate_key_image,
    generate_ringct_signatures,
)

# Crypto class.
from cryptonote.crypto.crypto import (
    InputState,
    OutputInfo,
    SpendableOutput,
    SpendableTransaction,
    Crypto,
)

# Transaction classes.
from cryptonote.classes.blockchain import MinerOutput, Output, OutputIndex, Transaction


class MoneroOutputInfo(OutputInfo):
    def __init__(
        self,
        index: OutputIndex,
        timelock: int,
        amount: int,
        spend_key: bytes,
        subaddress: Tuple[int, int],
        amount_key: bytes,
        commitment: bytes,
    ) -> None:
        """Constructor."""

        OutputInfo.__init__(self, index, timelock, amount, spend_key)

        self.subaddress: Tuple[int, int] = subaddress
        self.amount_key: bytes = amount_key
        self.commitment: bytes = commitment

    def to_json(self) -> Dict[str, Any]:
        """Convert a MoneroOutputInfo to a transmittable format."""

        return {
            **OutputInfo.to_json(self),
            "subaddress": [self.subaddress[0], self.subaddress[1]],
            "amount_key": self.amount_key.hex(),
            "commitment": self.commitment.hex(),
        }

    @staticmethod
    def from_json(output: Dict[str, Any]) -> Any:
        """Load an MoneroOutputInfo from JSON."""

        result: Any = MoneroOutputInfo(
            OutputIndex(bytes.fromhex(output["hash"]), output["index"]),
            output["timelock"],
            output["amount"],
            bytes.fromhex(output["spend_key"]),
            (output["subaddress"][0], output["subaddress"][1]),
            bytes.fromhex(output["amount_key"]),
            bytes.fromhex(output["commitment"]),
        )
        result.state = InputState(output["state"])
        return result


class MoneroSpendableTransaction(SpendableTransaction):
    """
    MoneroSpendableTransaction class.
    Represents a Transaction created by this library which can be signed and serialized.
    """

    amount_keys: List[bytes] = []
    signatures: Optional[RingCTSignatures]

    def __init__(
        self,
        inputs: List[OutputInfo],
        amount_keys: List[bytes],
        output_keys: List[bytes],
        output_amounts: List[int],
        extra: bytes,
        fee: int,
    ) -> None:
        self.inputs: List[OutputInfo] = inputs

        self.amount_keys: List[bytes] = amount_keys
        self.output_keys: List[bytes] = output_keys
        self.output_amounts: List[int] = output_amounts

        self.extra = extra
        self.fee = fee

        self.signatures = None

    @property
    def hash(self) -> bytes:
        """Get the hash of a MoneroSpendableTransaction."""

    def serialize(self) -> Tuple[bytes, bytes]:
        """Serialize a MoneroSpendableTransaction."""

        # Serialize the version and lock time.
        prefix: bytes = bytes([2, 0])

        prefix += to_var_int(len(self.inputs))
        for input_i in self.inputs:
            prefix += bytes([2, 0])
            prefix += to_var_int(len(input_i.mixins))
            for mixin in input_i.mixins:
                prefix += to_var_int(mixin)
            prefix += input_i.image

        prefix += to_var_int(len(self.output_keys))
        for o in range(len(self.output_keys)):
            prefix += bytes([0, 2])
            prefix += self.output_keys[o]

        prefix += to_var_int(len(self.extra))
        prefix += self.extra

        if self.signatures is None:
            return (ed.H(prefix), bytes())

        # RangeCT below. All of our Transactions are Simple Padded Bulletproofs (type 4).
        base: bytes = bytes([5])
        base += to_var_int(self.fee)

        for o in range(len(self.output_keys)):
            for i in range(8):
                base += bytes([self.signatures.ecdh_info[o].amount[i]])

        for out_public_key in self.signatures.out_public_keys:
            for i in range(32):
                base += bytes([out_public_key.mask[i]])

        # Prunable info.
        prunable: bytes = to_var_int(len(self.signatures.prunable.bulletproofs))
        for bulletproof in self.signatures.prunable.bulletproofs:
            for i in range(32):
                prunable += bytes([bulletproof.capital_a[i]])
            for i in range(32):
                prunable += bytes([bulletproof.s[i]])
            for i in range(32):
                prunable += bytes([bulletproof.t1[i]])
            for i in range(32):
                prunable += bytes([bulletproof.t2[i]])
            for i in range(32):
                prunable += bytes([bulletproof.taux[i]])
            for i in range(32):
                prunable += bytes([bulletproof.mu[i]])

            prunable += to_var_int(len(bulletproof.l))
            for l in bulletproof.l:
                for i in range(32):
                    prunable += bytes([l[i]])

            prunable += to_var_int(len(bulletproof.r))
            for r in bulletproof.r:
                for i in range(32):
                    prunable += bytes([r[i]])

            for i in range(32):
                prunable += bytes([bulletproof.a[i]])
            for i in range(32):
                prunable += bytes([bulletproof.b[i]])
            for i in range(32):
                prunable += bytes([bulletproof.t[i]])

        for cl in self.signatures.prunable.CLSAGs:
            for s in cl.s:
                for i in range(32):
                    prunable += bytes([s[i]])
            for i in range(32):
                prunable += bytes([cl.c1[i]])
            for i in range(32):
                prunable += bytes([cl.D[i]])

        for pseudo_out in self.signatures.prunable.pseudo_outs:
            for i in range(32):
                prunable += bytes([pseudo_out[i]])

        return (
            ed.H(ed.H(prefix) + ed.H(base) + ed.H(prunable)),
            prefix + base + prunable,
        )


class MoneroCrypto(Crypto):
    """
    MoneroCrypto class.
    Implements the various cryptographic operations used by Monero.
    """

    def __init__(self, mainnet: bool = True):
        """Initializes the various network properties of the Monero network."""

        if mainnet:
            self.network_bytes_property: List[bytes] = [
                bytes([0x12]),
                bytes([0x13]),
                bytes([0x2A]),
            ]

            self.oldest_txo_property = 11000000
        else:
            self.network_bytes_property = [bytes([0x35]), bytes([0x36]), bytes([0x3F])]

            self.oldest_txo_property = 600000

        self.address_regex_property: Any = re.compile(
            r"^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{95}$"
        )
        self.integrated_address_regex_property: Any = re.compile(
            r"^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{106}$"
        )
        self.payment_id_lengths_property: Set[int] = {8}

        self.lock_blocks_property = 10
        self.miner_lock_blocks_property = 60
        self.required_mixins_property = 11
        self.confirmations_property = 10

    @property
    def network_byte_length(self) -> int:
        """Length of the network bytes for this coin."""

        return 1

    @property
    def network_bytes(self):
        """
        Network bytes used by the coin.
        Standard address, payment ID address, subaddress.
        Payment ID coins use the first two, subaddress coins use all three.
        """

        return self.network_bytes_property

    @property
    def address_regex(self):
        """Regex to check the validity of an address or subaddress."""

        return self.address_regex_property

    @property
    def integrated_address_regex(self):
        """Regex to check the validity of an integrated address."""

        return self.integrated_address_regex_property

    @property
    def payment_id_leading(self) -> bool:
        """Whether or not the payment ID leads the keys in the address."""

        return False

    @property
    def payment_id_lengths(self) -> Set[int]:
        """Valid lengths for a payment ID."""

        return self.payment_id_lengths_property

    @property
    def lock_blocks(self) -> int:
        """Amount of Blocks TXOs are locked for."""

        return self.lock_blocks_property

    @property
    def miner_lock_blocks(self) -> int:
        """Amount of Blocks Miner TXOs are locked for."""

        return self.miner_lock_blocks_property

    @property
    def oldest_txo(self) -> int:
        """Oldest TXO to use for a mixin."""

        return self.oldest_txo_property

    @property
    def required_mixins(self) -> int:
        """Required mixins per input."""

        return self.required_mixins_property

    @property
    def confirmations(self) -> int:
        """Required confirmations."""

        return self.confirmations_property

    def output_from_json(self, output: Dict[str, Any]) -> MoneroOutputInfo:
        """Load a MoneroOutputInfo from JSON."""

        return MoneroOutputInfo.from_json(output)

    def new_address(
        self,
        key_pair: Tuple[bytes, bytes],
        unique_factor: Union[Tuple[int, int], bytes],
    ) -> Tuple[Tuple[bytes, bytes], Optional[bytes], bytes, bytes]:
        """
        Constructs a new address with the root key pair and the index.
        Returns the key pair, payment ID, network byte, and unique factor to watch for.
        """

        if not isinstance(unique_factor, bytes):
            if unique_factor == (0, 0):
                return (
                    (ed.public_from_secret(key_pair[0]), key_pair[1]),
                    None,
                    self.network_bytes[0],
                    key_pair[0],
                )
            else:
                subaddress_key_pair = ed.generate_subaddress_key_pair(
                    key_pair[0], key_pair[1], unique_factor
                )

                return (
                    subaddress_key_pair,
                    None,
                    self.network_bytes[2],
                    subaddress_key_pair[0],
                )
        else:
            raise Exception("Invalid unique factor.")

    def get_payment_IDs(
        self,
        shared_keys: List[bytes],
        payment_IDs: List[bytes],
    ) -> List[bytes]:
        """Returns the Transaction's payment IDs, decrypted if necessary."""

        # Monero is a subaddress coin.
        return []

    def create_shared_key(self, scalar: bytes, point: bytes) -> bytes:
        """Created the shared key of which there is one per R."""

        # 8Ra.
        Ra8: Any = ed.scalarmult(ed.decodepoint(point), ed.decodeint(scalar))
        Ra8 = ed.decompress(Ra8)
        for _ in range(3):
            Ra8 = ed.add(Ra8, Ra8)
        Ra8 = ed.encodepoint(ed.compress(Ra8))
        return Ra8

    def can_spend_output(
        self,
        unique_factors: Dict[bytes, Tuple[int, int]],
        shared_key: bytes,
        tx: Transaction,
        o: int,
    ) -> Optional[MoneroOutputInfo]:
        """Checks if an output is spendable and returns the relevant info."""

        # Grab the output.
        output = tx.outputs[o]

        # Transaction one time keys are defined as P = Hs(H8Ra || i)G + B.
        # This is rewrittable as B = P - Hs(8Ra || i) G.

        # Hs(8Ra || i)
        amount_key: bytes = ed.Hs(shared_key + to_var_int(o))

        # P - Hs(8Ra || i)G
        amount_key_G: ed.CompressedPoint = ed.scalarmult(ed.B, ed.decodeint(amount_key))
        # Make it negative so it can be subtracted by adding it.
        amount_key_G = (-amount_key_G[0], amount_key_G[1])
        spend_key: bytes = ed.encodepoint(
            ed.add_compressed(ed.decodepoint(output.key), amount_key_G)
        )

        # We now have the spend key of the Transaction.
        if spend_key in unique_factors:
            # Get the amount.
            amount: int = 0
            if isinstance(output, MinerOutput):
                amount = output.amount
            else:
                # Decrypt the amount.
                amount = int.from_bytes(
                    output.amount, byteorder="little"
                ) ^ int.from_bytes(
                    ed.H(b"amount" + amount_key)[0:8], byteorder="little"
                )

            commitment: bytes = ed.COMMITMENT_MASK
            if isinstance(output, Output):
                # The encrypted amount is malleable.
                # We need to rebuild the commitment to verify it's accurate.
                commitment = ed.Hs(b"commitment_mask" + amount_key)
                if (
                    ed.encodepoint(
                        ed.add_compressed(
                            ed.scalarmult(
                                ed.B,
                                ed.decodeint(commitment),
                            ),
                            ed.scalarmult(ed.C, amount),
                        )
                    )
                    != output.commitment
                ):
                    return None

            return MoneroOutputInfo(
                OutputIndex(tx.tx_hash, o),
                tx.unlock_time,
                amount,
                spend_key,
                (unique_factors[spend_key][0], unique_factors[spend_key][1]),
                amount_key,
                commitment,
            )
        return None

    def get_minimum_fee(
        self,
        minimum_fee: Tuple[int, int],
        inputs: int,
        outputs: int,
        mixins: List[List[int]],
        extra: int,
        fee: int,
    ) -> int:
        """
        Calculates the minimum fee via the passed in:
        - Minimum fee (fee per byte, quantization mask)
        - Number of inputs
        - Number of outputs
        - Mixins
        - Extra length
        - Fee (a bit ironic, yet the fee changes the serialization length)
        """

        # Calculate the Transaction length.
        length: int = len(to_var_int(inputs)) + (803 * inputs)
        for i in mixins:
            for v in i:
                length += len(to_var_int(v))
        length += len(to_var_int(outputs)) + (74 * outputs)
        length += len(to_var_int(extra)) + extra
        length += len(to_var_int(fee))

        length += 64 * min(outputs, 4)
        length += 614

        # Calculate and return the minimum fee.
        return (
            ((length * minimum_fee[0]) + minimum_fee[1] - 1)
            // minimum_fee[1]
            * minimum_fee[1]
        )

    def generate_input_key(
        self,
        output: OutputInfo,
        private_view_key: bytes,
        private_spend_key: bytes,
    ) -> bytes:
        """Generate the one-time private key associated with an input."""

        if isinstance(output, MoneroOutputInfo):
            return ed.encodeint(
                (
                    ed.decodeint(output.amount_key)
                    + ed.generate_subaddress_private_spend_key(
                        private_view_key,
                        private_spend_key,
                        output.subaddress,
                    )
                )
                % ed.l
            )
        else:
            raise Exception("MoneroCrypto handed a non-Monero OutputInfo.")

    def generate_key_image(
        self,
        output: OutputInfo,
        private_view_key: bytes,
        private_spend_key: bytes,
    ) -> bytes:
        """Calculate the key image for the specified input."""

        input_key: bytes = self.generate_input_key(
            output, private_view_key, private_spend_key
        )
        return generate_key_image(input_key, ed.public_from_secret(input_key))

    def spendable_transaction(
        self,
        inputs: List[OutputInfo],
        mixins: List[List[int]],
        outputs: List[SpendableOutput],
        ring: List[List[List[bytes]]],
        change: SpendableOutput,
        fee: int,
    ) -> MoneroSpendableTransaction:
        """Create a MoneroSpendableTransaction."""

        # Clone the arguments.
        inputs = list(inputs)
        outputs = list(outputs)

        # Calculate the Transaction's amount.
        amount: int = 0
        for input_i in inputs:
            amount += input_i.amount
        for output in outputs:
            amount -= output.amount
        amount -= fee

        # Verify the outputs, change output (if needed), and fee are payable.
        if amount < 0:
            raise Exception(
                "Transaction doesn't have enough of an amount to pay "
                + "all the outputs, a change output (if needed), and the fee."
            )
        elif amount == 0:
            if len(outputs) < 2:
                raise Exception(
                    "Transaction doesn't have enough to create a second output."
                )
        else:
            # Add the change output.
            change.amount = amount
            outputs.append(change)

        # Shuffle the outputs.
        shuffle(outputs)

        # Embed the mixins and ring into the inputs.
        for i in range(len(inputs)):
            inputs[i].mixins = []
            index_sum: int = 0
            for index in mixins[i]:
                inputs[i].mixins.append(index - index_sum)
                index_sum += inputs[i].mixins[-1]

            inputs[i].ring = ring[i]

        # Create an r.
        r: bytes = ed.Hs(urandom(32))

        # Create the actual output key and the output amounts.
        Rs: List[bytes] = []
        rA8s: List[bytes] = []
        amount_keys: List[bytes] = []
        output_keys: List[bytes] = []
        output_amounts: List[int] = []
        for o in range(len(outputs)):
            rA8s.append(self.create_shared_key(r, outputs[o].view_key))
            amount_keys.append(ed.Hs(rA8s[-1] + to_var_int(o)))

            output_keys.append(
                ed.encodepoint(
                    ed.add_compressed(
                        ed.scalarmult(ed.B, ed.decodeint(amount_keys[-1])),
                        ed.decodepoint(outputs[o].spend_key),
                    )
                )
            )

            rG: bytes
            if outputs[o].network == self.network_bytes_property[2]:
                rG = ed.encodepoint(
                    ed.scalarmult(ed.decodepoint(outputs[o].spend_key), ed.decodeint(r))
                )
            else:
                rG = ed.encodepoint(ed.scalarmult(ed.B, ed.decodeint(r)))
            Rs.append(rG)

            output_amounts.append(outputs[o].amount)

        # Deduplicate the Rs.
        Rs = list(set(Rs))

        # Create an extra.
        extra: bytes = bytes([0x01]) + Rs[0]
        # Add the other Rs.
        if len(Rs) > 1:
            extra += bytes([0x04]) + to_var_int(len(Rs) - 1)
            for R in Rs[1:]:
                extra += R

        # Add the payment IDs.
        extra_payment_IDs: bytes = bytes()
        for o in range(len(outputs)):
            potential_payment_id: Optional[bytes] = outputs[o].payment_id
            if potential_payment_id:
                extra_payment_IDs += bytes([0x01]) + (
                    int.from_bytes(potential_payment_id, byteorder="little")
                    ^ int.from_bytes(
                        ed.H(rA8s[o] + bytes([0x8D]))[0:8], byteorder="little"
                    )
                ).to_bytes(8, byteorder="little")
        if extra_payment_IDs:
            extra += (
                bytes([0x02]) + to_var_int(len(extra_payment_IDs)) + extra_payment_IDs
            )

        return MoneroSpendableTransaction(
            inputs, amount_keys, output_keys, output_amounts, extra, fee
        )

    def sign(
        self,
        tx: SpendableTransaction,
        private_view_key: bytes,
        private_spend_key: bytes,
    ) -> None:
        """Sign a MoneroSpendableTransaction."""

        if not isinstance(tx, MoneroSpendableTransaction):
            raise Exception("Was told to sign a non-Monero Spendable Transaction.")

        # Generate the key image.
        for i in range(len(tx.inputs)):
            tx.inputs[i].image = self.generate_key_image(
                tx.inputs[i], private_view_key, private_spend_key
            )

        # Sort the inputs by their key images.
        tx.inputs.sort(key=lambda i: i.image, reverse=True)

        # Regenerate the private keys and extract the amounts/indexes/ring.
        input_keys: List[Tuple[bytes, bytes]] = []
        input_amounts: List[int] = []
        input_indexes: List[int] = []
        ring: List[List[List[bytes]]] = []
        for input_i in tx.inputs:
            if isinstance(input_i, MoneroOutputInfo):
                input_keys.append(
                    (
                        self.generate_input_key(
                            input_i, private_view_key, private_spend_key
                        ),
                        input_i.commitment,
                    )
                )
            else:
                raise Exception("MoneroCrypto handed a non-Monero OutputInfo.")

            input_amounts.append(input_i.amount)
            input_indexes.append(input_i.index.index)
            ring.append(input_i.ring)

        # Create the RingCT signatures.
        tx.signatures = generate_ringct_signatures(
            tx.serialize()[0],
            input_keys,
            tx.output_keys,
            tx.amount_keys,
            ring,
            input_indexes,
            input_amounts,
            tx.output_amounts,
            tx.fee,
        )
