"""Transaction/BlockHeader/Block class file."""

# Types.
from typing import Dict, List, Tuple, Union, Any

# VarInt lib.
from cryptonote.lib.var_int import from_var_int


class MinerInput:
    """MinerInput class. Contains an input from a miner Transaction (the block height)."""

    def __init__(self, height: int) -> None:
        """Constructor."""

        self.height: int = height


class MinerOutput:
    """MinerOutput class. Contains an output from a miner Transaction (the key and amount)."""

    def __init__(self, key: bytes, amount: int) -> None:
        """Constructor."""

        self.key: bytes = key
        self.amount: int = amount


class Input:
    """Input class. Contains an amount, list of mixins, and key image."""

    def __init__(self, mixins: List[int], image: bytes) -> None:
        """Constructor."""

        self.mixins: List[int] = mixins
        self.image: bytes = image


class Output:
    """Output class. Contains an output key, encrypted amount, and commitment."""

    def __init__(self, key: bytes, amount: bytes, commitment: bytes) -> None:
        """Constructor."""

        self.key: bytes = key
        self.amount: bytes = amount
        self.commitment: bytes = commitment


AbstractInput = Union[Input, MinerInput]
AbstractOutput = Union[Output, MinerOutput]


class OutputIndex:
    """OutputIndex class. Specifies an output by a Transaction hash and integer index."""

    def __init__(self, tx_hash: bytes, index: int) -> None:
        """Constructor."""
        self.tx_hash: bytes = tx_hash
        self.index: int = index

    def to_json(self) -> Dict[str, Any]:
        """Convert an OutputIndex to a transmittable format."""

        return {"hash": self.tx_hash.hex(), "index": self.index}

    def __hash__(self) -> int:
        """Hash an OutputIndex so it can be used as a key in a Dict."""

        return hash((self.tx_hash, self.index))

    def __eq__(self, other: Any) -> bool:
        """Compare two OutputIndexes. Necessary to be usable as a key in a Dict."""

        return (self.tx_hash, self.index) == (other.tx_hash, other.index)


class Transaction:
    """Transaction class."""

    def __init__(self, tx_hash: bytes, json: Dict[str, Any]) -> None:
        """Constructor."""

        # Hash.
        self.tx_hash: bytes = tx_hash

        # Unlock time.
        self.unlock_time: int = json["unlock_time"]

        # Parse the inputs.
        self.inputs: List[AbstractInput] = []
        if "gen" in json["vin"][0]:
            self.inputs.append(MinerInput(json["vin"][0]["gen"]["height"]))
        else:
            for i in range(len(json["vin"])):
                self.inputs.append(
                    Input(
                        json["vin"][i]["key"]["key_offsets"],
                        bytes.fromhex(json["vin"][i]["key"]["k_image"]),
                    )
                )

        # Parse the outputs.
        self.outputs: List[AbstractOutput] = []
        for o in range(len(json["vout"])):
            if "gen" in json["vin"][0]:
                self.outputs.append(
                    MinerOutput(
                        bytes.fromhex(json["vout"][o]["target"]["key"]),
                        json["vout"][o]["amount"],
                    )
                )
            else:
                self.outputs.append(
                    Output(
                        bytes.fromhex(json["vout"][o]["target"]["key"]),
                        bytes.fromhex(json["rct_signatures"]["ecdhInfo"][o]["amount"]),
                        bytes.fromhex(json["rct_signatures"]["outPk"][o]),
                    )
                )

        # Parse extra.
        self.extra: bytes = bytes(json["extra"])

        self.Rs: List[bytes] = []
        self.payment_IDs: List[bytes] = []

        def skip_tag(cursor: int) -> int:
            tag_or_length: Tuple[int, int] = from_var_int(self.extra, cursor)
            cursor = tag_or_length[1]
            tag_or_length = from_var_int(self.extra, cursor)
            cursor = tag_or_length[1] + tag_or_length[0]
            return cursor

        def check_R(R: bytes) -> bool:
            if len(R) != 32:
                return False
            # This originally also called decodepoint which then calls isoncurve.
            # It always errored, even with valid Rs.
            return True

        try:
            cursor: int = 0
            while cursor < len(self.extra):
                tag: Tuple[int, int] = from_var_int(self.extra, cursor)
                cursor = tag[1]

                # TX_EXTRA_TAG_PADDING
                if tag[0] == 0x00:
                    cursor += 8 + int.from_bytes(
                        self.extra[cursor : cursor + 8], byteorder="little"
                    )

                # TX_EXTRA_TAG_PUBKEY
                elif tag[0] == 0x01:
                    potential_R: bytes = self.extra[cursor : cursor + 32]
                    if not check_R(potential_R):
                        break

                    self.Rs.append(potential_R)
                    cursor += 32

                # TX_EXTRA_NONCE
                elif tag[0] == 0x02:
                    length: Tuple[int, int] = from_var_int(self.extra, cursor)
                    cursor = length[1]
                    end: int = cursor + length[0]

                    while cursor + 9 <= end:
                        # Unencrypted payment IDs are a 1-byte header and 32-byte value.
                        # Encrypted payment IDs are a 1-byte header and 8-byte value.

                        # TX_EXTRA_NONCE_PAYMENT_ID
                        if self.extra[cursor] == 0x00:
                            self.payment_IDs.append(
                                self.extra[cursor + 1 : cursor + 33]
                            )
                            cursor += 33
                            continue
                        # TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID
                        if self.extra[cursor] == 0x01:
                            self.payment_IDs.append(self.extra[cursor + 1 : cursor + 9])
                            cursor += 9
                        else:
                            break

                    cursor = end

                # TX_EXTRA_TAG_ADDITIONAL_PUBKEYS
                elif tag[0] == 0x04:
                    keys: Tuple[int, int] = from_var_int(self.extra, cursor)
                    cursor = keys[1]

                    for _ in range(keys[0]):
                        potential_R: bytes = self.extra[cursor : cursor + 32]
                        if not check_R(potential_R):
                            break

                        self.Rs.append(potential_R)
                        cursor += 32

                # TX_EXTRA_MERGE_MINING_TAG, TX_EXTRA_MYSTERIOUS_MINERGATE_TAG
                elif (tag[0] == 0x03) or (tag[0] == tag[0] == 0xDE):
                    cursor = skip_tag(cursor)

                else:
                    break
        except IndexError:
            pass

        # Remove duplicate Rs.
        # This isn't necessarily secure due to the existence of torsion points, where effectively duplicate Rs can remain.
        # It must be partnered with a check if we already found an output was spendable.
        # Since that check would be comprehensive, this is effectively an optimization.
        self.Rs = list(set(self.Rs))
        # Remove duplicate payment IDs.
        self.payment_IDs = list(set(self.payment_IDs))


class BlockHeader:
    """BlockHeader class."""

    def __init__(self, json: Dict[str, Any]) -> None:
        """Constructor."""

        # Chain info.
        self.hash: bytes = bytes.fromhex(json["hash"])
        self.height: int = json["height"]
        self.depth: int = json["depth"]
        self.previous: bytes = bytes.fromhex(json["prev_hash"])
        self.time: int = json["timestamp"]
        self.orphaned: bool = json["orphan_status"]

        # Mining info.
        self.cummulative_difficulty: int = json["cumulative_difficulty"]
        self.difficulty: int = json["difficulty"]
        self.miner_tx_hash: bytes = bytes.fromhex(json["miner_tx_hash"])

        # Transactions.
        self.txs: int = json["num_txes"]

    def __eq__(self, other: Any) -> bool:
        """Equality operator. Used by the tests."""

        if (
            (not isinstance(other, BlockHeader))
            or (self.hash != other.hash)
            or (self.height != other.height)
            or (self.depth != other.depth)
            or (self.previous != other.previous)
            or (self.time != other.time)
            or (self.orphaned != other.orphaned)
            or (self.cummulative_difficulty != other.cummulative_difficulty)
            or (self.difficulty != other.difficulty)
            or (self.miner_tx_hash != other.miner_tx_hash)
            or (self.txs != other.txs)
        ):
            return False
        return True


class Block:
    """Block class."""

    def __init__(self, header: BlockHeader, json: Dict[str, Any]) -> None:
        """Constructor."""

        self.header: BlockHeader = header
        self.hashes: List[bytes] = []
        for tx_hash in json["tx_hashes"]:
            self.hashes.append(bytes.fromhex(tx_hash))

    def __eq__(self, other: Any) -> bool:
        """Equality operator. Used by the tests."""

        if (
            (not isinstance(other, Block))
            or (self.header != other.header)
            or (self.hashes != other.hashes)
        ):
            return False
        return True
