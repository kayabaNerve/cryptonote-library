"""Crypto class file."""

# Types.
from typing import Dict, Set, List, Tuple, Optional, Union, Any

# Enum class.
from enum import Enum

# Abstract class standard lib.
from abc import ABC, abstractmethod

# Transaction class.
from cryptonote.classes.blockchain import OutputIndex, Transaction


class InputState(Enum):
    Spendable = 0
    Transmitted = 1
    Spent = 2


class OutputInfo:
    # Actual output info.
    index: OutputIndex
    amount: int
    spend_key: bytes

    # Current state, used to decide whether or not the output is usable as an input.
    state: InputState

    # Temporary storage for variables only used when signing.
    # Signing changes the order of the inputs so it's important to properly connect data.
    # The easiest way to do this is simply to embed the data in the OutputInfo.
    mixins: List[int]
    ring: List[List[bytes]]
    image: bytes

    def __init__(
        self, index: OutputIndex, timelock: int, amount: int, spend_key: bytes
    ) -> None:
        """Constructor."""

        self.index = index
        self.timelock = timelock
        self.amount = amount
        self.spend_key = spend_key

        self.state = InputState(0)

    def to_json(self) -> Dict[str, Any]:
        """Convert an OutputInfo to a transmittable format."""

        return {
            **self.index.to_json(),
            "timelock": self.timelock,
            "amount": self.amount,
            "spend_key": self.spend_key.hex(),
            "state": self.state.value,
        }

    def __eq__(self, other: Any) -> bool:
        """Compare two OutputInfos. Used to compare the Dict of spendable outputs."""

        return (self.index, self.timelock, self.amount, self.spend_key, self.state) == (
            other.index,
            other.timelock,
            other.amount,
            other.spend_key,
            other.state,
        )

    @staticmethod
    def from_json(output: Dict[str, Any]) -> Any:
        """Load an OutputInfo from JSON."""

        result: Any = OutputInfo(
            OutputIndex(bytes.fromhex(output["hash"]), output["index"]),
            output["timelock"],
            output["amount"],
            bytes.fromhex(output["spend_key"]),
        )
        result.state = InputState(output["state"])
        return result


class SpendableOutput:
    """SpendableOutput class. Contains the address and amount."""

    def __init__(
        self,
        network: bytes,
        view_key: bytes,
        spend_key: bytes,
        payment_id: Optional[bytes],
        amount: int,
    ) -> None:
        """Constructor."""

        # Directly embeds Address as Address requires Crypto.
        self.network: bytes = network
        self.view_key: bytes = view_key
        self.spend_key: bytes = spend_key
        self.payment_id: Optional[bytes] = payment_id

        self.amount: int = amount


class SpendableTransaction(ABC):
    """
    SpendableTransaction class.
    Represents a Transaction created by this library which can be signed and serialized.
    """

    @property
    @abstractmethod
    def hash(self) -> bytes:
        """Get the hash of a SpendableTransaction."""

    @abstractmethod
    def serialize(self) -> Tuple[bytes, bytes]:
        """Serialize a SpendableTransaction."""


class Crypto(ABC):
    """
    Crypto class.
    Implements the various cryptographic operations used by a coin.
    """

    # Abstract methods inheritors must implement.
    def __init__(self, mainnet: bool = True) -> None:
        """Constructor."""

    @property
    @abstractmethod
    def network_byte_length(self) -> int:
        """Length of the network bytes for this coin."""

    @property
    @abstractmethod
    def network_bytes(self) -> List[bytes]:
        """
        Network bytes used by the coin.
        Standard address, payment ID address, subaddress.
        Payment ID coins use the first two, subaddress coins use all three.
        """

    @property
    @abstractmethod
    def address_regex(self) -> Any:
        """Regex to check the validity of an address or subaddress."""

    @property
    @abstractmethod
    def integrated_address_regex(self) -> Any:
        """Regex to check the validity of an integrated address."""

    @property
    @abstractmethod
    def payment_id_leading(self) -> bool:
        """Whether or not the payment ID leads the keys in the address."""

    @property
    @abstractmethod
    def payment_id_lengths(self) -> Set[int]:
        """Valid lengths for a payment ID."""

    @property
    @abstractmethod
    def lock_blocks(self) -> int:
        """Amount of Blocks TXOs are locked for."""

    @property
    @abstractmethod
    def miner_lock_blocks(self) -> int:
        """Amount of Blocks Miner TXOs are locked for."""

    @property
    @abstractmethod
    def oldest_txo(self) -> int:
        """Oldest TXO to use for a mixin."""

    @property
    @abstractmethod
    def required_mixins(self) -> int:
        """Required mixins per input."""

    @property
    @abstractmethod
    def confirmations(self) -> int:
        """Required confirmations."""

    @abstractmethod
    def output_from_json(self, output: Dict[str, Any]) -> OutputInfo:
        """Load an OutputInfo from JSON."""

    @abstractmethod
    def new_address(
        self,
        key_pair: Tuple[bytes, bytes],
        unique_factor: Union[Tuple[int, int], bytes],
    ) -> Tuple[Tuple[bytes, bytes], Optional[bytes], bytes, bytes]:
        """
        Constructs a new address with the root key pair and the index.
        Returns the key pair, payment ID, network byte, and unique factor to watch for.
        """

    @abstractmethod
    def get_payment_IDs(
        self,
        shared_keys: List[bytes],
        payment_IDs: List[bytes],
    ) -> List[bytes]:
        """Returns the Transaction's payment IDs, decrypted if necessary."""

    @abstractmethod
    def create_shared_key(self, scalar: bytes, point: bytes) -> bytes:
        """Created the shared key of which there is one per R."""

    @abstractmethod
    def can_spend_output(
        self,
        unique_factors: Dict[bytes, Tuple[int, int]],
        shared_key: bytes,
        tx: Transaction,
        o: int,
    ) -> Optional[OutputInfo]:
        """Checks if an output is spendable and returns the relevant info."""

    @abstractmethod
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

    @abstractmethod
    def generate_input_key(
        self, output: OutputInfo, private_view_key: bytes, private_spend_key: bytes
    ) -> bytes:
        """Generate the one-time private key associated with an input."""

    @abstractmethod
    def generate_key_image(
        self, output: OutputInfo, private_view_key: bytes, private_spend_key: bytes
    ) -> bytes:
        """Calculate the key image for the specified input."""

    @abstractmethod
    def spendable_transaction(
        self,
        inputs: List[OutputInfo],
        mixins: List[List[int]],
        outputs: List[SpendableOutput],
        ring: List[List[List[bytes]]],
        change: SpendableOutput,
        fee: int,
    ) -> SpendableTransaction:
        """Create a SpendableTransaction."""

    @abstractmethod
    def sign(
        self,
        tx: SpendableTransaction,
        private_view_key: bytes,
        private_spend_key: bytes,
    ) -> None:
        """Sign a SpendableTransaction."""
