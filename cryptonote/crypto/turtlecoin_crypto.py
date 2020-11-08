"""TurtlecoinCrypto class file."""

# Types.
from typing import Set, List, Any

# Regex standard lib.
import re

# MoneroPaymentIDCrypto class.
from cryptonote.crypto.monero_payment_id_crypto import MoneroPaymentIDCrypto


class TurtlecoinCrypto(MoneroPaymentIDCrypto):
    """
    TurtlecoinCrypto class.
    Currently based off MoneroPaymentIDCrypto in order to implement all abstract methods.
    """

    def __init__(self, mainnet: bool = True):
        """Initializes the various network properties of the Turtlecoin network."""

        self.network_bytes_property: List[bytes] = [
            bytes.fromhex("9df6ee01"),
            bytes.fromhex("9df6ee01"),
        ]

        self.address_regex_property: Any = re.compile(
            r"^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{99}$"
        )
        self.integrated_address_regex_property: Any = re.compile(
            r"^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{187}$"
        )
        self.payment_id_lengths_property: Set[int] = {64}

    @property
    def network_byte_length(self) -> int:
        """Length of the network bytes for this coin."""

        return 4

    @property
    def payment_id_leading(self) -> bool:
        """Whether or not the payment ID leads the keys in the address."""

        return True
