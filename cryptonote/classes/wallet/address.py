"""Address file. Handles address encoding and decoding."""

# Types.
from typing import Tuple, Optional, Any

# Keccak hash function.
from Cryptodome.Hash import keccak

# Crypto class.
from cryptonote.crypto.crypto import Crypto

# Base58 Character Set.
BASE58: str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# AddressError.
class AddressError(Exception):
    """AddressError Exception. Used when an invalid address is parsed."""


# Address class.
class Address:
    """Contains address info and the serialized address."""

    def __init__(
        self,
        crypto: Crypto,
        key_pair: Tuple[bytes, bytes],
        payment_id: Optional[bytes] = None,
        network_byte: Optional[bytes] = None,
        address: Optional[str] = None,
    ) -> None:
        """Converts a ViewKey and a SpendKey into an address."""

        # Verify the data lengths
        if len(crypto.network_bytes) not in {2, 3}:
            raise Exception("Invalid network bytes.")
        if (len(key_pair[0]) != 32) or (len(key_pair[1]) != 32):
            raise Exception("Invalid key pair length.")
        if (payment_id is not None) and (
            len(payment_id) not in crypto.payment_id_lengths
        ):
            raise Exception("Invalid payment ID.")

        self.network: bytes
        self.view_key: bytes = key_pair[0]
        self.spend_key: bytes = key_pair[1]
        self.payment_id: Optional[bytes] = payment_id

        # If we were passed in an address, verify it against the regex.
        if address is not None:
            # Require a network byte was also specified.
            if network_byte is None:
                raise Exception("Address parsed without a specified network byte.")

            if (not crypto.address_regex.match(address)) and (
                not crypto.integrated_address_regex.match(address)
            ):
                raise Exception("Invalid address used in constructor override.")

            # Set the network byte, address type, and address. Then return.
            self.network = network_byte
            self.address: str = address
            return

        # If there's a payment ID, set the network byte to integrated address.
        # Else, set it to subaddress if there is a subaddress byte.
        # Else, set it to regular address.
        if self.payment_id is not None:
            self.network = crypto.network_bytes[1]
        else:
            if len(crypto.network_bytes) == 3:
                self.network = crypto.network_bytes[2]
            else:
                self.network = crypto.network_bytes[0]

        # If a network byte was specified, despite an address not being specified, use that.
        if network_byte is not None:
            self.network = network_byte
            if self.network not in crypto.network_bytes:
                raise Exception("Address doesn't have a valid network byte.")

        # Get the data to be encoded.
        data: bytes = self.network
        if (self.payment_id is not None) and crypto.payment_id_leading:
            data += self.payment_id
        data += self.spend_key + self.view_key
        if (self.payment_id is not None) and (not crypto.payment_id_leading):
            data += self.payment_id

        # Add the checksum.
        checksum_hash: Any = keccak.new(digest_bits=256)
        checksum_hash.update(data)
        data += checksum_hash.digest()[0:4]

        # Convert the bytes to Base58.
        result: str = ""
        for i in range(0, len(data), 8):
            block: bytes = data[i : i + 8]
            blockInt: int = int.from_bytes(block, byteorder="big")
            blockStr: str = ""

            remainder: int
            while blockInt > 0:
                remainder = blockInt % 58
                blockInt = blockInt // 58
                blockStr += BASE58[remainder]

            # Pad the block as needed.
            if len(block) == 8:
                while len(blockStr) < 11:
                    blockStr += BASE58[0]
            elif len(block) == 5:
                while len(blockStr) < 7:
                    blockStr += BASE58[0]

            result += blockStr[::-1]

        # Set the address.
        self.address: str = result

    @staticmethod
    def parse(crypto: Crypto, address: str) -> Any:
        """
        Parse an address and extract the contained info.
        Raises AddressError if it fails to parse the address.
        """

        # Check the address against the regex.
        if (not crypto.address_regex.match(address)) and (
            not crypto.integrated_address_regex.match(address)
        ):
            raise AddressError("Invalid address.")

        # Convert the Base58 to bytes.
        data: bytes = bytes()
        for i in range(0, len(address), 11):
            blockStr: str = address[i : i + 11]
            blockInt: int = 0

            multi = 1
            for char in blockStr[::-1]:
                blockInt += multi * BASE58.index(char)
                multi = multi * 58

            if len(blockStr) == 11:
                data += blockInt.to_bytes(8, byteorder="big")
            elif len(blockStr) == 7:
                data += blockInt.to_bytes(5, byteorder="big")

        # Extract the payment ID and checksum.
        payment_id: Optional[bytes]
        if crypto.payment_id_leading:
            payment_id = data[crypto.network_byte_length : -68]
        else:
            payment_id = data[(crypto.network_byte_length + 64) : -4]
        if not payment_id:
            payment_id = None
        checksum: bytes = data[-4:]

        # Check the checksum.
        checksum_hash: Any = keccak.new(digest_bits=256)
        checksum_hash.update(data[0:-4])
        if checksum_hash.digest()[0:4] != checksum:
            raise AddressError("Invalid address checksum.")

        # Verify the network byte is valid.
        network_byte: bytes = data[0 : crypto.network_byte_length]
        if (network_byte not in crypto.network_bytes) or (
            (payment_id is not None) and (network_byte != crypto.network_bytes[1])
        ):
            raise AddressError("Address doesn't have a valid network byte.")

        # Return the Address.
        view_key: bytes
        spend_key: bytes
        if crypto.payment_id_leading:
            view_key = data[-36:-4]
            spend_key = data[-68:-36]
        else:
            view_key = data[
                (crypto.network_byte_length + 32) : (crypto.network_byte_length + 64)
            ]
            spend_key = data[
                crypto.network_byte_length : (crypto.network_byte_length + 32)
            ]
        return Address(
            crypto, (view_key, spend_key), payment_id, network_byte, address,
        )

    def __eq__(self, other: Any) -> bool:
        """Equality operator. Used by the tests."""

        if (
            (not isinstance(other, Address))
            or (self.network != other.network)
            or (self.view_key != other.view_key)
            or (self.spend_key != other.spend_key)
            or (self.payment_id != other.payment_id)
            or (self.address != other.address)
        ):
            return False
        return True

    def __str__(self):
        return self.address
