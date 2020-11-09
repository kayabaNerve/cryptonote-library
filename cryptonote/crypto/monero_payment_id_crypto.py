"""MoneroPaymentIDCrypto class file."""

# Types.
from typing import Set, List, Tuple, Optional, Union

# Ed25519 lib.
import cryptonote.lib.ed25519 as ed

# MoneroCrypto class.
from cryptonote.crypto.monero_crypto import (
    OutputInfo,
    MoneroOutputInfo,
    MoneroCrypto,
)


class MoneroPaymentIDCrypto(MoneroCrypto):
    """
    MoneroPaymentIDCrypto class.
    Implements the various cryptographic operations used by Monero, yet with payment IDs instead of subaddresses.
    """

    def new_address(
        self,
        key_pair: Tuple[bytes, bytes],
        unique_factor: Union[Tuple[int, int], bytes],
    ) -> Tuple[Tuple[bytes, bytes], Optional[bytes], bytes, bytes]:
        """
        Constructs a new address with the root key pair and the index.
        Returns the key pair, payment ID, network byte, and unique factor to watch for.
        """

        if isinstance(unique_factor, bytes):
            if len(unique_factor) == 0:
                return (
                    (
                        ed.public_from_secret(key_pair[0]),
                        key_pair[1],
                    ),
                    None,
                    self.network_bytes[0],
                    key_pair[1],
                )
            else:
                return (
                    (
                        ed.public_from_secret(key_pair[0]),
                        key_pair[1],
                    ),
                    unique_factor,
                    self.network_bytes[1],
                    unique_factor,
                )
        else:
            raise Exception("Invalid unique factor.")

    def get_payment_IDs(
        self,
        shared_keys: List[bytes],
        payment_IDs: List[bytes],
    ) -> List[bytes]:
        """Returns the Transaction's payment IDs, decrypted if necessary."""

        # The payment ID is xor encrypted with:
        # H(8Ra || ENCRYPTED_PAYMENT_ID_TAIL)
        # where ENCRYPTED_PAYMENT_ID_TAIL is 0x8d.
        result: Set[bytes] = set({})
        for shared_key in shared_keys:
            for payment_id in payment_IDs:
                result.add(
                    (
                        int.from_bytes(payment_id, byteorder="little")
                        ^ int.from_bytes(
                            ed.H(shared_key + bytes([0x8D]))[0:8], byteorder="little"
                        )
                    ).to_bytes(8, byteorder="little")
                )
        return list(result)

    def generate_input_key(
        self,
        output: OutputInfo,
        private_view_key: bytes,
        private_spend_key: bytes,
    ) -> bytes:
        """Generate the one-time private key associated with an input."""

        if isinstance(output, MoneroOutputInfo):
            return ed.encodeint(
                (ed.decodeint(output.amount_key) + ed.decodeint(private_spend_key))
                % ed.l
            )
        else:
            raise Exception("MoneroCrypto handed a non-Monero OutputInfo.")
