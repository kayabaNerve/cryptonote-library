# Types.
from typing import Dict, Any

# Address class.
from cryptonote.classes.wallet.address import Address

# TurtlecoinCrypto class.
from cryptonote.crypto.turtlecoin_crypto import TurtlecoinCrypto

# TurtlecoinRPC class.
from cryptonote.rpc.turtlecoin_rpc import TurtlecoinRPC

# Wallet classes.
from cryptonote.classes.wallet.wallet import WatchWallet, Wallet

# Key generation test.
def TRTL_key_generation(turtlecoin_crypto: TurtlecoinCrypto, constants: Dict[str, Any]):
    wallet: Wallet = Wallet(turtlecoin_crypto, constants["PRIVATE_SPEND_KEY"])
    watch: WatchWallet = WatchWallet(
        turtlecoin_crypto,
        TurtlecoinRPC("", -1),
        wallet.private_view_key,
        wallet.public_spend_key,
        -1,
    )

    assert wallet.private_spend_key == constants["PRIVATE_SPEND_KEY"]
    assert wallet.public_spend_key == constants["PUBLIC_SPEND_KEY"]
    assert watch.public_spend_key == constants["PUBLIC_SPEND_KEY"]

    assert wallet.private_view_key == constants["PRIVATE_VIEW_KEY"]
    assert wallet.public_view_key == constants["PUBLIC_VIEW_KEY"]
    assert watch.private_view_key == constants["PRIVATE_VIEW_KEY"]
    assert watch.public_view_key == constants["PUBLIC_VIEW_KEY"]


# Test address vectors.
def TRTL_address_test(turtlecoin_crypto: TurtlecoinCrypto, constants: Dict[str, Any]):
    watch: WatchWallet = WatchWallet(
        turtlecoin_crypto,
        TurtlecoinRPC("", -1),
        constants["PRIVATE_VIEW_KEY"],
        constants["PUBLIC_SPEND_KEY"],
        -1,
    )

    address: Address = watch.new_address(b"")
    assert address.network == turtlecoin_crypto.network_bytes[0]
    assert address.payment_id is None
    assert address.address == constants["TRTL"]["ADDRESS"]
    assert address == Address.parse(turtlecoin_crypto, constants["TRTL"]["ADDRESS"])


# Test payment ID vectors.
def TRTL_integrated_address_test(
    turtlecoin_crypto: TurtlecoinCrypto, constants: Dict[str, Any]
):
    watch: WatchWallet = WatchWallet(
        turtlecoin_crypto,
        TurtlecoinRPC("", -1),
        constants["PRIVATE_VIEW_KEY"],
        constants["PUBLIC_SPEND_KEY"],
        -1,
    )

    address: Address = watch.new_address(constants["TRTL"]["PAYMENT_ID"])
    assert address.network == turtlecoin_crypto.network_bytes[1]
    assert address.payment_id == constants["TRTL"]["PAYMENT_ID"]
    assert address.address == constants["TRTL"]["INTEGRATED_ADDRESS"]
    assert address == Address.parse(
        turtlecoin_crypto, constants["TRTL"]["INTEGRATED_ADDRESS"]
    )
