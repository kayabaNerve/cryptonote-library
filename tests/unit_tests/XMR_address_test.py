# Types.
from typing import Dict, List, Any

# Address class.
from cryptonote.classes.wallet.address import Address

# MoneroCrypto class.
from cryptonote.crypto.monero_crypto import MoneroCrypto

# MoneroRPC class.
from cryptonote.rpc.monero_rpc import MoneroRPC

# Wallet classes.
from cryptonote.classes.wallet.wallet import WatchWallet, Wallet

# Key generation test.
def XMR_key_generation(monero_crypto: MoneroCrypto, constants: Dict[str, Any]):
    wallet: Wallet = Wallet(monero_crypto, constants["PRIVATE_SPEND_KEY"])
    watch: WatchWallet = WatchWallet(
        monero_crypto,
        MoneroRPC("", -1),
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
def XMR_address_test(monero_crypto: MoneroCrypto, constants: Dict[str, Any]):
    watch: WatchWallet = WatchWallet(
        monero_crypto,
        MoneroRPC("", -1),
        constants["PRIVATE_VIEW_KEY"],
        constants["PUBLIC_SPEND_KEY"],
        -1,
    )

    address: Address = watch.new_address((0, 0))
    assert address.network == monero_crypto.network_bytes[0]
    assert address.payment_id is None
    assert address.address == constants["XMR"]["ADDRESS"]
    assert address == Address.parse(monero_crypto, constants["XMR"]["ADDRESS"])


# Test subaddress vectors.
def XMR_subaddress_address_test(monero_crypto: MoneroCrypto, constants: Dict[str, Any]):
    watch: WatchWallet = WatchWallet(
        monero_crypto,
        MoneroRPC("", -1),
        constants["PRIVATE_VIEW_KEY"],
        constants["PUBLIC_SPEND_KEY"],
        -1,
    )

    for subaddress in constants["XMR"]["SUBADDRESSES"]:
        address: Address = watch.new_address(subaddress[0])
        assert address.payment_id is None
        assert address.address == subaddress[1]
        assert address.address == subaddress[1]
        assert address == Address.parse(monero_crypto, subaddress[1])


# Test payment ID vectors.
def XMR_integrated_address_test(
    monero_payment_id_crypto: MoneroCrypto, constants: Dict[str, Any]
):
    watch: WatchWallet = WatchWallet(
        monero_payment_id_crypto,
        MoneroRPC("", -1),
        constants["PRIVATE_VIEW_KEY"],
        constants["PUBLIC_SPEND_KEY"],
        -1,
    )

    address: Address = watch.new_address(constants["XMR"]["PAYMENT_ID"])
    assert address.network == monero_payment_id_crypto.network_bytes[1]
    assert address.payment_id == constants["XMR"]["PAYMENT_ID"]
    assert address.address == constants["XMR"]["INTEGRATED_ADDRESS"]
    assert address == Address.parse(
        monero_payment_id_crypto, constants["XMR"]["INTEGRATED_ADDRESS"]
    )
