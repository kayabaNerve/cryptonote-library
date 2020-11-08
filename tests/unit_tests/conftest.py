# Types.
from typing import Dict, Any

# pytest lib.
import pytest

# Crypto classes.
from cryptonote.crypto.monero_crypto import MoneroCrypto
from cryptonote.crypto.monero_payment_id_crypto import MoneroPaymentIDCrypto
from cryptonote.crypto.turtlecoin_crypto import TurtlecoinCrypto


@pytest.fixture
def monero_crypto() -> MoneroCrypto:
    return MoneroCrypto()


@pytest.fixture
def monero_payment_id_crypto() -> MoneroPaymentIDCrypto:
    return MoneroPaymentIDCrypto()


@pytest.fixture
def turtlecoin_crypto() -> TurtlecoinCrypto:
    return TurtlecoinCrypto()


@pytest.fixture
def constants() -> Dict[str, Any]:
    return {
        "PRIVATE_SPEND_KEY": bytes.fromhex(
            "8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903"
        ),
        "PUBLIC_SPEND_KEY": bytes.fromhex(
            "f8631661f6ab4e6fda310c797330d86e23a682f20d5bc8cc27b18051191f16d7"
        ),
        "PRIVATE_VIEW_KEY": bytes.fromhex(
            "99c57d1f0f997bc8ca98559a0ccc3fada3899756e63d1516dba58b7e468cfc05"
        ),
        "PUBLIC_VIEW_KEY": bytes.fromhex(
            "4a1535063ad1fee2dabbf909d4fd9a873e29541b401f0944754e17c9a41820ce"
        ),
        "XMR": {
            "ADDRESS": "4B33mFPMq6mKi7Eiyd5XuyKRVMGVZz1Rqb9ZTyGApXW5d1aT7UBDZ89ewmnWFkzJ5wPd2SFbn313vCT8a4E2Qf4KQH4pNey",
            "PAYMENT_ID": bytes.fromhex("b8963a57855cf73f"),
            "INTEGRATED_ADDRESS": "4Ljin4CrSNHKi7Eiyd5XuyKRVMGVZz1Rqb9ZTyGApXW5d1aT7UBDZ89ewmnWFkzJ5wPd2SFbn313vCT8a4E2Qf4KbaTH6MnpXSn88oBX35",
            "SUBADDRESSES": [
                (
                    (0, 1),
                    "8C5zHM5ud8nGC4hC2ULiBLSWx9infi8JUUmWEat4fcTf8J4H38iWYVdFmPCA9UmfLTZxD43RsyKnGEdZkoGij6csDeUnbEB",
                ),
                (
                    (0, 256),
                    "883z7xonbVBGXpsatJZ53vcDiXQkrkTHUHPxrdrHXiPnZY8DMaYJ7a88C5ovncy5zHWkLc2cQ2hUoaKYCjFtjwFV4vtcpiF",
                ),
                (
                    (256, 1),
                    "87X4ksVMRv2UGhHcgVjY6KJDjqP9S4zrCNkmomL1ziQVeZXF3RXbAx7i2rRt3UU5eXDzG9TWZ6Rk1Fyg6pZrAKQCNfLrSne",
                ),
                (
                    (256, 256),
                    "86gYdT7yqDJUXegizt1vbF3YKz5qSYVaMB61DFBDzrpVEpYgDbmuXJbXE77LQfAygrVGwYpw8hxxx9DRTiyHAemA8B5yBAq",
                ),
            ],
        },
        "TRTL": {
            "ADDRESS": "TRTLv3pt1oEiFzzeqx8a3SLGViScSRxdX3EbUuByN98L5Ci9crwm6joAqdaARMMmMrcdH1UTiRgi6Bj4GQJovygCUSvM9qR5hzk",
            "PAYMENT_ID": "D140E38B529BA3E0FF10B21BE31AA8101EF6582704F1AAE0BA8476A28F77C209".encode(
                "utf-8"
            ),
            "INTEGRATED_ADDRESS": "TRTLuyDjVGBCaKzUxwTEdwBuXQsBaEkfqC5BiUWCLBNGBuiEJsxgT5X9uJAes5ykvcBv4BbNBqxpKAEdFBQrnJ9CCEtNyVXchLUiFzzeqx8a3SLGViScSRxdX3EbUuByN98L5Ci9crwm6joAqdaARMMmMrcdH1UTiRgi6Bj4GQJovygCUSvM9qJY4w2",
        },
    }
