# CryptoNote Library

Written over a few months in 2019. Internally abstracted For CryptoNote in general, yet fully implemented for Monero v12. Wallet and WatchWallet functionality, not using Monero's wallet2 API/an external node. It's Python combined with a wrapper around the C for key image/RingCT signature generation. This makes it notable for providing a much larger amount of functionality independently, not to mention further context on Monero's internal API.

Porting it to the latest Monero version would require updating the signature structures/serializations. It MAY require updating the C API beyond these structs, yet it may be the same. That would be extremely beneficial due to the time spent figuring out those internal function calls.

This is not actively maintained, will likely throw a ton of complaints against the latest Pyright version as it updates quite frequently, and does not use virtualenv. Anyone is welcome to create PRs, yet it isn't something which will be treated with the utmost urgency.

### Requirements

- Ubuntu/Arch Linux.
- Python 3.6 or newer and a matching pip
- A Python app which doesn't change its current working directory (due to how the CDLLs are loaded)

### Installation

Install compilation dependencies:

```
apt-get install build-essential cmake pkg-config libboost-all-dev libssl-dev libzmq3-dev libpgm-dev libunbound-dev libsodium-dev
```

```
pacman -S base-devel cmake boost openssl zeromq libpgm unbound libsodium
```

Install and compile for development:

```
git clone git@github.com:kayabaNerve/cryptonote-library.git
cd cryptonote-library
python3 -m pip install --user -e .
```

### Run tests

Tests are handled by the pytest library and can be run with the following command:

```
python3 -m pytest
```

Before running them, please spawn a debug Monero daemon with a fresh data directory and the `--regtest --fixed-difficulty 1 --offline` flags.

### Static Typing

This library supports static typing via both Pyright (`pyright -p .`) and MyPy (`mypy --config-file mypy.ini --namespace-packages .`).

### Styling

This library is automatically formatted by Black (`black .`).

### Caveats

- Monero requires selected mixins, by median, be within the last 40% of outputs. This library doesn't handle this, instead trusting that the defined oldest output is within the last 40% of outputs.

- Monero selects half its mixins from X to Y and then half from X to Z, where is X is the start of mixin-able outputs, Y is one week ago, and Z is now. This library selects all 10 from X to Z. This causes the real output to frequently be the last mixin.

- Monero has a minimum fee this library checks against. Not all CryptoNote coins have this functionality (Turtlecoin doesn't). To implement the non-existent RPC route/calculation on such coins, have the RPC route return (1, 1) and the fee calculation function return 0.

- Monero locks all outputs for 10 blocks. This library doesn't handle that check whatsoever. An external block queue must be set up to wait until 10 blocks pass before handling its transactions.

- This library uses the root address (unmodified view/spend key with no payment ID) for change. On subaddress networks, we have the ability to determine the output destination no matter what other outputs exists/what's in extra (assuming correct R encoding). On payment ID networks, we can't link payment IDs to a specific output. Therefore, on payment ID networks, a withdraw to another address managed by this library will produce a Transaction with two spendable outputs yet only one payment ID. Attributing both spendable outputs to the account behind the payment ID will accordingly cause funds to be reported multiple times.

- This library is slow. Checking Monero transactions is an expensive operation. It takes a couple seconds per transaction because it does all Ed25519 operations in pure Python. The only operations not performed in Python are key image generation and RingCT signing. This was done for two reasons: simplicity and configurability. Thanks to being in Python, it's very easy to update the various formulas in case other CryptoNote coins differ from Monero. In order to speed the library up, moving from Python to the already used Monero libraries is an extremely viable option.
