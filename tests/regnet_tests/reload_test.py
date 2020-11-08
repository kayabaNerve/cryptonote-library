# JSON standard lib.
import json

# pytest lib.
import pytest

# WatchWallet class.
from cryptonote.classes.wallet.wallet import WatchWallet

# Test fixtures.
from tests.regnet_tests.conftest import Harness


@pytest.mark.second_to_last
def reload_test(harness: Harness) -> None:
    # Now that we have a Wallet with a lot of history, reload the state.
    reloaded: WatchWallet = WatchWallet(
        harness.crypto,
        harness.rpc,
        harness.watch.private_view_key,
        harness.watch.public_spend_key,
        json.loads(json.dumps(harness.watch.save_state())),
    )

    assert harness.watch.last_block == reloaded.last_block
    assert harness.watch.confirmation_queue == reloaded.confirmation_queue
    assert harness.watch.inputs == reloaded.inputs
    assert harness.watch.unique_factors == reloaded.unique_factors
