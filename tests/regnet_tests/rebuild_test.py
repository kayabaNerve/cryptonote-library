# JSON standard lib.
import json

# pytest lib.
import pytest

# WatchWallet class.
from cryptonote.classes.wallet.wallet import WatchWallet

# Test fixtures.
from tests.regnet_tests.conftest import Harness


@pytest.mark.last
def rebuild_test(harness: Harness) -> None:
    # Test rebuilding the state.
    reloaded = WatchWallet(
        harness.crypto,
        harness.rpc,
        harness.wallet.private_view_key,
        harness.wallet.public_spend_key,
        1,
    )
    reloaded.poll_blocks()
    reloaded.rebuild_input_states(
        json.loads(
            json.dumps(
                harness.wallet.generate_key_images(
                    json.loads(json.dumps(reloaded.save_state()["inputs"]))
                )
            )
        )
    )

    assert harness.watch.last_block == reloaded.last_block
    assert harness.watch.confirmation_queue == reloaded.confirmation_queue
    assert harness.watch.inputs == reloaded.inputs
    assert harness.watch.unique_factors == reloaded.unique_factors
