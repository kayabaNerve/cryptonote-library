"""MoneroRPC class file."""

# Types.
from typing import Dict, List, Tuple, Any

# JSON standard lib.
import json

# Blockchain classes.
from cryptonote.classes.blockchain import Transaction
from cryptonote.classes.blockchain import BlockHeader, Block

# RPC class.
from cryptonote.rpc.rpc import RPC


class MoneroRPC(RPC):
    """Monero RPC. Only provides methods available by Monero."""

    def get_info(self) -> Dict[str, Any]:
        """Get info about the node."""

        return self.jsonrpc_request("get_info")

    def generate_blocks(self, count: int, address: str) -> Dict[str, Any]:
        """Get info about the node."""

        return self.jsonrpc_request(
            "generateblocks",
            {
                "wallet_address": address,
                "amount_of_blocks": count,
                "reserve_size": 20,
                "prev_block": "",
                "starting_nonce": 0,
            },
        )

    def get_raw_block(self, block_hash: bytes) -> bytes:
        """Get a raw block by its hash."""

        return bytes.fromhex(
            self.jsonrpc_request("get_block", {"hash": block_hash.hex()})["blob"]
        )

    def publish_block(self, block: bytes) -> None:
        """Publish a raw block."""

        self.jsonrpc_request("submit_block", [block.hex()])

    def get_block_count(self) -> int:
        """Get the Block count."""

        return self.jsonrpc_request("get_block_count")["count"]

    def get_block_hash(self, height: int) -> bytes:
        """Get a Block's hash by it's height."""

        return bytes.fromhex(self.jsonrpc_request("on_get_block_hash", [height]))

    def get_last_block_header(self) -> BlockHeader:
        """Get the last BlockHeader."""

        return BlockHeader(
            self.jsonrpc_request("get_last_block_header")["block_header"]
        )

    def get_block_header_by_hash(self, block_hash: bytes) -> BlockHeader:
        """Get a BlockHeader by its hash."""

        return BlockHeader(
            self.jsonrpc_request(
                "get_block_header_by_hash", {"hash": block_hash.hex()}
            )["block_header"]
        )

    def get_block_header_by_height(self, height: int) -> BlockHeader:
        """Get a BlockHeader by its height."""

        return BlockHeader(
            self.jsonrpc_request("get_block_header_by_height", {"height": height})[
                "block_header"
            ]
        )

    def get_block(self, block_hash: bytes) -> Block:
        """Get a Block by its Hash."""

        res: Dict[str, Any] = self.jsonrpc_request(
            "get_block", {"hash": block_hash.hex()}
        )
        return Block(BlockHeader(res["block_header"]), json.loads(res["json"]))

    def get_transaction(self, tx_hash: bytes) -> Transaction:
        """Get a Transaction by its Hash."""

        return Transaction(
            tx_hash,
            json.loads(
                self.rpc_request(
                    "get_transactions",
                    {"txs_hashes": [tx_hash.hex()], "decode_as_json": True},
                )["txs"][0]["as_json"]
            ),
        )

    def get_o_indexes(self, tx_hash: bytes) -> List[int]:
        """Get output indexes by their Transaction's Hash."""

        return self.rpc_request("get_o_indexes.bin", {"txid": (10, tx_hash)})[
            "o_indexes"
        ]

    def get_outs(self, index: int) -> Dict[str, Any]:
        """Get output information based on its index."""

        return self.rpc_request(
            "get_outs.bin",
            {"outputs": (0x80 | 12, [{"amount": (5, 0), "index": (5, index)}])},
        )["outs"][0]

    def get_fee_estimate(self) -> Tuple[int, int]:
        """Get an estimate of the fee per byte, along with the quantization mask."""

        res: Dict[str, Any] = self.jsonrpc_request("get_fee_estimate")
        return (res["fee"], res["quantization_mask"])

    def is_key_image_spent(self, image: bytes) -> bool:
        """Check if a key image is spent."""

        return self.rpc_request("is_key_image_spent", {"key_images": [image.hex()]})[
            "spent_status"
        ] != [0]

    def publish_transaction(self, tx: bytes) -> None:
        """Publish a serialized Transaction."""

        self.rpc_request("send_raw_transaction", {"tx_as_hex": tx.hex()})

    def generate_blocks(self, amount: int, address: str) -> None:
        """Generate Blocks for testing purposes."""

        self.jsonrpc_request(
            "generateblocks", {"amount_of_blocks": amount, "wallet_address": address}
        )
