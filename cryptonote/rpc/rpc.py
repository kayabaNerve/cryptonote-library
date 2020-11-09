"""RPC class file."""

# Types.
from typing import Dict, List, Tuple, Union, Any

# Abstract class standard lib.
from abc import ABC, abstractmethod

# Struct standard lib.
import struct

import requests

# VarInt lib.
from cryptonote.lib.var_int import to_rpc_var_int, from_rpc_var_int

# Blockchain classes.
from cryptonote.classes.blockchain import Transaction
from cryptonote.classes.blockchain import BlockHeader, Block


class RPCError(Exception):
    """RPCError Exception. Used when the RPC fails."""


# JSON Binary format lookup.
binary_lookup: Dict[int, struct.Struct] = {
    1: struct.Struct("q"),
    2: struct.Struct("i"),
    3: struct.Struct("h"),
    4: struct.Struct("b"),
    5: struct.Struct("Q"),
    6: struct.Struct("I"),
    7: struct.Struct("H"),
    8: struct.Struct("B"),
    9: struct.Struct("d"),
    11: struct.Struct("?"),
}


def rpc_binary_serialize_internal(data: Any, code: int = -1) -> bytes:
    """Serialize data according to epee for the binary RPC calls."""

    result: bytes = bytes()
    if code == -1:
        code = data[0]
        result = bytes([code])
        data = data[1]

    if code in binary_lookup:
        result += binary_lookup[code].pack(data)
    elif code == 10:
        result += to_rpc_var_int(len(data)) + data
    elif code == 12:
        result += to_rpc_var_int(len(data))
        for field in data:
            result += bytes([len(field)]) + field.encode("utf-8")
            result += rpc_binary_serialize_internal(data[field])
    elif code & 0x80 == 0x80:
        result += to_rpc_var_int(len(data))
        for elem in data:
            result += rpc_binary_serialize_internal(elem, code & 0b1111)
    return result


def rpc_binary_serialize(data: Any) -> bytes:
    """Serialize an object according to epee for the binary RPC calls."""

    if data is None:
        return bytes()

    result: bytes = bytes.fromhex("011101010101020101") + to_rpc_var_int(len(data))
    for field in data:
        result += bytes([len(field)]) + field.encode("utf-8")
        result += rpc_binary_serialize_internal(data[field])
    return result


def rpc_binary_parse_internal(
    data: bytes, cursor: int, code: int = -1
) -> Tuple[Any, int]:
    """Parse data according to epee for the binary RPC calls."""

    result: Any = None
    if code == -1:
        code = data[cursor]
        cursor += 1

    if code in binary_lookup:
        result = binary_lookup[code].unpack_from(data, cursor)[0]
        cursor += binary_lookup[code].size
    elif code == 10:
        length: int
        (length, cursor) = from_rpc_var_int(data, cursor)
        result = data[cursor : cursor + length]
        cursor += length
    elif code == 12:
        result = {}

        fields: int
        (fields, cursor) = from_rpc_var_int(data, cursor)

        for _ in range(fields):
            length: int = data[cursor]
            cursor += 1

            name: str = data[cursor : cursor + length].decode("utf-8")
            cursor += length

            (result[name], cursor) = rpc_binary_parse_internal(data, cursor)
    elif code & 0x80 == 0x80:
        result = []
        length: int
        (length, cursor) = from_rpc_var_int(data, cursor)
        for _ in range(length):
            elem: Any
            (elem, cursor) = rpc_binary_parse_internal(data, cursor, code & 0b1111)
            result.append(elem)

    if result is None:
        raise Exception("Failed to parse a binary RPC response.")
    return (result, cursor)


def rpc_binary_parse(data: bytes) -> Dict[str, Any]:
    """Parse an object according to epee for the binary RPC calls."""

    result: Dict[str, Any] = {}
    cursor: int = 10  # Magic, version, and object type.

    # Read fields until there's no more data.
    while cursor < len(data):
        length: int = data[cursor]
        cursor += 1

        name: str = data[cursor : cursor + length].decode("utf-8")
        cursor += length

        (result[name], cursor) = rpc_binary_parse_internal(data, cursor)

    # Convert known string fields to string.
    if "status" in result:
        result["status"] = result["status"].decode("utf-8")

    return result


def check_rpc_result(result: Any) -> None:
    """Check a RPC result for validity."""

    if isinstance(result, Dict):
        if isinstance(result["status"], str):
            status: str = result["status"]
            if status != "OK":
                raise RPCError("Node has a status other than OK: " + status)
        if result["untrusted"]:
            raise RPCError("Node is still syncing.")


class RPC(ABC):
    """
    RPC class.
    Provides a way to send requests to both RPCs.
    Also implements RPC methods shared by CryptoNote, Turtlecoin, and Monero.
    """

    # Constructor.
    def __init__(self, ip: str, rpc: int) -> None:
        """Construct a RPC instance from the Node."""
        self.ip: str = ip
        self.rpc: int = rpc

        self.client: requests.Session = requests.Session()
        self.nextID: int = 0

    # Make a request to the JSON RPC.
    def jsonrpc_request(
        self, method: str, paramsArg: Union[Dict[str, Any], List[Any], None] = None
    ) -> Any:
        """Perform a request to the JSON RPC."""

        # Extract the params.
        params: Union[Dict[str, Any], List[Any]] = {}
        if paramsArg is not None:
            params = paramsArg

        result: Dict[str, Any] = self.client.post(
            f"http://{self.ip}:{self.rpc}/json_rpc",
            json={
                "jsonrpc": "2.0",
                "id": self.nextID,
                "method": method,
                "params": params,
            },
        ).json()
        self.nextID += 1
        if "error" in result:
            raise RPCError(
                str(result["error"]["code"]) + " " + result["error"]["message"]
            )
        result = result["result"]
        check_rpc_result(result)
        return result

    def rpc_request(
        self,
        method: str,
        paramsArg: Union[Dict[str, Any], List[Any], None] = None,
        retried: bool = False,
    ) -> Dict[str, Any]:
        """Perform a request to the HTTP-routed RPC."""

        # Get if this method is binary or not.
        binary: bool = False
        if method[-4:] == ".bin":
            binary = True

        # Extract the params.
        params: Union[Dict[str, Any], List[Any], bytes] = {}
        if (not binary) and (paramsArg is not None):
            params = paramsArg
        elif binary:
            params = rpc_binary_serialize(paramsArg)

        resp: requests.Response
        if isinstance(params, bytes):
            resp = self.client.post(
                f"http://{self.ip}:{self.rpc}/{method}",
                data=params,
                headers={"Content-Type": "application/octet-stream"},
            )
        else:
            resp = self.client.post(
                f"http://{self.ip}:{self.rpc}/{method}", json=params
            )

        if binary and (resp.status_code == 404):
            raise Exception("Invalid binary serialization/parsing.")

        # Extract the HTTP response.
        result: Any = rpc_binary_parse(resp.content) if binary else resp.json()
        check_rpc_result(result)
        return result

    # Abstract methods inheritors must implement.
    @abstractmethod
    def get_info(self) -> Dict[str, Any]:
        """Get info about the node."""

    @abstractmethod
    def get_raw_block(self, block_hash: bytes) -> bytes:
        """Get a raw block by its hash."""

    @abstractmethod
    def publish_block(self, block: bytes) -> None:
        """Publish a raw block."""

    @abstractmethod
    def get_block_count(self) -> int:
        """Get the Block count."""

    @abstractmethod
    def get_block_hash(self, height: int) -> bytes:
        """Get a Block's hash by it's height."""

    @abstractmethod
    def get_last_block_header(self) -> BlockHeader:
        """Get the last BlockHeader."""

    @abstractmethod
    def get_block_header_by_hash(self, block_hash: bytes) -> BlockHeader:
        """Get a BlockHeader by its hash."""

    @abstractmethod
    def get_block_header_by_height(self, height: int) -> BlockHeader:
        """Get a BlockHeader by its height."""

    @abstractmethod
    def get_block(self, block_hash: bytes) -> Block:
        """Get a Block by its Hash."""

    @abstractmethod
    def get_transaction(self, tx_hash: bytes) -> Transaction:
        """Get a Transaction by its Hash."""

    @abstractmethod
    def get_o_indexes(self, tx_hash: bytes) -> List[int]:
        """Get output indexes by their Transaction's Hash."""

    @abstractmethod
    def get_outs(self, index: int) -> Dict[str, Any]:
        """Get output information based on its index."""

    @abstractmethod
    def get_fee_estimate(self) -> Tuple[int, int]:
        """Get an estimate of the fee per byte, along with the quantization mask."""

    @abstractmethod
    def is_key_image_spent(self, image: bytes) -> bool:
        """Check if a key image is spent."""

    @abstractmethod
    def publish_transaction(self, tx: bytes) -> None:
        """Publish a serialized Transaction."""

    @abstractmethod
    def generate_blocks(self, amount: int, address: str) -> None:
        """Generate Blocks for testing purposes."""
