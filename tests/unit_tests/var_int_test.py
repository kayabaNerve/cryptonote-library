# Types.
from typing import Tuple

# randint standard function.
from random import randint

# VarInt lib.
from cryptonote.lib.var_int import (
    to_var_int,
    to_rpc_var_int,
    from_var_int,
    from_rpc_var_int,
)

# Test 500 random serializations.
def varint_serializations_test() -> None:
    for _ in range(500):
        num: int = randint(0, 2 ** 16)
        assert from_var_int(to_var_int(num), 0)[0] == num
        assert from_rpc_var_int(to_rpc_var_int(num), 0)[0] == num


# Test 500 random serializations with random data before and after.
def padded_varint_serializations_test() -> None:
    for _ in range(500):
        num: int = randint(0, 2 ** 16)

        var_int: bytes = to_var_int(num)
        length: int = len(var_int)

        rpc_var_int: bytes = to_rpc_var_int(num)
        rpc_length: int = len(rpc_var_int)

        before: int = randint(0, 32)
        for i in range(before):
            var_int = bytes([randint(0, 255)]) + var_int
            rpc_var_int = bytes([randint(0, 255)]) + rpc_var_int
        for i in range(randint(0, 32)):
            var_int += bytes([randint(0, 255)])
            rpc_var_int += bytes([randint(0, 255)])

        res: Tuple[int, int] = from_var_int(var_int, before)
        assert res[0] == num
        assert res[1] == before + length

        rpc_res: Tuple[int, int] = from_rpc_var_int(rpc_var_int, before)
        assert res[0] == num
        assert res[1] == before + length
