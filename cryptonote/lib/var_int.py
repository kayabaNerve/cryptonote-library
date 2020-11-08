"""VarInt functions."""

# Types.
from typing import Tuple


def to_var_int(i: int) -> bytes:
    """Converts an int to bytes."""

    result: bytes = bytes()
    while i >= 0x80:
        result += bytes([(i & 0x7F) | 0x80])
        i >>= 7
    result += bytes([i])
    return result


def from_var_int(i: bytes, cursor: int) -> Tuple[int, int]:
    """Converts bytes to an int."""

    # Convert the to_var_int to an int.
    original_cursor: int = cursor
    value: int = 0
    while True:
        value += (i[cursor] & 0x7F) << ((cursor - original_cursor) * 7)
        cursor += 1
        if i[cursor - 1] & 0x80 == 0:
            break

    return (value, cursor)


def to_rpc_var_int(i: int) -> bytes:
    """Converts an int to bytes."""

    mask: int
    if i < 2 ** 6:
        mask = 0
    elif i < 2 ** 14:
        mask = 1
    elif i < 2 ** 30:
        mask = 2
    else:
        mask = 3

    i <<= 2
    i |= mask
    return i.to_bytes(2 ** mask, byteorder="little")


def from_rpc_var_int(i: bytes, cursor: int) -> Tuple[int, int]:
    """Converts bytes to an int."""

    mask: int = i[cursor] & 0b11
    length: int = 2 ** mask
    result: int = int.from_bytes(i[cursor : cursor + length], byteorder="little") >> 2
    cursor += length

    return (result, cursor)
