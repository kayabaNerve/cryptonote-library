# The reference Ed25519 software is in the public domain.
#     Source: https://ed25519.cr.yp.to/python/ed25519.py
#
# Parts Copyright (c) 2016 The MoneroPy Developers. Released under the BSD 3-Clause
# Parts taken from https://github.com/monero-project/mininero/blob/master/ed25519ietf.py

# Types.
from typing import List, Tuple

import operator as _oper

from Cryptodome.Hash import keccak

indexbytes = _oper.getitem
int2byte = _oper.methodcaller("to_bytes", 1, "big")

b = 256
q = 2 ** 255 - 19
l = 2 ** 252 + 27742317777372353535851937790883648493


def expmod(b, e, m):
    if e == 0:
        return 1
    t = expmod(b, e // 2, m) ** 2 % m
    if e & 1:
        t = (t * b) % m
    return t


def inv(x):
    return expmod(x, q - 2, q)


d = -121665 * inv(121666)
I = expmod(2, (q - 1) // 4, q)


def xrecover(y):
    xx = (y * y - 1) * inv(d * y * y + 1)
    x = expmod(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * I) % q
    if x % 2 != 0:
        x = q - x
    return x


def compress(P):
    zinv = inv(P[2])
    return (P[0] * zinv % q, P[1] * zinv % q)


def decompress(P):
    return (P[0], P[1], 1, P[0] * P[1] % q)


By = 4 * inv(5)
Bx = xrecover(By)
B = [Bx % q, By % q]


def edwards(P, Q):
    x1 = P[0]
    y1 = P[1]
    x2 = Q[0]
    y2 = Q[1]
    x3 = (x1 * y2 + x2 * y1) * inv(1 + d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * inv(1 - d * x1 * x2 * y1 * y2)
    return [x3 % q, y3 % q]


def add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % q
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % q
    C = 2 * P[3] * Q[3] * d % q
    D = 2 * P[2] * Q[2] % q
    E = B - A
    F = D - C
    G = D + C
    H = B + A
    return (E * F, G * H, F * G, E * H)


def add_compressed(P, Q):
    return compress(add(decompress(P), decompress(Q)))


def scalarmult(P, e):
    if e == 0:
        return [0, 1]
    Q = scalarmult(P, e // 2)
    Q = edwards(Q, Q)
    if e & 1:
        Q = edwards(Q, P)
    return Q


def encodeint(y):
    bits = [(y >> i) & 1 for i in range(b)]
    return b"".join(
        [int2byte(sum([bits[i * 8 + j] << j for j in range(8)])) for i in range(b // 8)]
    )


def encodepoint(P):
    x = P[0]
    y = P[1]
    bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]
    return b"".join(
        [int2byte(sum([bits[i * 8 + j] << j for j in range(8)])) for i in range(b // 8)]
    )


def bit(h, i):
    return (indexbytes(h, i // 8) >> (i % 8)) & 1


def isoncurve(P):
    x = P[0]
    y = P[1]
    return (-x * x + y * y - 1 - d * x * x * y * y) % q == 0


def decodeint(s):
    return sum(2 ** i * bit(s, i) for i in range(0, b))


def decodepoint(s):
    y = sum(2 ** i * bit(s, i) for i in range(0, b - 1))
    x = xrecover(y)
    if x & 1 != bit(s, b - 1):
        x = q - x
    P = [x, y]
    if not isoncurve(P):
        raise Exception("decoding point that is not on curve")
    return P


def public_from_secret(k):
    keyInt = decodeint(k)
    aB = scalarmult(B, keyInt)
    return encodepoint(aB)


# Code added for the CryptoNote library.
C: List[bytes] = decodepoint(
    bytes.fromhex("8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94")
)
COMMITMENT_MASK: bytes = (b"\1" + (b"\0" * 31))


def H(d: bytes) -> bytes:
    """Keccak-256."""

    hash: Any = keccak.new(digest_bits=256)
    hash.update(d)
    return hash.digest()


def Hs(d: bytes) -> bytes:
    """Keccak-256 mod l."""

    return encodeint(decodeint(H(d)) % l)


def generate_subaddress_private_spend_key(
    private_view_key: bytes, private_spend_key: bytes, index: Tuple[int, int],
) -> int:
    """
    Generate a subaddress private spend key using the
    private spend key and private view key.
    """

    if index == (0, 0):
        return decodeint(private_spend_key)

    return decodeint(private_spend_key) + decodeint(
        Hs(
            b"SubAddr\0"
            + private_view_key
            + index[0].to_bytes(4, byteorder="little")
            + index[1].to_bytes(4, byteorder="little")
        )
    )


def generate_subaddress_public_spend_key(
    private_view_key: bytes, public_spend_key: bytes, subaddress: Tuple[int, int]
) -> bytes:
    """
    Generate a subaddress public spend key using the
    private view key and master public spend key.
    """

    if subaddress == (0, 0):
        return public_spend_key

    return encodepoint(
        add_compressed(
            decodepoint(public_spend_key),
            scalarmult(
                B,
                decodeint(
                    Hs(
                        b"SubAddr\0"
                        + private_view_key
                        + subaddress[0].to_bytes(4, byteorder="little")
                        + subaddress[1].to_bytes(4, byteorder="little")
                    )
                ),
            ),
        )
    )


def generate_subaddress_public_view_key(
    private_view_key: bytes, public_spend_key: bytes, subaddress: Tuple[int, int]
) -> bytes:
    """
    Generate a subaddress public view key using the
    private view key and subaddress public spend key.
    """

    if subaddress == (0, 0):
        return public_from_secret(private_view_key)

    return encodepoint(
        scalarmult(decodepoint(public_spend_key), decodeint(private_view_key))
    )


def generate_subaddress_key_pair(
    private_view_key: bytes, public_spend_key: bytes, subaddress: Tuple[int, int]
) -> Tuple[bytes, bytes]:
    """
    Generate a subaddress public view key using the
    private view key and subaddress public spend key.
    """

    subaddress_spend_key: bytes = generate_subaddress_public_spend_key(
        private_view_key, public_spend_key, subaddress
    )

    return (
        generate_subaddress_public_view_key(
            private_view_key, subaddress_spend_key, subaddress
        ),
        subaddress_spend_key,
    )
