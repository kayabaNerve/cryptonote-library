from typing import List, Tuple

class Key:
    def __getitem__(self, i: int) -> int: ...

class CTKey:
    dest: Key
    mask: Key

class ECDHTuple:
    mask: Key
    amount: Key

class Bulletproof:
    v: List[Key]

    capital_a: Key
    s: Key
    t1: Key
    t2: Key

    taux: Key
    mu: Key

    l: List[Key]
    r: list[Key]

    a: Key
    b: Key
    t: Key

class CLSAGSignature:
    s: List[Key]
    c1: Key
    D: Key

class RingCTPrunable:
    pseudo_outs: List[Key]
    bulletproofs: List[Bulletproof]
    CLSAGs: List[CLSAGSignature]

class RingCTSignatures:
    ecdh_info: List[ECDHTuple]
    out_public_keys: List[CTKey]
    prunable: RingCTPrunable

def generate_key_image(priv_key: bytes, pub_key: bytes) -> bytes: ...
def generate_ringct_signatures(
    prefix_hash: bytes,
    private_keys: List[Tuple[bytes, bytes]],
    destinations: List[bytes],
    amount_keys: List[bytes],
    ring: List[List[List[bytes]]],
    indexes: List[int],
    inputs: List[int],
    outputs: List[int],
    fee: int,
) -> RingCTSignatures: ...
