# Types.
from typing import Any

# OS standard lib.
from os import path

# CTypes standard lib.
from ctypes import cdll

# Load Monero's shared libraries.
dir: str = path.dirname(path.realpath(__file__)) + "/monero/"
cdll.LoadLibrary(dir + "src/crypto/libcncrypto.so")
cdll.LoadLibrary(dir + "src/ringct/libringct_basic.so")
cdll.LoadLibrary(dir + "src/device/libdevice.so")
cdll.LoadLibrary(dir + "src/cryptonote_core/libcryptonote_core.so")
cdll.LoadLibrary(dir + "src/ringct/libringct.so")

# Load the C++ wrapper.
from cryptonote.lib.monero_rct.c_monero_rct import (
    RingCTSignatures,
    generate_key_image,
    generate_ringct_signatures,
    test_ringct_signatures,
)

# Assign the imports to a nameless variable so the checkers recognize they're used.
_: Any
_ = RingCTSignatures
_ = generate_key_image
_ = generate_ringct_signatures
_ = test_ringct_signatures
