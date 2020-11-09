from os import path
from ctypes import cdll

dir: str = path.dirname(path.realpath(__file__)) + "/monero/"
cdll.LoadLibrary(dir + "src/crypto/libcncrypto.so")
cdll.LoadLibrary(dir + "src/cryptonote_basic/libcryptonote_basic.so")
cdll.LoadLibrary(dir + "src/cryptonote_core/libcryptonote_core.so")
cdll.LoadLibrary(dir + "src/ringct/libringct_basic.so")
cdll.LoadLibrary(dir + "src/device/libdevice.so")
cdll.LoadLibrary(dir + "src/cryptonote_core/libcryptonote_core.so")
cdll.LoadLibrary(dir + "src/ringct/libringct.so")
