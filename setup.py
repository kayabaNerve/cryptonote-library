"""Setup the CryptoNote Library."""

# Types.
from typing import List, Optional

# Change directory standard function. Used to build Monero and then the CMoneroRCT wrapper.
from os import chdir

# check_call standard function.
import sys
import sysconfig
from subprocess import call, check_call, check_output

# setuptools setup function and build modes.
from setuptools import setup
from setuptools.command.develop import develop
from setuptools.command.install import install


def build_monero() -> None:
    """Build Monero's shared object files and compile the wrapper."""

    check_call("git submodule update --init --recursive".split())
    print("Downloaded submodules.")

    chdir("cryptonote/lib/monero_rct/monero")

    # Building the wrapper fails due to some macro not being found.
    # The file that contains the macros is included.
    # The file using the macros has the following comment right above them:
    # /* I have no clue what these lines means */
    # This comments out those macros.
    check_call("git apply ../warnings.patch".split())

    check_call("cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=1 .".split())
    print("Built Monero's Makefiles.")

    check_call("make -j2".split())
    print("Built Monero's shared libraries and a debug Monero node.")

    chdir("..")

    suffix: Optional[str] = sysconfig.get_config_var("EXT_SUFFIX")
    if suffix is None:
        suffix = ".so"
    wrapper_build: List[str] = (
        "g++ -O3 -Wall -shared -std=c++14 -fPIC".split()
        + check_output([sys.executable] + "-m pybind11 --includes".split())
        .decode("utf-8")
        .split()
        + "-Imonero/contrib/epee/include -Imonero/src c_monero_rct.cpp -o".split()
        + ("c_monero_rct" + suffix).strip().split()
        + "-Lmonero/src/crypto -lcncrypto".split()
        + "-Lmonero/src/device -ldevice".split()
        + "-Lmonero/src/ringct -lringct_basic -lringct".split()
        + "-Lmonero/src/cryptonote_core -lcryptonote_core".split()
    )
    check_call(wrapper_build)
    print("Built the wrapper around Monero's shared libraries.")

    chdir("../../..")


# PyRight successfully picks up on the develop stub. MyPy doesn't.
class Develop(develop):  # type: ignore
    """Install CryptoNote with a symbolic link."""

    def run(self) -> None:
        """Run the installation script."""

        develop.run(self)
        build_monero()


# Install has the same problem as Develop.
class Install(install):  # type: ignore
    """Install CryptoNote."""

    def run(self) -> None:
        """Run the installation script."""

        install.run(self)
        build_monero()


setup(
    name="cryptonote",
    version="1.0.0",
    author="Luke Parker (kayabaNerve)",
    packages=[
        "cryptonote",
        "cryptonote.lib",
        "cryptonote.lib.monero_rct",
        "cryptonote.classes.blockchain",
        "cryptonote.classes.wallet",
        "cryptonote.rpc",
    ],
    install_requires=[
        "pybind11",
        "pycryptodomex",
        "pytest",
        "pytest-ordering",
        "click",
        "requests",
    ],
    python_requires=">=3.6",
    cmdclass={
        "develop": Develop,
        "install": Install,
    },
)
