from typing import Dict, List, Any

from setuptools.command.develop import develop
from setuptools.command.install import install

def setup(
    name: str,
    version: str,
    author: str,
    packages: List[str],
    install_requires: List[str],
    python_requires: str,
    entry_points: Dict[str, List[str]],
    cmdclass: Dict[str, Any],
) -> None: ...
def find_namespace_packages() -> List[str]: ...
