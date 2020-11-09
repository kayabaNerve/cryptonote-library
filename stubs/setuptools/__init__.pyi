from typing import Dict, List, Any

def setup(
    name: str,
    version: str,
    author: str,
    packages: List[str],
    install_requires: List[str],
    python_requires: str,
    cmdclass: Dict[str, Any],
) -> None: ...
def find_namespace_packages() -> List[str]: ...
