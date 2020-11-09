from typing import Dict, List, Union, Any

class Response:
    status_code: int
    content: bytes
    def json(self) -> Dict[str, Any]: ...

class Session:
    def post(
        self,
        url: str,
        json: Union[Dict[str, Any], List[Any]] = ...,
        data: bytes = ...,
        headers: Dict[str, str] = ...,
    ) -> Response: ...
