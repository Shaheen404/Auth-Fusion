"""Phase 2: Raw HTTP Request Parsing Engine.

Accurately converts a raw HTTP text block (e.g. from Burp Suite) into
structured components that the Python requests library can use.
"""

from __future__ import annotations


class ParsedRequest:
    """Container for a parsed raw HTTP request."""

    __slots__ = ("method", "path", "headers", "body")

    def __init__(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: str | None,
    ) -> None:
        self.method = method
        self.path = path
        self.headers = headers
        self.body = body

    def __repr__(self) -> str:
        return (
            f"ParsedRequest(method={self.method!r}, path={self.path!r}, "
            f"headers=<{len(self.headers)} headers>, "
            f"body={'<present>' if self.body else '<none>'})"
        )


def parse_raw_request(raw_text: str) -> ParsedRequest:
    """Parse a raw HTTP request into its components.

    Handles:
      - Various HTTP methods (GET, POST, PUT, DELETE, PATCH, etc.)
      - Endpoint path extraction
      - Header dictionary construction (handles \\r\\n line endings)
      - Request body (JSON, XML, form data) or absent body
      - Multi-value headers with the same name (last value wins)

    Args:
        raw_text: The raw HTTP request as a string.

    Returns:
        A ParsedRequest with method, path, headers, and body.

    Raises:
        ValueError: If the request line is malformed.
    """
    # Normalize line endings: replace \r\n with \n, then split
    normalized = raw_text.replace("\r\n", "\n")

    # Split head (request-line + headers) from body on the first blank line
    if "\n\n" in normalized:
        head, body = normalized.split("\n\n", 1)
        body = body if body.strip() else None
    else:
        head = normalized
        body = None

    lines = head.split("\n")

    # --- Parse request line ---
    request_line = lines[0].strip()
    parts = request_line.split()
    if len(parts) < 2:
        raise ValueError(f"Malformed request line: {request_line!r}")

    method = parts[0].upper()
    path = parts[1]

    # --- Parse headers ---
    headers: dict[str, str] = {}
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        colon_idx = line.find(":")
        if colon_idx == -1:
            continue
        key = line[:colon_idx].strip()
        value = line[colon_idx + 1 :].strip()
        headers[key] = value

    return ParsedRequest(
        method=method,
        path=path,
        headers=headers,
        body=body,
    )


def load_request_file(filepath: str) -> str:
    """Read and return the contents of a raw request file.

    Args:
        filepath: Path to the raw request text file.

    Returns:
        The raw text content of the file.

    Raises:
        FileNotFoundError: If the file does not exist.
        IOError: If the file cannot be read.
    """
    with open(filepath, "r", encoding="utf-8") as fh:
        return fh.read()
