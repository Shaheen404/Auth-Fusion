"""Phase 3: Execution & Manipulation Engine.

Handles token swapping, request replay, and response analysis to detect
Broken Object Level Authorization (BOLA) and Privilege Escalation.
"""

from __future__ import annotations

import urllib3

import requests

from auth_fusion.parser import ParsedRequest

# Suppress InsecureRequestWarning when using --proxy with self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# HTTP status codes that indicate the server accepted the request
SUCCESS_CODES = range(200, 300)

# Minimum response body length (bytes) to consider "meaningful data"
MIN_BODY_LENGTH = 2


class ReplayResult:
    """Container for the result of a replayed request."""

    __slots__ = (
        "status_code",
        "headers",
        "body",
        "is_vulnerable",
        "analysis",
    )

    def __init__(
        self,
        status_code: int,
        headers: dict[str, str],
        body: str,
        is_vulnerable: bool,
        analysis: str,
    ) -> None:
        self.status_code = status_code
        self.headers = headers
        self.body = body
        self.is_vulnerable = is_vulnerable
        self.analysis = analysis


def swap_token(
    headers: dict[str, str], attacker_token: str
) -> dict[str, str]:
    """Replace the Authorization Bearer token in headers.

    Performs a case-insensitive search for the Authorization header and
    replaces its value with the attacker's Bearer token.

    Args:
        headers: The original headers dictionary.
        attacker_token: The low-privilege attacker's token.

    Returns:
        A new headers dictionary with the swapped token.
    """
    new_headers: dict[str, str] = {}
    token_swapped = False

    for key, value in headers.items():
        if key.lower() == "authorization":
            new_headers[key] = f"Bearer {attacker_token}"
            token_swapped = True
        else:
            new_headers[key] = value

    if not token_swapped:
        new_headers["Authorization"] = f"Bearer {attacker_token}"

    return new_headers


def build_url(
    target_host: str, path: str, use_https: bool = True
) -> str:
    """Construct the full URL from host, path, and scheme.

    Args:
        target_host: The target domain or IP.
        path: The endpoint path (e.g. /api/v1/users).
        use_https: Whether to use HTTPS (default True).

    Returns:
        The fully-qualified URL string.
    """
    scheme = "https" if use_https else "http"
    # Strip any trailing slash from host and leading slash duplication
    host = target_host.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return f"{scheme}://{host}{path}"


def replay_request(
    parsed: ParsedRequest,
    attacker_token: str,
    target_host: str,
    use_https: bool = True,
    proxy: str | None = None,
    timeout: int = 30,
) -> ReplayResult:
    """Replay the parsed request with the attacker's token.

    Args:
        parsed: The parsed raw HTTP request.
        attacker_token: The low-privilege attacker's Bearer token.
        target_host: The target domain or IP.
        use_https: Whether to use HTTPS.
        proxy: Optional proxy URL for debugging.
        timeout: Request timeout in seconds.

    Returns:
        A ReplayResult containing the response and vulnerability analysis.
    """
    swapped_headers = swap_token(parsed.headers, attacker_token)

    # Remove the Host header — requests will set it from the URL
    for key in list(swapped_headers.keys()):
        if key.lower() == "host":
            del swapped_headers[key]

    url = build_url(target_host, parsed.path, use_https)

    proxies = None
    if proxy:
        proxies = {"http": proxy, "https": proxy}

    response = requests.request(
        method=parsed.method,
        url=url,
        headers=swapped_headers,
        data=parsed.body,
        proxies=proxies,
        timeout=timeout,
        verify=False,
        allow_redirects=False,
    )

    is_vulnerable, analysis = analyze_response(response)

    return ReplayResult(
        status_code=response.status_code,
        headers=dict(response.headers),
        body=response.text,
        is_vulnerable=is_vulnerable,
        analysis=analysis,
    )


def analyze_response(response: requests.Response) -> tuple[bool, str]:
    """Analyze the HTTP response for signs of privilege escalation.

    Heuristics:
      - 2xx status code with a non-trivial body → likely vulnerable
      - 401/403 → access denied → not vulnerable
      - 404 → resource not found → inconclusive
      - Other status codes → manual review recommended

    Args:
        response: The HTTP response object.

    Returns:
        A tuple of (is_vulnerable, analysis_message).
    """
    code = response.status_code
    body = response.text.strip()

    if code in (401, 403):
        return False, (
            f"[SAFE] Access Denied (HTTP {code}). "
            "The server correctly rejected the low-privilege token."
        )

    if code == 404:
        return False, (
            "[INCONCLUSIVE] HTTP 404 — resource not found. "
            "The endpoint may not exist or may require different parameters."
        )

    if code in SUCCESS_CODES and len(body) >= MIN_BODY_LENGTH:
        # Check if the response body looks like it contains real data
        snippet = body[:200]
        return True, (
            f"[VULNERABLE] HTTP {code} — The server returned a "
            f"successful response with data using the attacker's token!\n"
            f"  Response snippet: {snippet}..."
        )

    if code in SUCCESS_CODES:
        return False, (
            f"[LIKELY SAFE] HTTP {code} — success status but empty/trivial "
            "response body. The server may have accepted the request but "
            "returned no privileged data."
        )

    return False, (
        f"[MANUAL REVIEW] HTTP {code} — unexpected status code. "
        "Manual investigation is recommended."
    )


def print_report(result: ReplayResult) -> None:
    """Print a formatted vulnerability report to stdout.

    Args:
        result: The ReplayResult from the replayed request.
    """
    banner = "=" * 60
    print(f"\n{banner}")
    print("  AUTH-FUSION — Vulnerability Analysis Report")
    print(banner)
    print(f"\n  Status Code : {result.status_code}")
    print(f"  Vulnerable  : {'YES' if result.is_vulnerable else 'NO'}")
    print(f"\n  Analysis:\n    {result.analysis}")

    if result.is_vulnerable:
        print("\n  Response Headers:")
        for key, value in result.headers.items():
            print(f"    {key}: {value}")
        print(f"\n  Response Body (first 500 chars):\n    {result.body[:500]}")

    print(f"\n{banner}\n")
