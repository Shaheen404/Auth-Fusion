"""Auth-Fusion — Main entry point.

Ties together the CLI, parser, and engine modules to run the
BOLA & Privilege Escalation detection workflow.
"""

import sys

from auth_fusion.cli import parse_cli
from auth_fusion.engine import print_report, replay_request
from auth_fusion.parser import load_request_file, parse_raw_request


def main(argv: list[str] | None = None) -> int:
    """Run the Auth-Fusion tool.

    Args:
        argv: Optional argument list (defaults to sys.argv).

    Returns:
        Exit code (0 = safe/not vulnerable, 1 = vulnerable, 2 = error).
    """
    args = parse_cli(argv)

    # --- Phase 2: Parse the raw request file ---
    print(f"[*] Loading raw request from: {args.request_file}")
    try:
        raw_text = load_request_file(args.request_file)
    except (FileNotFoundError, IOError) as exc:
        print(f"Error reading request file: {exc}", file=sys.stderr)
        return 2

    print("[*] Parsing raw HTTP request...")
    try:
        parsed = parse_raw_request(raw_text)
    except ValueError as exc:
        print(f"Error parsing request: {exc}", file=sys.stderr)
        return 2

    print(f"    Method : {parsed.method}")
    print(f"    Path   : {parsed.path}")
    print(f"    Headers: {len(parsed.headers)}")
    print(f"    Body   : {'Yes' if parsed.body else 'No'}")

    # --- Phase 3: Swap token and replay ---
    scheme = "HTTPS" if args.use_https else "HTTP"
    print(f"\n[*] Replaying request to {args.target_host} via {scheme}...")
    if args.proxy:
        print(f"    Proxy  : {args.proxy}")

    try:
        result = replay_request(
            parsed=parsed,
            attacker_token=args.attacker_token,
            target_host=args.target_host,
            use_https=args.use_https,
            proxy=args.proxy,
        )
    except Exception as exc:
        print(f"Error during request replay: {exc}", file=sys.stderr)
        return 2

    # --- Report ---
    print_report(result)

    return 1 if result.is_vulnerable else 0


if __name__ == "__main__":
    sys.exit(main())
