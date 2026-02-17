"""Phase 1: CLI Architecture & Input Handling.

Provides a clean, professional command-line interface using argparse
for the Auth-Fusion BOLA and Privilege Escalation detection tool.
"""

import argparse
import os
import sys

from auth_fusion import __version__


def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser for Auth-Fusion CLI."""
    parser = argparse.ArgumentParser(
        prog="auth-fusion",
        description=(
            "Auth-Fusion v{ver} — Automated BOLA & Privilege Escalation "
            "Detection Tool.\n\n"
            "Takes a low-privilege attacker token and a raw Burp Suite HTTP "
            "request belonging to a high-privilege victim, replays the "
            "request with the attacker's token, and analyzes the response "
            "for privilege escalation."
        ).format(ver=__version__),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  auth-fusion --attacker-token <TOKEN> --target-host "
            "api.example.com --request-file request.txt\n"
            "  auth-fusion --attacker-token <TOKEN> --target-host "
            "api.example.com --request-file request.txt --no-https "
            "--proxy http://127.0.0.1:8080\n"
        ),
    )

    # Required arguments
    required = parser.add_argument_group("required arguments")
    required.add_argument(
        "--attacker-token",
        required=True,
        help="The low-privilege attacker's Bearer token.",
    )
    required.add_argument(
        "--target-host",
        required=True,
        help="The target domain or IP address (e.g. api.example.com).",
    )
    required.add_argument(
        "--request-file",
        required=True,
        help="Path to a .txt file containing the raw Burp Suite HTTP request.",
    )

    # Optional arguments
    parser.add_argument(
        "--https",
        action="store_true",
        default=True,
        dest="use_https",
        help="Force HTTPS for the request (default: True).",
    )
    parser.add_argument(
        "--no-https",
        action="store_false",
        dest="use_https",
        help="Use HTTP instead of HTTPS.",
    )
    parser.add_argument(
        "--proxy",
        default=None,
        help=(
            "Route traffic through a proxy for debugging "
            "(e.g. http://127.0.0.1:8080)."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    return parser


def validate_args(args: argparse.Namespace) -> None:
    """Validate parsed CLI arguments.

    Raises:
        SystemExit: If the request file does not exist or is not readable.
    """
    if not os.path.isfile(args.request_file):
        print(
            f"Error: Request file not found: '{args.request_file}'",
            file=sys.stderr,
        )
        sys.exit(1)

    if not os.access(args.request_file, os.R_OK):
        print(
            f"Error: Request file is not readable: '{args.request_file}'",
            file=sys.stderr,
        )
        sys.exit(1)

    if not args.attacker_token.strip():
        print("Error: Attacker token cannot be empty.", file=sys.stderr)
        sys.exit(1)

    if not args.target_host.strip():
        print("Error: Target host cannot be empty.", file=sys.stderr)
        sys.exit(1)


def parse_cli(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse and validate command-line arguments.

    Args:
        argv: Optional list of arguments (defaults to sys.argv).

    Returns:
        Parsed and validated argument namespace.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_args(args)
    return args
