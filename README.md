# Auth-Fusion

A robust, modular Python Command Line Interface (CLI) tool that automates the discovery of **Broken Object Level Authorization (BOLA)** and **Privilege Escalation** (horizontal/vertical) in web and mobile APIs.

## How It Works

1. You provide a **low-privilege attacker's Bearer token** and a **raw HTTP request** (copied from Burp Suite) belonging to a high-privilege victim.
2. Auth-Fusion parses the raw request, **swaps** the victim's token with the attacker's token, **replays** the request, and **analyzes** the response to determine if privilege escalation occurred.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python -m auth_fusion \
  --attacker-token <LOW_PRIV_TOKEN> \
  --target-host api.example.com \
  --request-file request.txt
```

### Required Arguments

| Argument            | Description                                                    |
|---------------------|----------------------------------------------------------------|
| `--attacker-token`  | The low-privilege attacker's Bearer token.                     |
| `--target-host`     | The target domain or IP address (e.g. `api.example.com`).      |
| `--request-file`    | Path to a `.txt` file containing the raw Burp Suite request.   |

### Optional Arguments

| Argument     | Description                                                             |
|--------------|-------------------------------------------------------------------------|
| `--https`    | Force HTTPS for the request (default: `True`).                          |
| `--no-https` | Use HTTP instead of HTTPS.                                              |
| `--proxy`    | Route traffic through a proxy for debugging (e.g. `http://127.0.0.1:8080`). |
| `--version`  | Show the tool version and exit.                                         |

### Example Raw Request File (`request.txt`)

```
GET /api/v1/admin/users HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Accept: application/json
Content-Type: application/json

```

### Example Run

```bash
python -m auth_fusion \
  --attacker-token eyJhdHRhY2tlcl90b2tlbiI6InRlc3QifQ \
  --target-host api.example.com \
  --request-file request.txt \
  --proxy http://127.0.0.1:8080
```

## Project Structure

```
auth_fusion/
├── __init__.py      # Package metadata and version
├── __main__.py      # Main entry point
├── cli.py           # Phase 1: CLI argument parsing
├── parser.py        # Phase 2: Raw HTTP request parser
└── engine.py        # Phase 3: Token swapping, replay, and analysis
tests/
├── test_cli.py      # CLI tests
├── test_parser.py   # Parser tests
├── test_engine.py   # Engine tests
└── test_main.py     # Integration tests
```

## Running Tests

```bash
python -m pytest tests/ -v
```
