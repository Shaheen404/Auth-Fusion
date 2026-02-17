"""Tests for the main entry point (__main__.py)."""

from unittest.mock import MagicMock, patch

import pytest

from auth_fusion.__main__ import main
from auth_fusion.engine import ReplayResult


class TestMain:
    """Tests for the main function."""

    def test_missing_request_file_returns_error(self, tmp_path):
        """parse_cli calls sys.exit(1) when file doesn't exist."""
        with pytest.raises(SystemExit):
            main([
                "--attacker-token", "token",
                "--target-host", "example.com",
                "--request-file", "/nonexistent/file.txt",
            ])

    def test_malformed_request_returns_error(self, tmp_path):
        f = tmp_path / "bad.txt"
        f.write_text("BADREQUEST\r\n\r\n")
        result = main([
            "--attacker-token", "token",
            "--target-host", "example.com",
            "--request-file", str(f),
        ])
        assert result == 2

    @patch("auth_fusion.__main__.replay_request")
    def test_successful_safe_run(self, mock_replay, tmp_path):
        f = tmp_path / "req.txt"
        f.write_text(
            "GET /api/v1/users HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Authorization: Bearer victim\r\n"
            "\r\n"
        )
        mock_replay.return_value = ReplayResult(
            status_code=403,
            headers={},
            body="Forbidden",
            is_vulnerable=False,
            analysis="[SAFE]",
        )
        result = main([
            "--attacker-token", "attacker",
            "--target-host", "example.com",
            "--request-file", str(f),
        ])
        assert result == 0

    @patch("auth_fusion.__main__.replay_request")
    def test_successful_vulnerable_run(self, mock_replay, tmp_path):
        f = tmp_path / "req.txt"
        f.write_text(
            "GET /api/v1/admin HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Authorization: Bearer victim\r\n"
            "\r\n"
        )
        mock_replay.return_value = ReplayResult(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body='{"admin": true}',
            is_vulnerable=True,
            analysis="[VULNERABLE]",
        )
        result = main([
            "--attacker-token", "attacker",
            "--target-host", "example.com",
            "--request-file", str(f),
        ])
        assert result == 1

    @patch("auth_fusion.__main__.replay_request")
    def test_replay_exception_returns_error(self, mock_replay, tmp_path):
        f = tmp_path / "req.txt"
        f.write_text(
            "GET /api/v1/users HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Authorization: Bearer victim\r\n"
            "\r\n"
        )
        mock_replay.side_effect = ConnectionError("Connection refused")
        result = main([
            "--attacker-token", "attacker",
            "--target-host", "example.com",
            "--request-file", str(f),
        ])
        assert result == 2
