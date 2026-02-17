"""Tests for the CLI module (Phase 1)."""

import pytest

from auth_fusion.cli import build_parser, parse_cli, validate_args


class TestBuildParser:
    """Tests for the argument parser construction."""

    def test_parser_has_required_args(self):
        parser = build_parser()
        # Should parse without error when all required args are given
        args = parser.parse_args([
            "--attacker-token", "test_token",
            "--target-host", "example.com",
            "--request-file", "request.txt",
        ])
        assert args.attacker_token == "test_token"
        assert args.target_host == "example.com"
        assert args.request_file == "request.txt"

    def test_default_https_is_true(self):
        parser = build_parser()
        args = parser.parse_args([
            "--attacker-token", "t",
            "--target-host", "h",
            "--request-file", "f",
        ])
        assert args.use_https is True

    def test_no_https_flag(self):
        parser = build_parser()
        args = parser.parse_args([
            "--attacker-token", "t",
            "--target-host", "h",
            "--request-file", "f",
            "--no-https",
        ])
        assert args.use_https is False

    def test_proxy_argument(self):
        parser = build_parser()
        args = parser.parse_args([
            "--attacker-token", "t",
            "--target-host", "h",
            "--request-file", "f",
            "--proxy", "http://127.0.0.1:8080",
        ])
        assert args.proxy == "http://127.0.0.1:8080"

    def test_proxy_default_is_none(self):
        parser = build_parser()
        args = parser.parse_args([
            "--attacker-token", "t",
            "--target-host", "h",
            "--request-file", "f",
        ])
        assert args.proxy is None

    def test_missing_required_args(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])


class TestValidateArgs:
    """Tests for argument validation."""

    def test_nonexistent_file_exits(self, tmp_path):
        parser = build_parser()
        args = parser.parse_args([
            "--attacker-token", "token",
            "--target-host", "host",
            "--request-file", "/nonexistent/file.txt",
        ])
        with pytest.raises(SystemExit):
            validate_args(args)

    def test_valid_file_passes(self, tmp_path):
        f = tmp_path / "req.txt"
        f.write_text("GET / HTTP/1.1\r\n\r\n")
        parser = build_parser()
        args = parser.parse_args([
            "--attacker-token", "token",
            "--target-host", "host",
            "--request-file", str(f),
        ])
        # Should not raise
        validate_args(args)

    def test_empty_token_exits(self, tmp_path):
        f = tmp_path / "req.txt"
        f.write_text("GET / HTTP/1.1\r\n\r\n")
        parser = build_parser()
        args = parser.parse_args([
            "--attacker-token", "   ",
            "--target-host", "host",
            "--request-file", str(f),
        ])
        with pytest.raises(SystemExit):
            validate_args(args)

    def test_empty_host_exits(self, tmp_path):
        f = tmp_path / "req.txt"
        f.write_text("GET / HTTP/1.1\r\n\r\n")
        parser = build_parser()
        args = parser.parse_args([
            "--attacker-token", "token",
            "--target-host", "   ",
            "--request-file", str(f),
        ])
        with pytest.raises(SystemExit):
            validate_args(args)


class TestParseCli:
    """Tests for the full parse_cli flow."""

    def test_full_parse_flow(self, tmp_path):
        f = tmp_path / "req.txt"
        f.write_text("GET / HTTP/1.1\r\n\r\n")
        args = parse_cli([
            "--attacker-token", "my_token",
            "--target-host", "api.example.com",
            "--request-file", str(f),
        ])
        assert args.attacker_token == "my_token"
        assert args.target_host == "api.example.com"
        assert args.use_https is True
