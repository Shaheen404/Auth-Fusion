"""Tests for the execution & manipulation engine (Phase 3)."""

from unittest.mock import MagicMock, patch

import pytest

from auth_fusion.engine import (
    ReplayResult,
    analyze_response,
    build_url,
    print_report,
    swap_token,
)
from auth_fusion.parser import ParsedRequest


class TestSwapToken:
    """Tests for the token swapping function."""

    def test_swaps_authorization_header(self):
        headers = {
            "Host": "example.com",
            "Authorization": "Bearer victim_token",
            "Accept": "application/json",
        }
        result = swap_token(headers, "attacker_token")
        assert result["Authorization"] == "Bearer attacker_token"
        assert result["Host"] == "example.com"
        assert result["Accept"] == "application/json"

    def test_case_insensitive_authorization(self):
        headers = {
            "authorization": "Bearer old_token",
        }
        result = swap_token(headers, "new_token")
        assert result["authorization"] == "Bearer new_token"

    def test_adds_authorization_if_missing(self):
        headers = {"Host": "example.com"}
        result = swap_token(headers, "token")
        assert result["Authorization"] == "Bearer token"

    def test_does_not_mutate_original(self):
        headers = {"Authorization": "Bearer old"}
        result = swap_token(headers, "new")
        assert headers["Authorization"] == "Bearer old"
        assert result["Authorization"] == "Bearer new"


class TestBuildUrl:
    """Tests for URL construction."""

    def test_https_url(self):
        url = build_url("api.example.com", "/api/v1/users", use_https=True)
        assert url == "https://api.example.com/api/v1/users"

    def test_http_url(self):
        url = build_url("api.example.com", "/api/v1/users", use_https=False)
        assert url == "http://api.example.com/api/v1/users"

    def test_trailing_slash_on_host(self):
        url = build_url("api.example.com/", "/api/v1/users")
        assert url == "https://api.example.com/api/v1/users"

    def test_missing_leading_slash_on_path(self):
        url = build_url("api.example.com", "api/v1/users")
        assert url == "https://api.example.com/api/v1/users"


class TestAnalyzeResponse:
    """Tests for response analysis heuristics."""

    def _mock_response(self, status_code: int, text: str) -> MagicMock:
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = text
        return resp

    def test_401_is_safe(self):
        resp = self._mock_response(401, "Unauthorized")
        is_vuln, msg = analyze_response(resp)
        assert is_vuln is False
        assert "SAFE" in msg

    def test_403_is_safe(self):
        resp = self._mock_response(403, "Forbidden")
        is_vuln, msg = analyze_response(resp)
        assert is_vuln is False
        assert "SAFE" in msg

    def test_404_is_inconclusive(self):
        resp = self._mock_response(404, "Not Found")
        is_vuln, msg = analyze_response(resp)
        assert is_vuln is False
        assert "INCONCLUSIVE" in msg

    def test_200_with_data_is_vulnerable(self):
        resp = self._mock_response(200, '{"user": "admin", "role": "admin"}')
        is_vuln, msg = analyze_response(resp)
        assert is_vuln is True
        assert "VULNERABLE" in msg

    def test_200_with_empty_body_is_safe(self):
        resp = self._mock_response(200, "")
        is_vuln, msg = analyze_response(resp)
        assert is_vuln is False
        assert "LIKELY SAFE" in msg

    def test_500_needs_manual_review(self):
        resp = self._mock_response(500, "Server Error")
        is_vuln, msg = analyze_response(resp)
        assert is_vuln is False
        assert "MANUAL REVIEW" in msg


class TestPrintReport:
    """Tests for the report printer."""

    def test_print_safe_report(self, capsys):
        result = ReplayResult(
            status_code=403,
            headers={"Content-Type": "text/plain"},
            body="Forbidden",
            is_vulnerable=False,
            analysis="[SAFE] Access Denied",
        )
        print_report(result)
        captured = capsys.readouterr()
        assert "403" in captured.out
        assert "NO" in captured.out

    def test_print_vulnerable_report(self, capsys):
        result = ReplayResult(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body='{"secret": "data"}',
            is_vulnerable=True,
            analysis="[VULNERABLE] HTTP 200",
        )
        print_report(result)
        captured = capsys.readouterr()
        assert "200" in captured.out
        assert "YES" in captured.out
        assert "secret" in captured.out
