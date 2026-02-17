"""Tests for the raw HTTP request parser (Phase 2)."""

import pytest

from auth_fusion.parser import ParsedRequest, load_request_file, parse_raw_request


class TestParseRawRequest:
    """Tests for parse_raw_request function."""

    def test_basic_get_request(self):
        raw = (
            "GET /api/v1/users HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Authorization: Bearer victim_token_123\r\n"
            "Accept: application/json\r\n"
            "\r\n"
        )
        result = parse_raw_request(raw)
        assert result.method == "GET"
        assert result.path == "/api/v1/users"
        assert result.headers["Host"] == "example.com"
        assert result.headers["Authorization"] == "Bearer victim_token_123"
        assert result.headers["Accept"] == "application/json"
        assert result.body is None

    def test_post_request_with_json_body(self):
        raw = (
            "POST /api/v1/users/update HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/json\r\n"
            "Authorization: Bearer admin_token\r\n"
            "\r\n"
            '{"name": "John", "role": "admin"}'
        )
        result = parse_raw_request(raw)
        assert result.method == "POST"
        assert result.path == "/api/v1/users/update"
        assert result.body == '{"name": "John", "role": "admin"}'

    def test_put_request(self):
        raw = (
            "PUT /api/v1/profile/42 HTTP/1.1\r\n"
            "Host: api.target.com\r\n"
            "Authorization: Bearer token\r\n"
            "\r\n"
            "field1=value1&field2=value2"
        )
        result = parse_raw_request(raw)
        assert result.method == "PUT"
        assert result.path == "/api/v1/profile/42"
        assert result.body == "field1=value1&field2=value2"

    def test_delete_request_no_body(self):
        raw = (
            "DELETE /api/v1/users/99 HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Authorization: Bearer token\r\n"
            "\r\n"
        )
        result = parse_raw_request(raw)
        assert result.method == "DELETE"
        assert result.path == "/api/v1/users/99"
        assert result.body is None

    def test_unix_line_endings(self):
        raw = (
            "GET /api/data HTTP/1.1\n"
            "Host: example.com\n"
            "Authorization: Bearer abc\n"
            "\n"
        )
        result = parse_raw_request(raw)
        assert result.method == "GET"
        assert result.path == "/api/data"
        assert result.headers["Authorization"] == "Bearer abc"

    def test_no_blank_line_no_body(self):
        raw = (
            "GET /api/v1/info HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Authorization: Bearer token"
        )
        result = parse_raw_request(raw)
        assert result.method == "GET"
        assert result.path == "/api/v1/info"
        assert result.body is None

    def test_malformed_request_line_raises(self):
        raw = "INVALID\r\nHost: example.com\r\n\r\n"
        with pytest.raises(ValueError, match="Malformed request line"):
            parse_raw_request(raw)

    def test_empty_request_line_raises(self):
        raw = "\r\nHost: example.com\r\n\r\n"
        with pytest.raises(ValueError, match="Malformed request line"):
            parse_raw_request(raw)

    def test_patch_request(self):
        raw = (
            "PATCH /api/v1/items/5 HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"status": "active"}'
        )
        result = parse_raw_request(raw)
        assert result.method == "PATCH"
        assert result.path == "/api/v1/items/5"

    def test_header_with_colon_in_value(self):
        raw = (
            "GET /api/test HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Cookie: session=abc:def:ghi\r\n"
            "\r\n"
        )
        result = parse_raw_request(raw)
        assert result.headers["Cookie"] == "session=abc:def:ghi"

    def test_body_with_newlines(self):
        raw = (
            "POST /api/data HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n"
            '{\n  "key": "value"\n}'
        )
        result = parse_raw_request(raw)
        assert result.body is not None
        assert '"key": "value"' in result.body

    def test_parsed_request_repr(self):
        req = ParsedRequest("GET", "/test", {"Host": "x"}, None)
        r = repr(req)
        assert "GET" in r
        assert "/test" in r
        assert "<none>" in r

    def test_parsed_request_repr_with_body(self):
        req = ParsedRequest("POST", "/test", {}, "data")
        r = repr(req)
        assert "<present>" in r


class TestLoadRequestFile:
    """Tests for load_request_file function."""

    def test_load_valid_file(self, tmp_path):
        f = tmp_path / "req.txt"
        f.write_text("GET /test HTTP/1.1\r\nHost: x\r\n\r\n")
        content = load_request_file(str(f))
        assert "GET /test" in content

    def test_load_nonexistent_file(self):
        with pytest.raises(FileNotFoundError):
            load_request_file("/nonexistent/path/file.txt")
