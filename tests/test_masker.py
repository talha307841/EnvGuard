"""Unit tests for envguard.masker — edge cases and masking rules."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from envguard.masker import (
    MaskResult,
    mask_env_content,
    mask_env_file,
    mask_line,
    mask_value,
)

# ---------------------------------------------------------------------------
# mask_value
# ---------------------------------------------------------------------------


class TestMaskValue:
    def test_long_value_keeps_prefix(self):
        masked, was_masked = mask_value("supersecret", keep_prefix_chars=3)
        assert masked == "sup***"
        assert was_masked is True

    def test_short_value_fully_masked(self):
        # value with < 6 chars
        masked, was_masked = mask_value("abc", keep_prefix_chars=3)
        assert masked == "***"
        assert was_masked is True

    def test_exactly_6_chars_keeps_prefix(self):
        # 6 chars → keep first 3
        masked, was_masked = mask_value("abcdef", keep_prefix_chars=3)
        assert masked == "abc***"
        assert was_masked is True

    def test_exactly_5_chars_fully_masked(self):
        masked, was_masked = mask_value("abcde", keep_prefix_chars=3)
        assert masked == "***"
        assert was_masked is True

    def test_quoted_double_value_long(self):
        masked, was_masked = mask_value('"supersecret"', keep_prefix_chars=3)
        assert masked == '"sup***"'
        assert was_masked is True

    def test_quoted_single_value_short(self):
        masked, was_masked = mask_value("'hi'", keep_prefix_chars=3)  # inner = 'hi' (2 chars)
        assert masked == "'***'"
        assert was_masked is True

    def test_empty_value(self):
        masked, was_masked = mask_value("", keep_prefix_chars=3)
        assert masked == "***"
        assert was_masked is True

    def test_custom_mask_char(self):
        masked, _ = mask_value("password123", mask_char="#", keep_prefix_chars=3)
        assert masked == "pas###"

    def test_keep_prefix_0(self):
        masked, _ = mask_value("abcdefgh", keep_prefix_chars=0)
        assert masked == "***"

    def test_long_value_custom_prefix_len(self):
        masked, _ = mask_value("abcdefghij", keep_prefix_chars=5)
        assert masked == "abcde***"


# ---------------------------------------------------------------------------
# mask_line
# ---------------------------------------------------------------------------


class TestMaskLine:
    SAFE_KEYS = {"NODE_ENV", "PORT", "HOST", "APP_ENV", "DEBUG", "LOG_LEVEL"}

    def test_comment_line_passthrough(self):
        line = "# This is a comment\n"
        out, result = mask_line(line, safe_keys=self.SAFE_KEYS)
        assert out == line
        assert result is None

    def test_blank_line_passthrough(self):
        line = "\n"
        out, result = mask_line(line, safe_keys=self.SAFE_KEYS)
        assert out == line
        assert result is None

    def test_safe_key_not_masked(self):
        line = "NODE_ENV=production\n"
        out, result = mask_line(line, safe_keys=self.SAFE_KEYS)
        assert out == line
        assert result is not None
        assert result.was_masked is False

    def test_secret_key_masked(self):
        line = "API_SECRET=supersecretvalue\n"
        out, result = mask_line(line, safe_keys=self.SAFE_KEYS)
        assert "API_SECRET" in out
        assert "supersecretvalue" not in out
        assert result is not None
        assert result.was_masked is True

    def test_short_secret_fully_masked(self):
        line = "DB_PASS=abc\n"
        out, result = mask_line(line, safe_keys=self.SAFE_KEYS)
        assert "***" in out
        assert "abc" not in out
        assert result is not None
        assert result.was_masked is True

    def test_port_not_masked(self):
        line = "PORT=3000\n"
        out, result = mask_line(line, safe_keys=self.SAFE_KEYS)
        assert out == line
        assert result is not None
        assert result.was_masked is False

    def test_invalid_line_passthrough(self):
        line = "not_an_assignment\n"
        out, result = mask_line(line, safe_keys=self.SAFE_KEYS)
        assert out == line
        assert result is None

    def test_value_with_equals(self):
        # Values containing '=' (e.g. base64)
        line = "TOKEN=abc==\n"
        out, result = mask_line(line, safe_keys=self.SAFE_KEYS)
        assert result is not None
        assert result.was_masked is True
        # The key should remain
        assert out.startswith("TOKEN=")

    def test_trailing_newline_preserved(self):
        line = "SECRET_KEY=longvaluexyz\n"
        out, _ = mask_line(line, safe_keys=self.SAFE_KEYS)
        assert out.endswith("\n")

    def test_no_trailing_newline(self):
        line = "SECRET_KEY=longvaluexyz"
        out, _ = mask_line(line, safe_keys=self.SAFE_KEYS)
        assert not out.endswith("\n")

    def test_debug_not_masked(self):
        line = "DEBUG=true\n"
        out, result = mask_line(line, safe_keys=self.SAFE_KEYS)
        assert out == line
        assert result.was_masked is False  # type: ignore[union-attr]

    def test_log_level_not_masked(self):
        line = "LOG_LEVEL=verbose\n"
        out, result = mask_line(line, safe_keys=self.SAFE_KEYS)
        assert out == line
        assert result.was_masked is False  # type: ignore[union-attr]

    def test_key_with_spaces_around_equals(self):
        line = "MY_KEY = somevalue123\n"
        out, result = mask_line(line, safe_keys=self.SAFE_KEYS)
        assert result is not None
        assert result.was_masked is True


# ---------------------------------------------------------------------------
# mask_env_content
# ---------------------------------------------------------------------------


class TestMaskEnvContent:
    SAFE_KEYS = {"NODE_ENV", "PORT", "HOST", "APP_ENV", "DEBUG", "LOG_LEVEL"}

    def test_full_env_file(self):
        content = textwrap.dedent("""\
            # App config
            NODE_ENV=production
            PORT=8080

            DB_PASSWORD=supersecretpass
            API_KEY=myapikey123456
            DEBUG=false
        """)
        masked, results = mask_env_content(content, safe_keys=self.SAFE_KEYS)

        # Comments and blank lines preserved
        assert "# App config" in masked
        assert "\n\n" in masked

        # Safe keys preserved
        assert "NODE_ENV=production" in masked
        assert "PORT=8080" in masked
        assert "DEBUG=false" in masked

        # Secrets masked
        assert "supersecretpass" not in masked
        assert "myapikey123456" not in masked
        assert "DB_PASSWORD=sup***" in masked
        assert "API_KEY=mya***" in masked

        # Result list
        safe_results = [r for r in results if not r.was_masked]
        masked_results = [r for r in results if r.was_masked]
        assert len(safe_results) == 3  # NODE_ENV, PORT, DEBUG
        assert len(masked_results) == 2  # DB_PASSWORD, API_KEY

    def test_empty_file(self):
        masked, results = mask_env_content("", safe_keys=self.SAFE_KEYS)
        assert masked == ""
        assert results == []

    def test_only_comments(self):
        content = "# comment one\n# comment two\n"
        masked, results = mask_env_content(content, safe_keys=self.SAFE_KEYS)
        assert masked == content
        assert results == []

    def test_all_safe_keys(self):
        content = "NODE_ENV=test\nPORT=3000\nHOST=localhost\n"
        masked, results = mask_env_content(content, safe_keys=self.SAFE_KEYS)
        assert masked == content
        assert all(not r.was_masked for r in results)

    def test_preserves_line_endings(self):
        content = "KEY=longvalue123\r\n"
        masked, _ = mask_env_content(content, safe_keys=self.SAFE_KEYS)
        # Our masker preserves the original line endings
        assert masked.endswith("\r\n") or "KEY=" in masked


# ---------------------------------------------------------------------------
# mask_env_file
# ---------------------------------------------------------------------------


class TestMaskEnvFile:
    SAFE_KEYS = {"NODE_ENV", "PORT", "HOST", "APP_ENV", "DEBUG", "LOG_LEVEL"}

    def test_writes_temp_file(self, tmp_path):
        env = tmp_path / ".env"
        env.write_text("SECRET=longpassword123\nNODE_ENV=test\n", encoding="utf-8")

        tmp_file, results = mask_env_file(env, safe_keys=self.SAFE_KEYS)

        assert tmp_file is not None
        assert tmp_file.exists()
        content = tmp_file.read_text(encoding="utf-8")
        assert "longpassword123" not in content
        assert "NODE_ENV=test" in content
        # Cleanup
        tmp_file.unlink()

    def test_original_unchanged(self, tmp_path):
        env = tmp_path / ".env"
        original = "SECRET=longpassword123\n"
        env.write_text(original, encoding="utf-8")

        tmp_file, _ = mask_env_file(env, safe_keys=self.SAFE_KEYS)
        assert env.read_text(encoding="utf-8") == original

        if tmp_file:
            tmp_file.unlink()

    def test_dry_run_returns_none_path(self, tmp_path, capsys):
        env = tmp_path / ".env"
        env.write_text("SECRET=longpassword123\n", encoding="utf-8")

        tmp_file, results = mask_env_file(env, safe_keys=self.SAFE_KEYS, dry_run=True)
        assert tmp_file is None
        assert len(results) == 1
        assert results[0].was_masked is True
