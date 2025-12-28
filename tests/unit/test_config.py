"""Unit tests for src/config.py"""

import os
from unittest import mock

import pytest

from src.config import get_env, get_env_bool, get_env_int


class TestGetEnv:
    """Tests for get_env function."""

    def test_returns_default_when_env_not_set(self):
        """Should return default when environment variable is not set."""
        with mock.patch.dict(os.environ, {}, clear=True):
            result = get_env("NONEXISTENT_VAR", "default_value")
            assert result == "default_value"

    def test_returns_env_value_when_set(self):
        """Should return environment variable value when set."""
        with mock.patch.dict(os.environ, {"TEST_VAR": "custom_value"}):
            result = get_env("TEST_VAR", "default_value")
            assert result == "custom_value"

    def test_returns_empty_string_when_env_is_empty(self):
        """Should return empty string when env var is set to empty string."""
        with mock.patch.dict(os.environ, {"TEST_VAR": ""}):
            result = get_env("TEST_VAR", "default_value")
            assert result == ""


class TestGetEnvInt:
    """Tests for get_env_int function."""

    def test_returns_default_when_env_not_set(self):
        """Should return default when environment variable is not set."""
        with mock.patch.dict(os.environ, {}, clear=True):
            result = get_env_int("NONEXISTENT_VAR", 42)
            assert result == 42

    def test_returns_int_value_when_set(self):
        """Should return parsed integer when env var is set."""
        with mock.patch.dict(os.environ, {"TEST_INT": "123"}):
            result = get_env_int("TEST_INT", 0)
            assert result == 123

    def test_returns_zero_when_env_is_zero(self):
        """Should return 0 when env var is set to '0'."""
        with mock.patch.dict(os.environ, {"TEST_INT": "0"}):
            result = get_env_int("TEST_INT", 99)
            assert result == 0

    def test_raises_error_on_invalid_int(self):
        """Should raise ValueError when env var is not a valid integer."""
        with (
            mock.patch.dict(os.environ, {"TEST_INT": "not_a_number"}),
            pytest.raises(ValueError),
        ):
            get_env_int("TEST_INT", 0)

    def test_handles_negative_numbers(self):
        """Should handle negative integers correctly."""
        with mock.patch.dict(os.environ, {"TEST_INT": "-50"}):
            result = get_env_int("TEST_INT", 0)
            assert result == -50


class TestGetEnvBool:
    """Tests for get_env_bool function."""

    def test_returns_default_when_env_not_set(self):
        """Should return default when environment variable is not set."""
        with mock.patch.dict(os.environ, {}, clear=True):
            result = get_env_bool("NONEXISTENT_VAR", True)
            assert result is True

            result = get_env_bool("NONEXISTENT_VAR", False)
            assert result is False

    @pytest.mark.parametrize("value", ["true", "TRUE", "True", "TrUe"])
    def test_returns_true_for_true_values(self, value):
        """Should return True for 'true' (case-insensitive)."""
        with mock.patch.dict(os.environ, {"TEST_BOOL": value}):
            result = get_env_bool("TEST_BOOL", False)
            assert result is True

    @pytest.mark.parametrize("value", ["1"])
    def test_returns_true_for_one(self, value):
        """Should return True for '1'."""
        with mock.patch.dict(os.environ, {"TEST_BOOL": value}):
            result = get_env_bool("TEST_BOOL", False)
            assert result is True

    @pytest.mark.parametrize("value", ["yes", "YES", "Yes"])
    def test_returns_true_for_yes(self, value):
        """Should return True for 'yes' (case-insensitive)."""
        with mock.patch.dict(os.environ, {"TEST_BOOL": value}):
            result = get_env_bool("TEST_BOOL", False)
            assert result is True

    @pytest.mark.parametrize(
        "value", ["false", "FALSE", "0", "no", "NO", "anything_else", ""]
    )
    def test_returns_false_for_other_values(self, value):
        """Should return False for any other value."""
        with mock.patch.dict(os.environ, {"TEST_BOOL": value}):
            result = get_env_bool("TEST_BOOL", True)
            assert result is False
