"""Tests for the ANSI color helpers and terminal detection."""

from __future__ import annotations

import io

import pytest

from cm500_status.color import Palette, palette_for, should_colorize


def test_palette_disabled_returns_text_unchanged() -> None:
    palette = Palette(enabled=False)
    assert palette.paint("hello", "red", "bold") == "hello"


def test_palette_enabled_wraps_with_codes_and_reset() -> None:
    palette = Palette(enabled=True)
    painted = palette.paint("hello", "red")
    assert painted == "\033[31mhello\033[0m"


def test_palette_enabled_without_styles_is_unchanged() -> None:
    palette = Palette(enabled=True)
    assert palette.paint("hello") == "hello"


def test_palette_ignores_unknown_style_names() -> None:
    palette = Palette(enabled=True)
    assert palette.paint("hello", "chartreuse") == "hello"


class _FakeTTY(io.StringIO):
    def isatty(self) -> bool:
        return True


class _FakePipe(io.StringIO):
    def isatty(self) -> bool:
        return False


def test_should_colorize_true_for_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert should_colorize(_FakeTTY(), force_off=False) is True


def test_should_colorize_false_for_pipe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert should_colorize(_FakePipe(), force_off=False) is False


def test_should_colorize_respects_force_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert should_colorize(_FakeTTY(), force_off=True) is False


def test_should_colorize_respects_no_color_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    assert should_colorize(_FakeTTY(), force_off=False) is False


def test_palette_for_builds_from_stream(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert palette_for(_FakeTTY()).enabled is True
    assert palette_for(_FakePipe()).enabled is False
