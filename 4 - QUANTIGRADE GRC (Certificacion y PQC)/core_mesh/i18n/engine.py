#!/usr/bin/env python3
"""
engine.py - Internationalization (i18n) Engine for Quantigrade GCR.
Provides deterministic, fast translation resolution with multi-level fallback.
"""

from __future__ import annotations

from typing import Any

from core_mesh.i18n.locales import SUPPORTED_LANGUAGES, TRANSLATIONS


class I18nEngine:
    """Manages active locale and string translation."""

    def __init__(self, default_lang: str = "es"):
        self.default_lang = default_lang if default_lang in SUPPORTED_LANGUAGES else "es"
        self._current_lang = self.default_lang

    @property
    def current_lang(self) -> str:
        return self._current_lang

    @current_lang.setter
    def current_lang(self, lang: str) -> None:
        if lang in SUPPORTED_LANGUAGES:
            self._current_lang = lang
        else:
            self._current_lang = self.default_lang

    def t(self, key: str, lang: str | None = None, **kwargs: Any) -> str:
        """Translates a key into the target language with formatting."""
        target_lang = lang if lang and lang in SUPPORTED_LANGUAGES else self._current_lang
        text = TRANSLATIONS.get(target_lang, {}).get(key)
        if text is None:
            text = TRANSLATIONS.get("es", {}).get(key)
        if text is None:
            text = TRANSLATIONS.get("en", {}).get(key)
        if text is None:
            text = key

        if kwargs:
            try:
                return text.format(**kwargs)
            except (KeyError, ValueError, IndexError):
                return text
        return text

    def get_supported_languages(self) -> dict[str, str]:
        """Returns map of language codes to display strings."""
        return dict(SUPPORTED_LANGUAGES)


# Global default instance
_default_engine = I18nEngine(default_lang="es")


def t(key: str, lang: str | None = None, **kwargs: Any) -> str:
    """Convenience functional access to translation."""
    return _default_engine.t(key, lang=lang, **kwargs)


def set_locale(lang: str) -> None:
    """Sets the active global locale."""
    _default_engine.current_lang = lang


def get_current_locale() -> str:
    """Gets the active global locale code."""
    return _default_engine.current_lang
