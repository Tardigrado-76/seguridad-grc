#!/usr/bin/env python3
"""
test_i18n_engine.py - TDD Suite for Quantigrade I18n Engine.
Validates 8 supported languages, key resolution, parameter interpolation, and fallback logic.
"""

from __future__ import annotations

import pytest

from core_mesh.i18n import (
    SUPPORTED_LANGUAGES,
    I18nEngine,
    get_current_locale,
    set_locale,
    t,
)


def test_supported_languages_contains_8_locales():
    expected_codes = {"es", "en", "fr", "de", "it", "pt", "zh", "ja"}
    assert set(SUPPORTED_LANGUAGES.keys()) == expected_codes


@pytest.mark.parametrize("lang", ["es", "en", "fr", "de", "it", "pt", "zh", "ja"])
def test_all_languages_have_essential_keys(lang: str):
    engine = I18nEngine(default_lang=lang)
    assert engine.t("app_title") != "app_title"
    assert engine.t("metric_compliance") != "metric_compliance"
    assert engine.t("tab_csuite") != "tab_csuite"
    assert engine.t("tab_wargame") != "tab_wargame"


def test_parameter_interpolation():
    msg_es = t("airgap_breached", lang="es", count=3)
    assert "3 llamadas externas detectadas" in msg_es

    msg_en = t("airgap_breached", lang="en", count=5)
    assert "5 external calls detected" in msg_en

    msg_zh = t("airgap_breached", lang="zh", count=2)
    assert "检测到 2 次外部出站请求" in msg_zh


def test_fallback_on_missing_key():
    engine = I18nEngine(default_lang="fr")
    # Non-existent key should return the key itself
    res = engine.t("non_existent_regulatory_kpi_12345")
    assert res == "non_existent_regulatory_kpi_12345"


def test_locale_switching():
    set_locale("de")
    assert get_current_locale() == "de"
    assert t("metric_compliance") == "Gesamtkonformität"

    set_locale("es")
    assert get_current_locale() == "es"
    assert t("metric_compliance") == "Cumplimiento Global"
