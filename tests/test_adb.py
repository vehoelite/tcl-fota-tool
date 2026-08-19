"""Tests for reading a device's identity, esp. the FOTA fv derivation."""

from tcl_fw import adb


def test_fv_from_sysver_matches_stock_app():
    # The FOTA app derives fv as sysVer[1:4] + sysVer[6] + sysVer[4:8]; these
    # sysver inputs must reproduce known-good, live-confirmed fv values.
    assert adb._fv_from_sysver("X9LBZDH0") == "9LBHZDH0"
    assert adb._fv_from_sysver("XAXAWTM0") == "AXAMWTM0"


def test_fv_from_sysver_is_self_consistent():
    # The transform forces fv[3] == fv[6] (both come from sysVer[6]).
    fv = adb._fv_from_sysver("Q7ABCDE9")
    assert fv is not None and fv[3] == fv[6]


def test_fv_from_sysver_handles_missing_or_short():
    assert adb._fv_from_sysver(None) is None
    assert adb._fv_from_sysver("") is None
    assert adb._fv_from_sysver("SHORT") is None
    # Trailing whitespace from `getprop` must not throw the length check off.
    assert adb._fv_from_sysver("X9LBZDH0\n") == "9LBHZDH0"
