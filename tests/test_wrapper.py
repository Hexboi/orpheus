import subprocess
from pathlib import Path

import pytest

import orpheus


@pytest.mark.parametrize(
    ("raw", "normalized", "bits"),
    [
        ("0", "0x00000000", "0" * 32),
        ("0xffffffff", "0xffffffff", "1" * 32),
        ("0X40810000", "0x40810000", "01000000100000010000000000000000"),
    ],
)
def test_parse_kdc_options_accepts_unsigned_32_bit_values(raw, normalized, bits):
    assert orpheus.parse_kdc_options(raw) == (normalized, bits)


@pytest.mark.parametrize("raw", ["", "-1", "0x100000000", "nope", "0x-1"])
def test_parse_kdc_options_rejects_values_outside_unsigned_32_bit(raw):
    with pytest.raises(ValueError):
        orpheus.parse_kdc_options(raw)


@pytest.mark.parametrize("raw", ["-1", "-20", "x", ""])
def test_parse_nonnegative_int_rejects_invalid_values(raw):
    with pytest.raises(ValueError):
        orpheus.parse_nonnegative_int(raw, "sleep")


def test_build_argv_keeps_user_values_as_individual_tokens(tmp_path):
    output = tmp_path / "name with spaces;$(ignored).txt"
    config = orpheus.OrpheusConfig(
        cred="lab/user:p;ass",
        dcip="192.0.2.10",
        output_file=str(output),
        overwrite=True,
    )

    argv = orpheus.build_argv(config)

    assert argv[0] == orpheus.sys.executable
    assert argv[1].endswith("GetUserSPNs.py")
    assert "lab/user:p;ass" in argv
    assert str(output) in argv
    assert "-overwrite" in argv


def test_run_cli_passes_child_exit_code_through(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: subprocess.CompletedProcess(a, 4))

    result = orpheus.run_cli([
        "--cred", "lab/user:pass",
        "--dcip", "192.0.2.10",
        "--file", str(tmp_path / "result.txt"),
    ])

    assert result == 4


def test_invalid_repl_values_preserve_previous_state(monkeypatch):
    monkeypatch.setattr(orpheus, "clear_screen", lambda: None)
    monkeypatch.setattr(orpheus, "banner", lambda: None)
    monkeypatch.setattr(orpheus, "kdcopt", "0x40810000")
    monkeypatch.setattr(orpheus, "kdcbin", "01000000100000010000000000000000")
    monkeypatch.setattr(orpheus, "sleep", 4)
    monkeypatch.setattr(orpheus, "jitter", 2)

    orpheus.apply_hex("0x100000000")
    orpheus.apply_sleep("-1")
    orpheus.apply_jitter("-2")

    assert orpheus.kdcopt == "0x40810000"
    assert orpheus.kdcbin == "01000000100000010000000000000000"
    assert orpheus.sleep == 4
    assert orpheus.jitter == 2


def test_repl_can_enable_overwrite(monkeypatch):
    monkeypatch.setattr(orpheus, "clear_screen", lambda: None)
    monkeypatch.setattr(orpheus, "banner", lambda: None)
    monkeypatch.setattr(orpheus, "overwrite", False)
    orpheus.toggle_overwrite()
    assert orpheus.overwrite is True


def test_cli_help_explains_kdc_base_and_pacing():
    help_text = orpheus.build_parser().format_help().lower()
    assert "decimal or 0x-prefixed" in help_text
    assert "between consecutive" in help_text


def test_console_entrypoint_returns_cli_exit_code(monkeypatch):
    monkeypatch.setattr(orpheus.sys, "argv", ["orpheus", "--help"])
    monkeypatch.setattr(orpheus, "run_cli", lambda: 4)

    assert orpheus.cli() == 4


def test_console_entrypoint_without_arguments_starts_repl(monkeypatch):
    events = []
    monkeypatch.setattr(orpheus.sys, "argv", ["orpheus"])
    monkeypatch.setattr(orpheus, "signal", lambda *args: events.append("signal"))
    monkeypatch.setattr(orpheus, "main", lambda: events.append("repl"))

    assert orpheus.cli() == 0
    assert events == ["signal", "repl"]
