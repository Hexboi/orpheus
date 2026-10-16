from pathlib import Path

import pytest

import orpheus_runtime
from orpheus_runtime import ExitCode, ResultWriter, RunSummary, atomic_save, bounded_delay, load_usernames


@pytest.mark.parametrize(
    ("summary", "enumeration", "expected"),
    [
        (RunSummary(), True, ExitCode.SUCCESS),
        (RunSummary(attempted=2, succeeded=2), False, ExitCode.SUCCESS),
        (RunSummary(attempted=2, succeeded=1, failed=1), False, ExitCode.PARTIAL),
        (RunSummary(attempted=2, failed=2), False, ExitCode.NO_RESULTS),
        (RunSummary(attempted=1, skipped=1), False, ExitCode.NO_RESULTS),
    ],
)
def test_run_summary_maps_results_to_stable_exit_codes(summary, enumeration, expected):
    assert summary.exit_code(enumeration) == expected


class BoundaryRng:
    def __init__(self, value):
        self.value = value

    def randint(self, low, high):
        assert low <= self.value <= high
        return self.value


def test_bounded_delay_never_returns_negative_seconds():
    assert bounded_delay(1, 5, BoundaryRng(-5)) == 0
    assert bounded_delay(1, 5, BoundaryRng(5)) == 6


@pytest.mark.parametrize(
    ("raw", "normalized", "indexes"),
    [
        ("16", "0x00000010", [27]),
        ("0x10", "0x00000010", [27]),
        (0, "0x00000000", []),
        ("0xffffffff", "0xffffffff", list(range(32))),
    ],
)
def test_normalize_kdc_options_accepts_decimal_and_hex(raw, normalized, indexes):
    assert orpheus_runtime.normalize_kdc_options(raw) == (normalized, indexes)


@pytest.mark.parametrize("raw", ["", " 16", "16 ", "-1", "0x100000000", "nope"])
def test_normalize_kdc_options_rejects_invalid_values(raw):
    with pytest.raises(ValueError, match="unsigned 32-bit"):
        orpheus_runtime.normalize_kdc_options(raw)


def test_load_usernames_ignores_blanks_and_deduplicates_stably(tmp_path):
    source = tmp_path / "users.txt"
    source.write_text("alice\n\n bob \nalice\nBob\n", encoding="utf-8")
    assert load_usernames(source) == ["alice", "bob", "Bob"]


def test_result_writer_preserves_existing_file_on_total_failure(tmp_path):
    destination = tmp_path / "results.txt"
    destination.write_text("old\n", encoding="utf-8")
    with ResultWriter(destination, overwrite=True):
        pass
    assert destination.read_text(encoding="utf-8") == "old\n"


def test_result_writer_refuses_collision_without_overwrite(tmp_path):
    destination = tmp_path / "results.txt"
    destination.write_text("old", encoding="utf-8")
    with pytest.raises(FileExistsError):
        with ResultWriter(destination):
            pass


def test_result_writer_atomically_replaces_after_result(tmp_path):
    destination = tmp_path / "results.txt"
    destination.write_text("old", encoding="utf-8")
    with ResultWriter(destination, overwrite=True) as writer:
        writer.write("new\n")
    assert destination.read_text(encoding="utf-8") == "new\n"
    assert list(tmp_path.glob(".results.txt.*.tmp")) == []


def test_result_writer_cleans_temporary_file_when_replace_fails(monkeypatch, tmp_path):
    destination = tmp_path / "results.txt"
    monkeypatch.setattr("orpheus_runtime.os.replace", lambda *args: (_ for _ in ()).throw(OSError("locked")))

    with pytest.raises(OSError, match="locked"):
        with ResultWriter(destination) as writer:
            writer.write("new\n")

    assert not destination.exists()
    assert list(tmp_path.glob(".results.txt.*.tmp")) == []


def test_atomic_save_replaces_binary_destination_only_after_success(tmp_path):
    destination = tmp_path / "ticket.ccache"
    destination.write_bytes(b"old")

    def save(path):
        Path(path).write_bytes(b"new")

    atomic_save(save, destination, overwrite=True)
    assert destination.read_bytes() == b"new"
    assert list(tmp_path.glob(".ticket.ccache.*.tmp")) == []
