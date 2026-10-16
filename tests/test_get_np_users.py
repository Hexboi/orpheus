from types import SimpleNamespace

import pytest

import GetNPUsers


def options(**overrides):
    values = dict(
        no_pass=True, outputfile=None, format="hashcat", usersfile=None,
        aesKey=None, k=False, request=True, dc_ip="192.0.2.1", dc_host=None,
        options="0x40810010", encryption="18", sleep="0", jitter="0",
        hashes=None,
        overwrite=False,
    )
    values.update(overrides)
    return SimpleNamespace(**values)


def test_direct_no_pass_user_sends_one_as_req(monkeypatch):
    runner = GetNPUsers.GetUserNoPreAuth("alice", "", "lab.local", options())
    calls = []
    monkeypatch.setattr(runner, "getTGT", lambda username: calls.append(username) or "ticket")
    monkeypatch.setattr(runner, "outputTGT", lambda *args: None)

    runner.run()

    assert calls == ["alice"]


def test_users_file_ignores_blanks_and_duplicate_names(monkeypatch, tmp_path):
    users = tmp_path / "users.txt"
    users.write_text("alice\n\nalice\nbob\n", encoding="utf-8")
    runner = GetNPUsers.GetUserNoPreAuth(
        "", "", "lab.local", options(usersfile=str(users))
    )
    observed = []
    monkeypatch.setattr(runner, "request_multiple_TGTs", lambda names: observed.extend(names))

    runner.request_users_file_TGTs()

    assert observed == ["alice", "bob"]


def test_mixed_results_return_partial_summary_and_commit_successes(monkeypatch, tmp_path):
    destination = tmp_path / "results.txt"
    runner = GetNPUsers.GetUserNoPreAuth(
        "", "", "lab.local", options(outputfile=str(destination))
    )
    monkeypatch.setattr(
        runner, "getTGT",
        lambda username: "ticket-" + username if username == "alice" else (_ for _ in ()).throw(RuntimeError("denied")),
    )
    monkeypatch.setattr(runner, "outputTGT", lambda entry, fd=None: fd.write(entry + "\n"))

    summary = runner.request_multiple_TGTs(["alice", "bob"])

    assert (summary.attempted, summary.succeeded, summary.failed) == (2, 1, 1)
    assert destination.read_text(encoding="utf-8") == "ticket-alice\n"


def test_total_failure_preserves_existing_output(monkeypatch, tmp_path):
    destination = tmp_path / "results.txt"
    destination.write_text("old\n", encoding="utf-8")
    runner = GetNPUsers.GetUserNoPreAuth(
        "", "", "lab.local", options(outputfile=str(destination), overwrite=True)
    )
    monkeypatch.setattr(runner, "getTGT", lambda username: (_ for _ in ()).throw(RuntimeError("denied")))

    summary = runner.request_multiple_TGTs(["alice"])

    assert summary.failed == 1
    assert destination.read_text(encoding="utf-8") == "old\n"


def test_main_returns_no_results_exit_code(monkeypatch):
    class FakeRunner:
        def __init__(self, *args):
            pass

        def run(self):
            return GetNPUsers.RunSummary(attempted=1, failed=1)

    monkeypatch.setattr(GetNPUsers, "GetUserNoPreAuth", FakeRunner)
    code = GetNPUsers.main([
        "lab.local/alice", "-no-pass", "-request", "-dc-ip", "192.0.2.1"
    ])
    assert code == 5


def test_main_classifies_socket_permission_error_as_network_failure(monkeypatch):
    class FakeRunner:
        def __init__(self, *args):
            pass

        def run(self):
            raise PermissionError(10013, "socket blocked")

    monkeypatch.setattr(GetNPUsers, "GetUserNoPreAuth", FakeRunner)
    assert GetNPUsers.main([
        "lab.local/alice", "-no-pass", "-request", "-dc-ip", "192.0.2.1"
    ]) == 4


def test_main_accepts_existing_users_file(monkeypatch, tmp_path):
    users = tmp_path / "users.txt"
    users.write_text("alice\n", encoding="utf-8")

    class FakeRunner:
        def __init__(self, *args):
            pass

        def run(self):
            return GetNPUsers.RunSummary(attempted=1, succeeded=1)

    monkeypatch.setattr(GetNPUsers, "GetUserNoPreAuth", FakeRunner)
    assert GetNPUsers.main([
        "lab.local/", "-no-pass", "-request", "-usersfile", str(users)
    ]) == 0


def test_main_rejects_existing_output_before_network(monkeypatch, tmp_path):
    output = tmp_path / "existing.txt"
    output.write_text("old", encoding="utf-8")

    class FakeRunner:
        def __init__(self, *args):
            raise AssertionError("network runner constructed")

    monkeypatch.setattr(GetNPUsers, "GetUserNoPreAuth", FakeRunner)
    assert GetNPUsers.main([
        "lab.local/alice", "-no-pass", "-request", "-outputfile", str(output)
    ]) == 2


def test_main_normalizes_decimal_kdc_options_before_runner(monkeypatch):
    observed = {}

    class FakeRunner:
        def __init__(self, *args):
            observed["options"] = args[-1].options

        def run(self):
            return GetNPUsers.RunSummary()

    monkeypatch.setattr(GetNPUsers, "GetUserNoPreAuth", FakeRunner)

    assert GetNPUsers.main([
        "lab.local/alice", "-no-pass", "-options", "16"
    ]) == 0
    assert observed["options"] == "0x00000010"


def test_main_rejects_short_nt_hash_before_runner(monkeypatch):
    monkeypatch.setattr(
        GetNPUsers, "GetUserNoPreAuth",
        lambda *args: (_ for _ in ()).throw(AssertionError("runner constructed")),
    )

    assert GetNPUsers.main([
        "lab.local/alice", "-hashes", ":aa", "-no-pass"
    ]) == 2


@pytest.mark.parametrize(
    "outcomes",
    [(True, True), (False, True), (True, False), (False, False)],
)
def test_usersfile_pacing_occurs_between_all_attempts(monkeypatch, outcomes):
    runner = GetNPUsers.GetUserNoPreAuth("", "", "lab.local", options())
    events = []
    iterator = iter(outcomes)

    def get_tgt(username):
        events.append("request")
        if not next(iterator):
            raise RuntimeError("denied")
        return "ticket"

    monkeypatch.setattr(runner, "getTGT", get_tgt)
    monkeypatch.setattr(runner, "outputTGT", lambda *args: None)
    monkeypatch.setattr(runner, "haveARest", lambda: events.append("rest"))

    runner.request_multiple_TGTs(["first", "second"])

    assert events == ["request", "rest", "request"]


def test_help_explains_cache_only_auth_kdc_base_and_pacing():
    help_text = GetNPUsers.build_parser().format_help().lower()
    assert "-k -no-pass" in help_text
    assert "decimal or 0x-prefixed" in help_text
    assert "between consecutive" in help_text
