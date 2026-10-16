from types import SimpleNamespace

import pytest

import GetUserSPNs


def options(**overrides):
    values = dict(
        outputfile=None, usersfile=None, aesKey=None, k=False, request=True,
        dc_ip="192.0.2.1", save=False, request_user=None,
        options="0x40810010", encryption=18, sleep="0", jitter="0",
        hashes=None, overwrite=False,
    )
    values.update(overrides)
    return SimpleNamespace(**values)


def test_requested_tgs_etype_is_not_passed_to_tgt_acquisition(monkeypatch):
    runner = GetUserSPNs.GetUserSPNs("alice", "password", "lab.local", "lab.local", options())
    observed = {}

    def fake_tgt(*args, **kwargs):
        observed.update(kwargs)
        return b"tgt", "cipher", "old", "session"

    monkeypatch.setattr(GetUserSPNs, "get_tgt_for_credentials", fake_tgt)
    ticket = runner.getTGT(18)

    assert ticket["KDC_REP"] == b"tgt"
    assert "request_etype" not in observed
    assert "encType" not in observed


def test_users_file_is_normalized_before_ticket_requests(monkeypatch, tmp_path):
    users = tmp_path / "users.txt"
    users.write_text("alice\n\nalice\nbob\n", encoding="utf-8")
    runner = GetUserSPNs.GetUserSPNs(
        "admin", "password", "lab.local", "lab.local",
        options(usersfile=str(users)),
    )
    observed = []
    monkeypatch.setattr(runner, "request_multiple_TGSs", lambda names: observed.extend(names))
    runner.request_users_file_TGSs()
    assert observed == ["alice", "bob"]


def test_main_returns_no_results_exit_code(monkeypatch):
    class FakeRunner:
        def __init__(self, *args):
            pass

        def run(self):
            return GetUserSPNs.RunSummary(attempted=1, failed=1)

    monkeypatch.setattr(GetUserSPNs, "GetUserSPNs", FakeRunner)
    code = GetUserSPNs.main([
        "lab.local/alice:password", "-request", "-dc-ip", "192.0.2.1"
    ])
    assert code == 5


def test_main_classifies_socket_permission_error_as_network_failure(monkeypatch):
    class FakeRunner:
        def __init__(self, *args):
            pass

        def run(self):
            raise PermissionError(10013, "socket blocked")

    monkeypatch.setattr(GetUserSPNs, "GetUserSPNs", FakeRunner)
    assert GetUserSPNs.main([
        "lab.local/alice:password", "-request", "-dc-ip", "192.0.2.1"
    ]) == 4


def test_ccache_collision_requires_overwrite(monkeypatch, tmp_path):
    runner = GetUserSPNs.GetUserSPNs(
        "admin", "password", "lab.local", "lab.local", options(save=True)
    )
    destination = tmp_path / "alice.ccache"
    destination.write_text("old", encoding="utf-8")
    decoded = {
        "ticket": {
            "enc-part": {"etype": 999},
            "sname": {"name-string": ["service", "host"]},
        }
    }
    monkeypatch.setattr(GetUserSPNs.decoder, "decode", lambda *args, **kwargs: (decoded, None))
    monkeypatch.chdir(tmp_path)

    with pytest.raises(FileExistsError):
        runner.outputTGS(b"ticket", object(), object(), "alice", "alice")


def test_ccache_collision_is_detected_before_tgt_request(monkeypatch, tmp_path):
    runner = GetUserSPNs.GetUserSPNs(
        "admin", "password", "lab.local", "lab.local", options(save=True)
    )
    (tmp_path / "alice.ccache").write_text("old", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(runner, "getTGT", lambda *args: (_ for _ in ()).throw(AssertionError("network touched")))

    with pytest.raises(FileExistsError):
        runner.request_multiple_TGSs(["alice"])


def test_main_rejects_existing_output_before_network(monkeypatch, tmp_path):
    output = tmp_path / "existing.txt"
    output.write_text("old", encoding="utf-8")

    class FakeRunner:
        def __init__(self, *args):
            raise AssertionError("network runner constructed")

    monkeypatch.setattr(GetUserSPNs, "GetUserSPNs", FakeRunner)
    assert GetUserSPNs.main([
        "lab.local/alice:password", "-request", "-outputfile", str(output)
    ]) == 2


def test_main_normalizes_decimal_kdc_options_before_runner(monkeypatch):
    observed = {}

    class FakeRunner:
        def __init__(self, *args):
            observed["options"] = args[-1].options

        def run(self):
            return GetUserSPNs.RunSummary()

    monkeypatch.setattr(GetUserSPNs, "GetUserSPNs", FakeRunner)

    assert GetUserSPNs.main([
        "lab.local/alice:password", "-options", "16"
    ]) == 0
    assert observed["options"] == "0x00000010"


def test_main_rejects_short_nt_hash_before_runner(monkeypatch):
    monkeypatch.setattr(
        GetUserSPNs, "GetUserSPNs",
        lambda *args: (_ for _ in ()).throw(AssertionError("runner constructed")),
    )

    assert GetUserSPNs.main([
        "lab.local/alice", "-hashes", ":aa", "-no-pass"
    ]) == 2


class FakeOctets:
    def __init__(self, value):
        self.value = value

    def __getitem__(self, item):
        return FakeOctets(self.value[item])

    def asOctets(self):
        return self.value


def decoded_tgs(etype):
    return {
        "ticket": {
            "enc-part": {"etype": etype, "cipher": FakeOctets(b"x" * 40)},
            "realm": "LAB.LOCAL",
            "sname": {"name-string": ["service", "host"]},
        }
    }


def prepare_ticket_request(monkeypatch, runner, etype=23):
    monkeypatch.setattr(
        runner, "getTGT",
        lambda *args: {"KDC_REP": b"tgt", "cipher": object(), "sessionKey": object()},
    )
    monkeypatch.setattr(
        GetUserSPNs, "get_tgs",
        lambda *args, **kwargs: (b"ticket", object(), object(), object()),
    )
    monkeypatch.setattr(
        GetUserSPNs.decoder, "decode",
        lambda *args, **kwargs: (decoded_tgs(etype), None),
    )


def test_ccache_failure_does_not_commit_hash_or_success(monkeypatch, tmp_path):
    destination = tmp_path / "results.txt"
    runner = GetUserSPNs.GetUserSPNs(
        "admin", "password", "lab.local", "lab.local",
        options(outputfile=str(destination), save=True, overwrite=True),
    )
    prepare_ticket_request(monkeypatch, runner)

    class FailingCCache:
        def fromTGS(self, *args):
            pass

        def saveFile(self, path):
            raise OSError("ccache write failed")

    monkeypatch.setattr(GetUserSPNs, "CCache", FailingCCache)
    monkeypatch.chdir(tmp_path)

    summary = runner.request_multiple_TGSs(["alice"])

    assert (summary.succeeded, summary.failed) == (0, 1)
    assert not destination.exists()


def test_unsupported_tgs_etype_is_skipped_not_succeeded(monkeypatch, tmp_path):
    destination = tmp_path / "results.txt"
    runner = GetUserSPNs.GetUserSPNs(
        "admin", "password", "lab.local", "lab.local",
        options(outputfile=str(destination), overwrite=True),
    )
    prepare_ticket_request(monkeypatch, runner, etype=999)

    summary = runner.request_multiple_TGSs(["alice"])

    assert (summary.succeeded, summary.failed, summary.skipped) == (0, 0, 1)
    assert not destination.exists()


@pytest.mark.parametrize(
    "outcomes",
    [(True, True), (False, True), (True, False), (False, False)],
)
def test_usersfile_pacing_occurs_between_all_attempts(monkeypatch, outcomes):
    runner = GetUserSPNs.GetUserSPNs(
        "admin", "password", "lab.local", "lab.local", options()
    )
    events = []
    iterator = iter(outcomes)
    monkeypatch.setattr(
        runner, "getTGT",
        lambda *args: {"KDC_REP": b"tgt", "cipher": object(), "sessionKey": object()},
    )

    def get_tgs(*args, **kwargs):
        events.append("request")
        if not next(iterator):
            raise RuntimeError("denied")
        return b"ticket", object(), object(), object()

    monkeypatch.setattr(GetUserSPNs, "get_tgs", get_tgs)
    monkeypatch.setattr(runner, "outputTGS", lambda *args: True)
    monkeypatch.setattr(runner, "haveARest", lambda: events.append("rest"))

    runner.request_multiple_TGSs(["first", "second"])

    assert events == ["request", "rest", "request"]


def test_help_explains_cache_only_auth_kdc_base_and_pacing():
    help_text = GetUserSPNs.build_parser().format_help().lower()
    assert "-k -no-pass" in help_text
    assert "decimal or 0x-prefixed" in help_text
    assert "between consecutive" in help_text
