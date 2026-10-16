import struct

import pytest

import orpheus_kerberos


class FakeSocket:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.sent = b""
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def sendall(self, data):
        self.sent += data

    def recv(self, size):
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if len(chunk) > size:
            self.chunks.insert(0, chunk[size:])
            return chunk[:size]
        return chunk


def test_send_receive_handles_fragmented_header_and_body(monkeypatch):
    sock = FakeSocket([b"\x00", b"\x00\x00", b"\x05", b"he", b"l", b"lo"])
    monkeypatch.setattr(orpheus_kerberos.socket, "create_connection", lambda *a, **k: sock)

    result = orpheus_kerberos.send_receive(b"request", "realm", "192.0.2.1")

    assert result == b"hello"
    assert sock.sent == struct.pack("!I", 7) + b"request"
    assert sock.closed


@pytest.mark.parametrize("chunks", [[b"\x00"], [struct.pack("!I", 5), b"hi"]])
def test_send_receive_reports_early_eof_and_closes(monkeypatch, chunks):
    sock = FakeSocket(chunks)
    monkeypatch.setattr(orpheus_kerberos.socket, "create_connection", lambda *a, **k: sock)

    with pytest.raises(ConnectionError, match=r"192\.0\.2\.1:88.*expected.*received"):
        orpheus_kerberos.send_receive(b"request", "realm", "192.0.2.1")

    assert sock.closed


def test_send_receive_passes_bounded_timeout(monkeypatch):
    observed = {}
    sock = FakeSocket([struct.pack("!I", 0)])

    def connect(endpoint, timeout):
        observed.update(endpoint=endpoint, timeout=timeout)
        return sock

    monkeypatch.setattr(orpheus_kerberos.socket, "create_connection", connect)
    assert orpheus_kerberos.send_receive(b"", "realm", timeout=3.5) == b""
    assert observed == {"endpoint": ("realm", 88), "timeout": 3.5}
