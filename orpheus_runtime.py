"""Shared validation and execution primitives for Orpheus."""

from dataclasses import dataclass
from enum import IntEnum
import os
from pathlib import Path
import random
import tempfile


class ExitCode(IntEnum):
    SUCCESS = 0
    PARTIAL = 1
    INPUT_ERROR = 2
    AUTH_ERROR = 3
    NETWORK_ERROR = 4
    NO_RESULTS = 5


@dataclass
class RunSummary:
    attempted: int = 0
    succeeded: int = 0
    failed: int = 0
    skipped: int = 0

    def exit_code(self, enumeration_only: bool = False) -> ExitCode:
        if enumeration_only and self.attempted == 0:
            return ExitCode.SUCCESS
        if self.succeeded and (self.failed or self.skipped):
            return ExitCode.PARTIAL
        if self.succeeded:
            return ExitCode.SUCCESS
        return ExitCode.NO_RESULTS


def normalize_kdc_options(value: str | int) -> tuple[str, list[int]]:
    """Validate KDC options and return a canonical hex value and bit indexes."""
    if isinstance(value, str) and (not value or value.strip() != value):
        raise ValueError('KDC options must be an unsigned 32-bit integer')
    try:
        number = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError('KDC options must be an unsigned 32-bit integer') from exc
    if not 0 <= number <= 0xffffffff:
        raise ValueError('KDC options must be an unsigned 32-bit integer')
    bits = f'{number:032b}'
    return f'0x{number:08x}', [index for index, bit in enumerate(bits) if bit == '1']


def bounded_delay(sleep_seconds: int, jitter_seconds: int, rng=random) -> int:
    if sleep_seconds < 0 or jitter_seconds < 0:
        raise ValueError('sleep and jitter must be nonnegative')
    offset = rng.randint(-jitter_seconds, jitter_seconds) if jitter_seconds else 0
    return max(0, sleep_seconds + offset)


def load_usernames(path: str | Path) -> list[str]:
    values = []
    seen = set()
    with Path(path).open(encoding='utf-8') as source:
        for line in source:
            username = line.strip()
            if username and username not in seen:
                seen.add(username)
                values.append(username)
    return values


def atomic_save(save_function, destination: str | Path, overwrite: bool = False) -> None:
    destination = Path(destination)
    if destination.exists() and not overwrite:
        raise FileExistsError(f'output already exists: {destination}')
    destination.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        delete=False, dir=destination.parent,
        prefix=f'.{destination.name}.', suffix='.tmp',
    )
    temporary = Path(handle.name)
    handle.close()
    try:
        save_function(str(temporary))
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


class ResultWriter:
    """Commit result text atomically, and only after at least one write."""

    def __init__(self, destination: str | Path | None, overwrite: bool = False):
        self.destination = Path(destination) if destination else None
        self.overwrite = overwrite
        self._stream = None
        self._temporary = None
        self._wrote = False

    def __enter__(self):
        if self.destination is not None:
            if self.destination.exists() and not self.overwrite:
                raise FileExistsError(f'output already exists: {self.destination}')
            self.destination.parent.mkdir(parents=True, exist_ok=True)
            self._stream = tempfile.NamedTemporaryFile(
                mode='w', encoding='utf-8', newline='', delete=False,
                dir=self.destination.parent,
                prefix=f'.{self.destination.name}.', suffix='.tmp',
            )
            self._temporary = Path(self._stream.name)
        return self

    def write(self, value: str) -> None:
        self._wrote = True
        if self._stream is not None:
            self._stream.write(value)

    def commit(self) -> None:
        if self._stream is not None and not self._stream.closed:
            self._stream.flush()
            os.fsync(self._stream.fileno())
            self._stream.close()
        if self.destination is not None and self._wrote:
            os.replace(self._temporary, self.destination)
            self._temporary = None

    def _cleanup(self) -> None:
        if self._stream is not None and not self._stream.closed:
            self._stream.close()
        if self._temporary is not None:
            self._temporary.unlink(missing_ok=True)
            self._temporary = None

    def __exit__(self, exc_type, exc, traceback):
        try:
            if exc_type is None:
                self.commit()
        finally:
            self._cleanup()
        return False
