"""An append-only, tamper-evident log of agent tool calls, with idempotent replay.

Two things go wrong in a long agent run and neither is visible in the transcript:

1. A tool with a side effect runs twice, because a step was retried, a checkpoint was
   replayed or the process died after the call and before the state was saved.
2. Nobody can say afterwards which arguments were passed to which tool, in what order,
   and whether a secret leaked into the log.

A ledger answers both: every record is hash-chained to the previous one, so editing the
file is detectable, and every record carries an idempotency key derived from the tool
name and its arguments, so a repeat is recognisable before it runs.

    >>> from toolcall_ledger import Ledger
    >>> ledger = Ledger(":memory:")
    >>> first = ledger.record("send_email", {"to": "a@example.com"}, result="sent")
    >>> ledger.replay("send_email", {"to": "a@example.com"})
    'sent'
    >>> ledger.verify()

Standard library only, Python 3.9+.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "Ledger",
    "LedgerCorrupted",
    "Record",
    "idempotency_key",
    "read_records",
    "redact",
    "stable",
]

__version__ = "0.1.1"

DEFAULT_SECRET_MARKERS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "auth",
    "credential",
    "private",
    "session",
    "cookie",
)
MASK = "***"
MAX_RESULT_CHARS = 2000


def stable(value: Any) -> str:
    """A canonical JSON string: sorted keys, no whitespace, non-JSON values stringified."""
    return json.dumps(_plain(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _plain(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


def idempotency_key(tool: str, arguments: Any = None) -> str:
    """The key that makes two identical calls the same call."""
    return hashlib.sha256(f"{tool}\0{stable(arguments)}".encode()).hexdigest()[:32]


def redact(
    value: Any,
    *,
    markers: Sequence[str] = DEFAULT_SECRET_MARKERS,
    mask: str = MASK,
) -> Any:
    """Replace the values of secret-looking keys, at any depth."""
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            name = str(key).lower().replace("-", "_").replace(" ", "_")
            if any(marker in name for marker in markers):
                redacted[str(key)] = mask
            else:
                redacted[str(key)] = redact(item, markers=markers, mask=mask)
        return redacted
    if isinstance(value, (list, tuple)):
        return [redact(item, markers=markers, mask=mask) for item in value]
    return value


@dataclass(frozen=True)
class Record:
    """One tool call, as written to the ledger."""

    index: int
    tool: str
    arguments: Any
    key: str
    digest: str
    at: float
    ok: bool | None = None
    result: Any = None
    truncated: bool = False
    error: str | None = None
    duration: float | None = None

    def as_dict(self) -> dict[str, Any]:
        """The JSON form that is written to the file."""
        payload = {
            "index": self.index,
            "tool": self.tool,
            "arguments": self.arguments,
            "key": self.key,
            "at": self.at,
            "ok": self.ok,
            "result": self.result,
            "truncated": self.truncated,
            "digest": self.digest,
        }
        if self.error is not None:
            payload["error"] = self.error
        if self.duration is not None:
            payload["duration"] = self.duration
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> Record:
        return cls(
            index=int(payload["index"]),
            tool=str(payload["tool"]),
            arguments=payload.get("arguments"),
            key=str(payload["key"]),
            digest=str(payload["digest"]),
            at=float(payload["at"]),
            ok=payload.get("ok"),
            result=payload.get("result"),
            truncated=bool(payload.get("truncated", False)),
            error=payload.get("error"),
            duration=payload.get("duration"),
        )


class LedgerCorrupted(RuntimeError):
    """The chain does not verify: a record was edited, removed or reordered."""


def _chain(previous: str, payload: dict[str, Any]) -> str:
    body = {key: value for key, value in payload.items() if key != "digest"}
    return hashlib.sha256(f"{previous}\0{stable(body)}".encode()).hexdigest()


@dataclass
class Ledger:
    """A ledger file, or an in-memory one when ``path`` is ``":memory:"``.

    The first record chains to 64 zeros, so a truncated file is detectable too.
    """

    path: Path | str = ":memory:"
    markers: Sequence[str] = DEFAULT_SECRET_MARKERS
    max_result_chars: int = MAX_RESULT_CHARS
    mask: str = MASK
    _records: list[Record] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        self.path = Path(self.path) if self.path != ":memory:" else ":memory:"
        self._records = self._load()

    # -- writing ---------------------------------------------------------

    def record(
        self,
        tool: str,
        arguments: Any = None,
        *,
        result: Any = None,
        error: str | None = None,
        ok: bool | None = None,
        duration: float | None = None,
    ) -> Record:
        """Append a call and return the record that was written."""
        if not tool:
            raise ValueError("tool name must not be empty")
        stored_result, truncated = self._shrink(result)
        payload: dict[str, Any] = {
            "index": len(self._records),
            "tool": tool,
            "arguments": redact(arguments, markers=self.markers, mask=self.mask),
            "key": idempotency_key(tool, arguments),
            "at": time.time(),
            "ok": ok if ok is not None else error is None,
            "result": stored_result,
            "truncated": truncated,
        }
        if error is not None:
            payload["error"] = error
        if duration is not None:
            payload["duration"] = duration
        payload["digest"] = _chain(self._previous_digest(), payload)
        record = Record.from_dict(payload)
        self._records.append(record)
        self._append(record)
        return record

    def execute(self, tool: str, arguments: Any, function: Any) -> Any:
        """Run ``function`` once; a successful identical call earlier is replayed instead.

        The replay is what makes a retried agent step safe: the side effect happened, so
        returning the recorded result is the correct answer the second time.
        """
        previous = self.replay(tool, arguments)
        if previous is not None:
            return previous
        started = time.perf_counter()
        try:
            result = function()
        except Exception as error:
            self.record(
                tool,
                arguments,
                error=f"{type(error).__name__}: {error}",
                ok=False,
                duration=round(time.perf_counter() - started, 6),
            )
            raise
        self.record(
            tool,
            arguments,
            result=result,
            ok=True,
            duration=round(time.perf_counter() - started, 6),
        )
        return result

    # -- reading ---------------------------------------------------------

    def __len__(self) -> int:
        return len(self._records)

    def __iter__(self) -> Iterator[Record]:
        return iter(list(self._records))

    @property
    def records(self) -> list[Record]:
        """Every record, oldest first."""
        return list(self._records)

    def find(self, tool: str, arguments: Any = None) -> list[Record]:
        """Every record for the same tool and arguments."""
        key = idempotency_key(tool, arguments)
        return [record for record in self._records if record.key == key]

    def last(self, tool: str, arguments: Any = None) -> Record | None:
        """The most recent record for the same tool and arguments."""
        matches = self.find(tool, arguments)
        return matches[-1] if matches else None

    def replay(self, tool: str, arguments: Any = None) -> Any:
        """The result of the last successful identical call, or ``None``."""
        for record in reversed(self.find(tool, arguments)):
            if record.ok:
                return record.result
        return None

    def verify(self) -> None:
        """Recompute the chain and raise :class:`LedgerCorrupted` on any mismatch."""
        previous = "0" * 64
        for position, record in enumerate(self._records):
            if record.index != position:
                raise LedgerCorrupted(f"record {position} has index {record.index}")
            expected = _chain(previous, record.as_dict())
            if expected != record.digest:
                raise LedgerCorrupted(
                    f"record {position} ({record.tool}) does not match its digest"
                )
            previous = record.digest

    # -- internals -------------------------------------------------------

    def _previous_digest(self) -> str:
        return self._records[-1].digest if self._records else "0" * 64

    def _shrink(self, result: Any) -> tuple[Any, bool]:
        if result is None:
            return None, False
        text = result if isinstance(result, str) else stable(result)
        if len(text) <= self.max_result_chars:
            return result, False
        return text[: self.max_result_chars] + "… (truncated)", True

    def _load(self) -> list[Record]:
        if self.path == ":memory:" or not Path(self.path).exists():
            return []
        records: list[Record] = []
        with Path(self.path).open(encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    records.append(Record.from_dict(json.loads(line)))
                except (json.JSONDecodeError, KeyError) as error:
                    raise LedgerCorrupted(f"line {number} is not a record: {error}") from None
        return records

    def _append(self, record: Record) -> None:
        if self.path == ":memory:":
            return
        with Path(self.path).open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(record.as_dict(), ensure_ascii=False, sort_keys=True) + "\n")


def read_records(path: str | Path) -> Iterable[Record]:
    """Read a ledger file without keeping it open."""
    return Ledger(path).records
