# toolcall-ledger

A tamper-evident log of agent tool calls, and the reason a retried step does not send
the same email twice.

[![PyPI](https://img.shields.io/pypi/v/toolcall-ledger.svg)](https://pypi.org/project/toolcall-ledger/)
[![Python](https://img.shields.io/pypi/pyversions/toolcall-ledger.svg)](https://pypi.org/project/toolcall-ledger/)
[![tests](https://github.com/sandeshbagmare/toolcall-ledger/actions/workflows/ci.yml/badge.svg)](https://github.com/sandeshbagmare/toolcall-ledger/actions/workflows/ci.yml)
[![license](https://img.shields.io/pypi/l/toolcall-ledger.svg)](https://github.com/sandeshbagmare/toolcall-ledger/blob/main/LICENSE)

```python
>>> from toolcall_ledger import Ledger
>>> ledger = Ledger("runs/2026-11-23.jsonl")
>>> ledger.record("send_email", {"to": "a@example.com", "password": "hunter2"}, result="sent")
>>> ledger.replay("send_email", {"to": "a@example.com"})
'sent'
>>> ledger.verify()          # raises if any line was edited
```

Two failures that a trace viewer does not catch:

- **the side effect ran twice** — a node was retried, a checkpoint replayed, or the
  process died between the call and the state write;
- **the log cannot be trusted** — an argument was edited afterwards, and a secret was
  written to disk in the clear.

`toolcall-ledger` writes one JSON line per call, chains each line's SHA-256 to the
previous one, masks secret-looking argument keys before they reach the file, and derives
an idempotency key from the tool name and arguments so a repeat is recognisable.

## Install

```console
pip install toolcall-ledger
```

## Use

```python
from toolcall_ledger import Ledger

ledger = Ledger("runs/today.jsonl", max_result_chars=4000)

# record what a tool returned
ledger.record("search", {"q": "python"}, result=["a", "b"], duration=0.12)

# run a call at most once per (tool, arguments)
ledger.execute("charge_card", {"id": "cus_1", "amount": 500}, charge_card)

# ask what happened
ledger.replay("charge_card", {"amount": 500, "id": "cus_1"})   # the recorded result
ledger.find("search", {"q": "python"})                          # every matching record
ledger.records[-1]                                              # the last Record
ledger.verify()                                                 # LedgerCorrupted on tampering
```

```console
$ toolcall-ledger runs/today.jsonl
   0 send_email [ok] 0.2ms 6f2c1a3e5b0d
   1 search [ok] 120.1ms 8bf5a385c929
2 record(s), chain ok

$ toolcall-ledger runs/today.jsonl --check      # exit 1 if the chain does not verify
$ toolcall-ledger runs/today.jsonl --json --tool search
```

## What goes in a record

| field | meaning |
| ----- | ------- |
| `index` | position in the chain; a gap or a reorder is detected |
| `tool`, `arguments` | the call, with secret-looking argument values masked |
| `key` | idempotency key: `sha256(tool, canonical arguments)[:32]` |
| `ok`, `result`, `error`, `duration` | the outcome |
| `at` | Unix timestamp |
| `digest` | `sha256(previous digest, canonical record)` |

Masked by default, at any depth and case-insensitively: `password`, `passwd`, `secret`,
`token`, `api_key`, `apikey`, `authorization`, `auth`, `credential`, `private`,
`session`, `cookie`. Pass `markers=(...)` for your own.

## Rules

- The chain detects an **edit**, a **reorder** or a changed index. Removing lines from
  the end of a file is indistinguishable from a shorter run — keep the file somewhere
  append-only (a bucket with object-lock, or a store with retention) if that matters.
- `execute` treats "no earlier successful call" and "an earlier call returned `None`" the
  same way, so a tool returning `None` is not memoised. Return a small marker instead.
- Results longer than `max_result_chars` are truncated with a marker; the digests still
  cover the truncated text.
- Argument canonicalisation is JSON: dict order does not matter, a `datetime` or an
  object is stored as `repr`. Normalise exotic arguments yourself if you need stability.

## Why not just a log file

A plain JSONL log answers "what happened". This one answers "what happened, in this
order, and has anything been changed since". That is the difference between a debugging
aid and an audit trail you can hand to someone.

## Development

```console
python -m venv .venv
.venv/bin/pip install -e ".[test]"
.venv/bin/pytest
```

## License

MIT.
