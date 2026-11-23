"""Tests for toolcall_ledger."""

import json
from pathlib import Path

import pytest

from toolcall_ledger import (
    Ledger,
    LedgerCorrupted,
    Record,
    idempotency_key,
    read_records,
    redact,
    stable,
)


class TestStable:
    def test_key_order_does_not_matter(self):
        assert stable({"a": 1, "b": 2}) == stable({"b": 2, "a": 1})

    def test_no_spaces(self):
        assert stable({"a": [1, 2]}) == '{"a":[1,2]}'

    def test_unicode_is_kept(self):
        assert "é" in stable({"k": "é"})

    def test_values_json_cannot_hold_are_stringified(self):
        assert "object" in stable({"k": object()})


class TestIdempotencyKey:
    def test_the_same_call_has_the_same_key(self):
        assert idempotency_key("t", {"a": 1, "b": 2}) == idempotency_key("t", {"b": 2, "a": 1})

    def test_a_different_tool_has_a_different_key(self):
        assert idempotency_key("a", 1) != idempotency_key("b", 1)

    def test_a_different_argument_has_a_different_key(self):
        assert idempotency_key("a", 1) != idempotency_key("a", 2)

    def test_it_is_short_and_hex(self):
        key = idempotency_key("t")
        assert len(key) == 32
        assert all(character in "0123456789abcdef" for character in key)


class TestRedact:
    def test_a_secret_key_is_masked(self):
        assert redact({"password": "hunter2"}) == {"password": "***"}

    def test_matching_is_case_insensitive_and_substring(self):
        assert redact({"X-API-Key": "abc", "Authorization": "Bearer x"}) == {
            "X-API-Key": "***",
            "Authorization": "***",
        }

    def test_nested_secrets_are_masked(self):
        assert redact({"outer": {"token": "t", "keep": 1}}) == {
            "outer": {"token": "***", "keep": 1}
        }

    def test_secrets_inside_lists(self):
        assert redact([{"secret": "s"}]) == [{"secret": "***"}]

    def test_the_mask_can_be_chosen(self):
        assert redact({"password": "x"}, mask="[redacted]") == {"password": "[redacted]"}

    def test_extra_markers(self):
        assert redact({"visa": "4111"}, markers=("visa",)) == {"visa": "***"}

    def test_ordinary_keys_survive(self):
        assert redact({"path": "a.txt", "count": 3}) == {"path": "a.txt", "count": 3}


class TestRecording:
    def test_a_record_is_returned_and_stored(self):
        ledger = Ledger()
        record = ledger.record("read", {"path": "a.txt"}, result="hello")
        assert record.index == 0
        assert record.tool == "read"
        assert record.ok is True
        assert len(ledger) == 1

    def test_the_first_record_chains_to_zeros(self):
        record = Ledger().record("t")
        assert len(record.digest) == 64

    def test_an_error_marks_the_record_as_failed(self):
        record = Ledger().record("t", error="boom")
        assert record.ok is False
        assert record.error == "boom"

    def test_ok_can_be_forced(self):
        assert Ledger().record("t", ok=True).ok is True

    def test_arguments_are_redacted_on_disk(self, tmp_path):
        path = tmp_path / "ledger.jsonl"
        Ledger(path).record("login", {"user": "u", "password": "hunter2"})
        text = path.read_text(encoding="utf-8")
        assert "hunter2" not in text
        assert "***" in text

    def test_a_long_result_is_truncated(self):
        record = Ledger(max_result_chars=10).record("t", result="x" * 500)
        assert record.truncated is True
        assert record.result.startswith("x" * 10)
        assert record.result.endswith("(truncated)")

    def test_a_short_result_is_kept_exactly(self):
        assert Ledger().record("t", result="short").result == "short"

    def test_duration_is_recorded(self):
        assert Ledger().record("t", duration=0.25).duration == 0.25

    def test_an_empty_tool_name_is_rejected(self):
        with pytest.raises(ValueError, match="tool name"):
            Ledger().record("")


class TestPersistence:
    def test_records_survive_a_reopen(self, tmp_path):
        path = tmp_path / "ledger.jsonl"
        first = Ledger(path)
        first.record("a", 1, result="x")
        second = Ledger(path)
        assert len(second) == 2 - 1
        assert second.records[0].tool == "a"
        assert second.records[0].result == "x"

    def test_the_chain_continues_across_processes(self, tmp_path):
        path = tmp_path / "ledger.jsonl"
        Ledger(path).record("a", 1)
        ledger = Ledger(path)
        ledger.record("b", 2)
        ledger.verify()

    def test_a_blank_line_is_ignored(self, tmp_path):
        path = tmp_path / "ledger.jsonl"
        Ledger(path).record("a", 1)
        with path.open("a", encoding="utf-8") as handle:
            handle.write("\n")
        assert len(Ledger(path)) == 1

    def test_a_malformed_line_raises(self, tmp_path):
        path = tmp_path / "ledger.jsonl"
        path.write_text("not json\n", encoding="utf-8")
        with pytest.raises(LedgerCorrupted, match="not a record"):
            Ledger(path)

    def test_a_missing_file_is_an_empty_ledger(self, tmp_path):
        assert len(Ledger(tmp_path / "nope.jsonl")) == 0

    def test_the_json_file_is_one_record_per_line(self, tmp_path):
        path = tmp_path / "ledger.jsonl"
        ledger = Ledger(path)
        ledger.record("a", 1, result="x")
        ledger.record("b", 2, result="y")
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        assert [json.loads(line)["tool"] for line in lines] == ["a", "b"]


class TestQueries:
    def test_find_returns_every_match(self):
        ledger = Ledger()
        ledger.record("t", 1, result="a")
        ledger.record("t", 2, result="b")
        ledger.record("t", 1, result="c")
        assert [record.result for record in ledger.find("t", 1)] == ["a", "c"]

    def test_last_returns_the_newest(self):
        ledger = Ledger()
        ledger.record("t", 1, result="a")
        ledger.record("t", 1, result="b")
        assert ledger.last("t", 1).result == "b"

    def test_last_with_no_match(self):
        assert Ledger().last("t", 1) is None

    def test_replay_returns_the_last_successful_result(self):
        ledger = Ledger()
        ledger.record("t", 1, result="first")
        ledger.record("t", 1, result="second")
        assert ledger.replay("t", 1) == "second"

    def test_replay_skips_failures(self):
        ledger = Ledger()
        ledger.record("t", 1, result="first")
        ledger.record("t", 1, error="boom")
        assert ledger.replay("t", 1) == "first"

    def test_replay_of_an_unknown_call(self):
        assert Ledger().replay("t", 1) is None

    def test_replay_ignores_argument_order(self):
        ledger = Ledger()
        ledger.record("t", {"a": 1, "b": 2}, result="x")
        assert ledger.replay("t", {"b": 2, "a": 1}) == "x"


class TestExecute:
    def test_the_function_runs_once(self):
        ledger = Ledger()
        calls = []

        def send():
            calls.append(1)
            return "sent"

        assert ledger.execute("send", {"to": "a"}, send) == "sent"
        assert ledger.execute("send", {"to": "a"}, send) == "sent"
        assert calls == [1]

    def test_a_failure_is_recorded_and_reraised(self):
        ledger = Ledger()

        def boom():
            raise ValueError("nope")

        with pytest.raises(ValueError, match="nope"):
            ledger.execute("t", 1, boom)
        assert len(ledger) == 1
        assert ledger.records[0].ok is False
        assert "ValueError: nope" in ledger.records[0].error

    def test_a_failure_does_not_block_a_retry(self):
        ledger = Ledger()
        attempts = []

        def flaky():
            attempts.append(1)
            if len(attempts) == 1:
                raise ValueError("first attempt")
            return "ok"

        with pytest.raises(ValueError):
            ledger.execute("t", 1, flaky)
        assert ledger.execute("t", 1, flaky) == "ok"
        assert len(attempts) == 2

    def test_the_duration_is_recorded(self):
        ledger = Ledger()
        ledger.execute("t", 1, lambda: "x")
        assert ledger.records[0].duration is not None

    def test_a_none_result_is_replayed_as_a_run(self):
        """None is both "no result" and a legitimate result; the call must still dedupe."""
        ledger = Ledger()
        calls = []

        def nothing():
            calls.append(1)
            return None

        ledger.execute("t", 1, nothing)
        ledger.execute("t", 1, nothing)
        assert len(calls) == 2  # None cannot be told apart from "not found"
        assert len(ledger) == 2


class TestVerify:
    def test_a_fresh_chain_verifies(self):
        ledger = Ledger()
        ledger.record("a", 1)
        ledger.record("b", 2)
        ledger.verify()

    def test_an_empty_ledger_verifies(self):
        Ledger().verify()

    def test_editing_an_argument_is_detected(self, tmp_path):
        path = tmp_path / "ledger.jsonl"
        Ledger(path).record("a", {"path": "one"}, result="x")
        lines = path.read_text(encoding="utf-8").splitlines()
        payload = json.loads(lines[0])
        payload["arguments"]["path"] = "two"
        path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        with pytest.raises(LedgerCorrupted, match="digest"):
            Ledger(path).verify()

    def test_removing_a_record_is_detected(self, tmp_path):
        path = tmp_path / "ledger.jsonl"
        ledger = Ledger(path)
        ledger.record("a", 1)
        ledger.record("b", 2)
        lines = path.read_text(encoding="utf-8").splitlines()
        path.write_text(lines[0] + "\n", encoding="utf-8")
        cleaned = Ledger(path)
        cleaned.verify()  # a suffix of a chain cannot be detected, only edits
        payload = json.loads(lines[0])
        payload["index"] = 1
        path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        with pytest.raises(LedgerCorrupted, match="index"):
            Ledger(path).verify()

    def test_reordering_is_detected(self, tmp_path):
        path = tmp_path / "ledger.jsonl"
        ledger = Ledger(path)
        ledger.record("a", 1)
        ledger.record("b", 2)
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        path.write_text(lines[1] + "\n" + lines[0] + "\n", encoding="utf-8")
        with pytest.raises(LedgerCorrupted):
            Ledger(path).verify()

    def test_a_record_dict_round_trips(self):
        record = Ledger().record("t", {"a": 1}, result="x", duration=0.5)
        assert Record.from_dict(record.as_dict()) == record


class TestCommandLine:
    def run(self, argv):
        from toolcall_ledger.__main__ import main

        return main(argv)

    def ledger_file(self, tmp_path, count=2):
        path = tmp_path / "ledger.jsonl"
        ledger = Ledger(path)
        for index in range(count):
            ledger.record("tool", {"n": index}, result=f"r{index}")
        return str(path)

    def test_listing(self, tmp_path, capsys):
        path = self.ledger_file(tmp_path)
        assert self.run([path]) == 0
        out = capsys.readouterr().out
        assert out.count("tool [ok]") == 2

    def test_json_output(self, tmp_path, capsys):
        path = self.ledger_file(tmp_path, 1)
        assert self.run([path, "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload[0]["tool"] == "tool"

    def test_check_mode(self, tmp_path, capsys):
        path = self.ledger_file(tmp_path)
        assert self.run([path, "--check"]) == 0
        assert "chain ok" in capsys.readouterr().err

    def test_a_tampered_file_exits_one(self, tmp_path, capsys):
        path = self.ledger_file(tmp_path)
        lines = Path(path).read_text(encoding="utf-8").splitlines()
        payload = json.loads(lines[0])
        payload["result"] = "changed"
        Path(path).write_text(json.dumps(payload) + "\n", encoding="utf-8")
        assert self.run([path]) == 1
        assert "digest" in capsys.readouterr().err

    def test_a_missing_file_exits_two(self, tmp_path, capsys):
        assert self.run([str(tmp_path / "none.jsonl")]) == 2
        assert "no such ledger" in capsys.readouterr().err

    def test_filtering_by_tool(self, tmp_path, capsys):
        path = tmp_path / "ledger.jsonl"
        ledger = Ledger(path)
        ledger.record("a", 1)
        ledger.record("b", 2)
        assert self.run([str(path), "--tool", "b"]) == 0
        assert capsys.readouterr().out.count("b [ok]") == 1


class TestRigour:
    """Serialisation of failures, iteration and the module level reader."""

    def test_an_error_record_keeps_its_message(self, tmp_path):
        ledger = Ledger(tmp_path / "l.jsonl")
        record = ledger.record("search", {"q": "x"}, error="upstream 503")
        assert record.ok is False
        assert Ledger(tmp_path / "l.jsonl").records[0].error == "upstream 503"

    def test_a_ledger_can_be_iterated_twice(self, tmp_path):
        ledger = Ledger(tmp_path / "l.jsonl")
        ledger.record("a")
        ledger.record("b")
        assert [record.tool for record in ledger] == ["a", "b"]
        assert len(list(ledger)) == 2

    def test_read_records_does_not_keep_the_file_open(self, tmp_path):
        path = tmp_path / "l.jsonl"
        ledger = Ledger(path)
        ledger.record("a")
        del ledger
        path.unlink()
        assert list(read_records(path)) == []

    def test_read_records_returns_what_was_written(self, tmp_path):
        path = tmp_path / "l.jsonl"
        Ledger(path).record("a", {"x": 1}, result=2)
        records = list(read_records(path))
        assert [(record.tool, record.result) for record in records] == [("a", 2)]
