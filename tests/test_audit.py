"""哈希链审计单测(WP-02 验收 3/4)。"""

import hashlib
import json
import random
import time

import pytest

from foam.guard import audit
from foam.guard.audit import AuditLog, llm_meta, verify


def _write_records(path, kinds_payloads):
    with AuditLog(path) as log:
        for kind, payload in kinds_payloads:
            log.append(kind, payload)


def _read_lines(path):
    return path.read_text(encoding="utf-8").splitlines()


# ---------------------------------------------------------------- 基本行为

def test_append_builds_chain(tmp_path):
    path = tmp_path / "a.jsonl"
    with AuditLog(path) as log:
        r1 = log.append(audit.KIND_SCOPE_LOADED, {"source": "lab.scope"})
        r2 = log.append(audit.KIND_EXEC_REQUEST, {"command": "nmap 127.0.0.1"})
    assert r1["seq"] == 1
    assert r1["prev_hash"] == audit.ZERO_HASH
    assert r2["seq"] == 2
    assert r2["prev_hash"] == r1["hash"]
    assert r1["hash"] != r2["hash"]
    assert verify(path)


def test_reopen_continues_sequence(tmp_path):
    path = tmp_path / "a.jsonl"
    _write_records(path, [(audit.KIND_EXEC_REQUEST, {"command": "true"})])
    with AuditLog(path) as log:
        record = log.append(audit.KIND_KILL_SWITCH, {"by": "operator"})
    assert record["seq"] == 2
    assert verify(path)


def test_all_known_kinds_roundtrip(tmp_path):
    path = tmp_path / "a.jsonl"
    _write_records(path, [(kind, {"i": i}) for i, kind in enumerate(audit.KNOWN_KINDS)])
    assert len(audit.KNOWN_KINDS) >= 7  # 规格要求的 7 种
    assert verify(path)


def test_llm_meta_records_only_hash_and_counts():
    meta = llm_meta(
        "秘密 prompt 全文", "秘密响应全文", prompt_tokens=10, response_tokens=20
    )
    expected = hashlib.sha256("秘密 prompt 全文".encode()).hexdigest()
    assert meta["prompt_sha256"] == expected
    assert meta["prompt_tokens"] == 10
    assert meta["response_tokens"] == 20
    assert "秘密" not in json.dumps(meta, ensure_ascii=False)


def test_append_flushes_immediately(tmp_path):
    path = tmp_path / "a.jsonl"
    log = AuditLog(path)
    log.append(audit.KIND_EXEC_REQUEST, {"command": "id"})
    assert len(_read_lines(path)) == 1  # 未 close 也已落盘
    log.close()


def test_corrupt_tail_refuses_append(tmp_path):
    path = tmp_path / "a.jsonl"
    _write_records(path, [(audit.KIND_EXEC_REQUEST, {"command": "id"})])
    with open(path, "a", encoding="utf-8") as fh:
        fh.write('{"seq": 2, broken\n')
    with pytest.raises(ValueError, match="拒绝续写"):
        AuditLog(path)


# ---------------------------------------------------------------- 篡改检测

@pytest.fixture()
def good_chain(tmp_path):
    path = tmp_path / "chain.jsonl"
    _write_records(
        path,
        [(audit.KIND_EXEC_REQUEST, {"command": f"cmd-{i}", "targets": []})
         for i in range(5)],
    )
    return path


def test_tamper_payload_byte(good_chain):
    lines = _read_lines(good_chain)
    lines[2] = lines[2].replace("cmd-2", "cmd-3")
    good_chain.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not verify(good_chain)
    assert audit.explain(good_chain)


def test_tamper_seq(good_chain):
    lines = _read_lines(good_chain)
    record = json.loads(lines[1])
    record["seq"] = 99
    lines[1] = json.dumps(record, sort_keys=True, ensure_ascii=False)
    good_chain.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not verify(good_chain)


def test_tamper_ts(good_chain):
    lines = _read_lines(good_chain)
    record = json.loads(lines[0])
    record["ts"] = "2001-01-01T00:00:00+00:00"
    lines[0] = json.dumps(record, sort_keys=True, ensure_ascii=False)
    good_chain.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not verify(good_chain)


def test_tamper_hash_field(good_chain):
    lines = _read_lines(good_chain)
    record = json.loads(lines[3])
    record["hash"] = "f" * 64
    lines[3] = json.dumps(record, sort_keys=True, ensure_ascii=False)
    good_chain.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not verify(good_chain)


def test_tamper_prev_hash(good_chain):
    lines = _read_lines(good_chain)
    record = json.loads(lines[1])
    record["prev_hash"] = "a" * 64
    lines[1] = json.dumps(record, sort_keys=True, ensure_ascii=False)
    good_chain.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not verify(good_chain)


def test_delete_middle_record(good_chain):
    lines = _read_lines(good_chain)
    del lines[2]
    good_chain.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not verify(good_chain)


def test_swap_two_records(good_chain):
    lines = _read_lines(good_chain)
    lines[1], lines[3] = lines[3], lines[1]
    good_chain.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not verify(good_chain)


def test_random_single_byte_mutation_always_breaks(tmp_path):
    """验收 4:随机篡改任一记录的任意字节,verify 必失败。"""
    rng = random.Random(20260820)  # noqa: S311 - 固定种子做篡改模拟,非加密用途
    for trial in range(300):
        path = tmp_path / f"r{trial}.jsonl"
        _write_records(
            path,
            [(audit.KIND_EXEC_REQUEST, {"command": f"nmap 127.0.0.{i}", "i": i})
             for i in range(rng.randint(1, 6))],
        )
        lines = _read_lines(path)
        row = rng.randrange(len(lines))
        col = rng.randrange(len(lines[row]))
        original = lines[row][col]
        replacement = rng.choice([c for c in "abzAJZ059\"{}:,. " if c != original])
        lines[row] = lines[row][:col] + replacement + lines[row][col + 1:]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        assert not verify(path), (
            f"第 {trial} 轮篡改未被检测:行 {row} 列 {col} "
            f"{original!r} -> {replacement!r}\n{lines[row]}"
        )


def test_empty_chain_verifies(tmp_path):
    path = tmp_path / "empty.jsonl"
    path.touch()
    assert verify(path)


def test_missing_file_fails(tmp_path):
    assert not verify(tmp_path / "nope.jsonl")


# ---------------------------------------------------------------- 性能

def test_append_10k_under_one_second(tmp_path):
    """验收 4:追加 1 万条 < 1s。"""
    path = tmp_path / "perf.jsonl"
    start = time.perf_counter()
    with AuditLog(path) as log:
        for i in range(10_000):
            log.append(
                audit.KIND_EXEC_RESULT_META,
                {"command": f"cmd-{i}", "exit_code": 0, "stdout_sha256": "0" * 64},
            )
    elapsed = time.perf_counter() - start
    assert len(_read_lines(path)) == 10_000
    assert verify(path)
    assert elapsed < 1.0, f"1 万条追加耗时 {elapsed:.3f}s,超过 1s 上限"
