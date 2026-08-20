"""output 层单测:落盘账目、三分流哈希、ring 有界、截断视图、分页一致性。"""

import hashlib

import pytest

from kalicode.tools.output import (
    OutputRecorder,
    RingBuffer,
    read_page,
    render_full,
    render_truncated,
    split_budget,
)

# ---------- OutputRecorder ----------


def test_recorder_three_files_and_hashes(tmp_path):
    rec = OutputRecorder(tmp_path, "job1")
    rec.feed_stdout(b"alpha\n")
    rec.feed_stderr(b"beta\n")
    rec.feed_stdout(b"gamma\n")
    manifest = rec.finalize()

    combined = b"alpha\nbeta\ngamma\n"  # 合流按到达顺序
    assert (tmp_path / "job1.log").read_bytes() == combined
    assert (tmp_path / "job1.stdout").read_bytes() == b"alpha\ngamma\n"
    assert (tmp_path / "job1.stderr").read_bytes() == b"beta\n"

    assert manifest.sha256 == hashlib.sha256(combined).hexdigest()
    assert manifest.stdout_sha256 == hashlib.sha256(b"alpha\ngamma\n").hexdigest()
    assert manifest.stderr_sha256 == hashlib.sha256(b"beta\n").hexdigest()

    assert manifest.total_bytes == len(combined)
    assert manifest.total_lines == 3
    assert manifest.stdout_bytes == len(b"alpha\ngamma\n")
    assert manifest.stderr_bytes == len(b"beta\n")
    assert manifest.output_path == tmp_path / "job1.log"

    # finalize 幂等
    assert rec.finalize() is manifest
    # finalize 后禁止再写
    with pytest.raises(RuntimeError):
        rec.feed_stdout(b"late\n")


def test_recorder_unsplit_pty_mode(tmp_path):
    rec = OutputRecorder(tmp_path, "pty1", split=False)
    rec.feed(b"banner\n")
    rec.feed(b"msf6 > ")
    manifest = rec.finalize()

    assert manifest.sha256 == hashlib.sha256(b"banner\nmsf6 > ").hexdigest()
    assert manifest.total_bytes == len(b"banner\nmsf6 > ")
    # 分流字段一律 None(PTY 单流),且不产生分流文件
    assert manifest.stdout_path is None
    assert manifest.stdout_sha256 is None
    assert manifest.stderr_path is None
    assert manifest.stderr_sha256 is None
    assert not (tmp_path / "pty1.stdout").exists()
    assert not (tmp_path / "pty1.stderr").exists()
    # split 字段标记与入口互斥
    with pytest.raises(RuntimeError):
        rec.feed_stdout(b"nope")


def test_recorder_creates_missing_directory(tmp_path):
    rec = OutputRecorder(tmp_path / "deep" / "nested", "j")
    rec.feed_stdout(b"x")
    assert rec.finalize().output_path.exists()


# ---------- RingBuffer ----------


def test_ring_buffer_bounded_and_exact_tail():
    ring = RingBuffer(64)
    data = bytes(range(256)) * 4  # 1024 字节
    ring.feed(data)
    assert len(ring) == 64
    assert ring.tail(64) == data[-64:]
    assert ring.tail(8) == data[-8:]
    assert ring.tail(0) == b""
    ring.feed(b"AB")
    assert len(ring) == 64
    assert ring.tail(2) == b"AB"


def test_ring_buffer_rejects_nonpositive_cap():
    with pytest.raises(ValueError):
        RingBuffer(0)


# ---------- split_budget / 视图渲染 ----------


def test_split_budget():
    assert split_budget(100, 1000) is None  # 不超预算不截断
    assert split_budget(1000, 1000) is None  # 恰好等于预算也不截断
    assert split_budget(1001, 1000) == (500, 500)
    assert split_budget(11, 10) == (5, 5)
    assert split_budget(10, 3) == (1, 2)  # 奇数预算:head 向下取整,tail 拿剩余
    assert split_budget(5, 0) == (0, 0)  # 零预算:全省略
    with pytest.raises(ValueError):
        split_budget(10, -1)


def test_render_full_replaces_invalid_bytes():
    assert render_full("你好\n".encode()) == "你好\n"
    text = render_full(b"\xff\xfeok")
    assert text.endswith("ok")
    assert "�" in text  # 乱码不崩,错误替换


def test_render_truncated_exact_format():
    text = render_truncated(
        b"ab",
        b"yz",
        total_bytes=10,
        total_lines=4,
        output_path="outputs/j.log",
        sha256="deadbeef",
    )
    assert text == (
        "ab\n… 省略 6 字节 / 共 4 行,完整输出已落盘 outputs/j.log "
        "(sha256:deadbeef),可用 read_output 分页读取 …\nyz"
    )


def test_render_truncated_rejects_bad_accounting():
    with pytest.raises(ValueError):
        render_truncated(
            b"12345678", b"12345678",
            total_bytes=10, total_lines=0, output_path="p", sha256="x",
        )


# ---------- read_page ----------


def test_read_page_reassembles_file(tmp_path):
    path = tmp_path / "out.log"
    expected = "".join(f"line-{i}\n" for i in range(1, 2001)).encode()
    path.write_bytes(expected)

    chunks, offset = [], 0
    while True:
        page = read_page(path, offset, 997)  # 故意用奇数页长
        chunks.append(page.text)
        assert page.total_bytes == len(expected)
        offset += page.bytes_read
        if not page.has_more:
            break
    assert "".join(chunks) == expected.decode()

    tail = read_page(path, len(expected) + 100, 10)  # 越过 EOF
    assert tail.bytes_read == 0 and tail.text == "" and not tail.has_more


def test_read_page_binary_no_crash(tmp_path):
    path = tmp_path / "bin.log"
    path.write_bytes(bytes(range(256)))
    page = read_page(path, 100, 50)
    assert page.bytes_read == 50
    assert page.has_more
    assert isinstance(page.text, str)  # 含替换字符,不抛异常


def test_read_page_rejects_bad_args(tmp_path):
    path = tmp_path / "x.log"
    path.write_bytes(b"x")
    with pytest.raises(ValueError):
        read_page(path, -1, 10)
    with pytest.raises(ValueError):
        read_page(path, 0, 0)
