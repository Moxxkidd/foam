"""WP-14d 拒答观测测试(总纲定案 Q7,验收 10)。

- 词表命中:中英各 ≥2 例,断言 detect 返回的具体模式串(按词表顺序);
- 零误报样例锁定:合法渗透叙述一律返回 [](优先于任何举例清单);
- fake loop:命中轮链上恰一条 refusal_detected,payload 仅
  round/text_sha256/patterns 无全文;行为零变更(无重试、无纠正回灌、
  状态机不动、轮数与消息序列同无检测时一致);
- reasoning 通道(ReasoningDelta)与空正文轮不触发;
- 本片链上 refusal_detected 未注册 KNOWN_KINDS(注册归 14a,契约 2):
  append/verify 不校验 kind,哈希链照常 verify,零风险。
"""

from __future__ import annotations

import hashlib
import json

import pytest

from foam.agent.backends.base import ReasoningDelta, TextDelta, ToolCall, Usage
from foam.agent.refusal import KIND_REFUSAL_DETECTED, REFUSAL_PATTERNS, detect
from foam.guard.audit import verify
from tests.test_loop import FakeBackend, audit_kinds, audit_records, make_loop


def test_patterns_are_normalized_form():
    """词表条目本身即规范化形态(小写、直引号),与 detect 的规范化口径一致。"""
    for pattern in REFUSAL_PATTERNS:
        assert pattern == pattern.lower()
        assert "’" not in pattern
    assert len(REFUSAL_PATTERNS) == len(set(REFUSAL_PATTERNS))


def test_detect_chinese_hits():
    assert detect("抱歉,我无法协助进行这次攻击") == ["无法协助"]
    assert detect("这个目标涉及内网穿透,我不能协助完成。") == ["不能协助"]
    # 按词表顺序返回(非文本出现顺序):「我无法执行」先出现于文本,
    # 但词表中「无法协助」靠前。
    assert detect("我无法执行该命令,也无法协助后续操作。") == ["无法协助", "我无法执行"]


def test_detect_english_hits():
    assert detect("I'm sorry, I can't assist with that.") == ["i can't assist"]
    assert detect("I cannot help with this request.") == ["i cannot help"]
    # 子串重叠的既定行为(纯子串匹配,不分词):两模式都命中,按词表顺序。
    assert detect("I cannot assist with that.") == ["i cannot assist", "cannot assist"]


def test_detect_normalization_case_and_curly_quote():
    """规范化:大写小写化 + U+2019 弯引号归一直引号。"""
    assert detect("I CAN'T ASSIST with that") == ["i can't assist"]
    assert detect("I can’t assist with that") == ["i can't assist"]  # U+2019
    assert detect("I CANNOT COMPLY.") == ["i cannot comply"]


def test_detect_clean_and_empty():
    assert detect("") == []
    assert detect("目标 80 端口开放,准备尝试已知 exploit 拿立足点。") == []


@pytest.mark.parametrize(
    "text",
    [
        "我不能确定该版本是否受影响",
        "我无法确定目标是否存活",
        "该服务对畸形包无法处理",
        "I cannot say whether this version is affected",
        "The scanner cannot identify the OS",
    ],
)
def test_detect_no_false_positives_on_legit_narration(text):
    """零误报样例锁定(验收 10):合法渗透叙述一律返回 []。"""
    assert detect(text) == []


async def test_loop_refusal_observed_payload_and_behavior_unchanged(tmp_path):
    """命中轮:链上恰一条 refusal_detected,payload 三键无全文,行为零变更。"""
    refusal_text = "抱歉,我无法协助进行这次攻击。"
    hit_dir = tmp_path / "hit"
    hit_dir.mkdir()
    env = make_loop(hit_dir, [[TextDelta(refusal_text), Usage(10, 5)]])
    assert isinstance(env.backend, FakeBackend)  # 脚本化后端夹具(复用 test_loop)

    result = await env.loop.run("对 127.0.0.1 做侦察")

    # 行为零变更:正常 finish,轮数/摘要照旧
    assert result.status == "finished"
    assert result.rounds == 1
    assert result.summary == refusal_text

    kinds = audit_kinds(env)
    refusal_records = [
        r for r in audit_records(env) if r["kind"] == KIND_REFUSAL_DETECTED
    ]
    assert len(refusal_records) == 1
    payload = refusal_records[0]["payload"]
    # payload 键恰为 {round, text_sha256, patterns}(14a 的 audit_stats 只消费
    # 这三键,勿指望其他键——一致性请求 1)
    assert set(payload) == {"round", "text_sha256", "patterns"}
    assert payload["round"] == 1
    assert payload["text_sha256"] == hashlib.sha256(
        refusal_text.encode("utf-8")
    ).hexdigest()
    assert payload["patterns"] == ["无法协助"]
    # 无全文(与 llm_meta 同口径:哈希+模式)
    assert refusal_text not in json.dumps(refusal_records[0], ensure_ascii=False)
    # 无重试、无纠正回灌;观测记录紧随本轮 llm_exchange_meta
    assert "loop_correction" not in kinds
    assert "llm_retry" not in kinds
    assert kinds.index(KIND_REFUSAL_DETECTED) == kinds.index("llm_exchange_meta") + 1
    # 未注册 kind 零风险(契约 2):append/verify 不校验 kind
    assert verify(env.audit_path)

    # 对照组(同脚本、干净正文):轮数与消息角色序列一致,审计仅少一条观测记录
    clean_dir = tmp_path / "clean"
    clean_dir.mkdir()
    clean_env = make_loop(
        clean_dir, [[TextDelta("收到,开始侦察 127.0.0.1。"), Usage(10, 5)]]
    )
    clean_result = await clean_env.loop.run("对 127.0.0.1 做侦察")
    assert clean_result.status == "finished"
    assert clean_result.rounds == result.rounds
    assert [m.role for m in clean_env.loop.messages] == [
        m.role for m in env.loop.messages
    ]
    assert audit_kinds(clean_env) == [k for k in kinds if k != KIND_REFUSAL_DETECTED]


async def test_loop_reasoning_channel_and_empty_text_not_detected(tmp_path):
    """reasoning 通道(ReasoningDelta)不进检测面;纯工具调用轮(正文空)不触发。"""
    env = make_loop(
        tmp_path,
        [
            [
                ReasoningDelta("我无法协助——但这只是思考通道,不在检测面(Q7)。"),
                ToolCall("tc-1", "run_command", {"command": "echo recon 127.0.0.1"}),
                Usage(10, 5),
            ],
            [TextDelta("侦察完成,无进一步动作。"), Usage(10, 5)],
        ],
    )
    result = await env.loop.run("侦察 127.0.0.1")

    assert result.status == "finished"
    assert result.rounds == 2
    assert KIND_REFUSAL_DETECTED not in audit_kinds(env)
    # 非空断言:思考确实到达过审计面(只记哈希),排除测试 vacuous
    meta = [r for r in audit_records(env) if r["kind"] == "llm_exchange_meta"]
    assert "reasoning_sha256" in meta[0]["payload"]
    assert verify(env.audit_path)
