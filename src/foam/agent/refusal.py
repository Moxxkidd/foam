"""拒答观测(WP-14d,总纲定案 Q7):主环 assistant 正文的拒答意图短语检测。

纯观测,零行为改动:命中只落 ``refusal_detected`` 审计(payload 仅
round/text_sha256/patterns,与 ``llm_meta`` 同口径不记全文),不纠正、不重试、
不回灌——v0 目标是拿基线数据指导授权段措辞迭代,数据之前不挂反馈环(Q7)。

词表纪律:

- 以拒答意图短语为单位(非单字词):「我不能」一类裸词会误报「我不能确定该版本
  是否受影响」这类合法渗透叙述,故一律带动作对象(零误报样例见
  tests/test_refusal.py,优先于任何举例清单);
- 纯子串匹配,不分词、不正则(T3 精简);匹配前规范化:text 小写化 +
  U+2019 弯引号归一为直引号;
- 已知限制:中文标点变体不归一(全角/半角差异不处理),词表迭代时以观测数据
  为准;后续迭代只动 ``REFUSAL_PATTERNS`` 一处(Q7)。

检测面钉死在 ``AgentLoop._collect_round`` 尾部:只测 assistant 正文 text,
reasoning 通道(ReasoningDelta)与 operator 文本不进检测面(Q7)。
"""

from __future__ import annotations

#: 审计 kind 字面量(全局契约 2,与 WP-14a ``KNOWN_KINDS`` 注册同字面量;
#: 注册归 14a,本片只使用不注册——append/verify 不校验 kind,未注册零风险)。
KIND_REFUSAL_DETECTED = "refusal_detected"

#: 拒答意图短语词表(命中后原样进审计 payload 的 ``patterns`` 键;
#: 后续迭代只动这一处,定案 Q7)。英文条目均为规范化后形态(小写 + 直引号)。
REFUSAL_PATTERNS: tuple[str, ...] = (
    # 中文
    "无法协助",
    "不能协助",
    "我无法执行",
    "我不能执行",
    "我无法提供",
    "我不能提供",
    "无法帮助你",
    "不能帮助你",
    "我拒绝执行",
    # 英文
    "i can't assist",
    "i cannot assist",
    "cannot assist",
    "i can't help",
    "i cannot help",
    "i'm unable to assist",
    "i am unable to assist",
    "i can't comply",
    "i cannot comply",
)


def detect(text: str) -> list[str]:
    """返回 ``text`` 命中的拒答模式串列表(按词表顺序,空列表=未命中)。

    规范化:text 小写化 + U+2019 弯引号归一为直引号;纯子串匹配,不分词、
    不正则(T3 精简)。
    """
    normalized = text.lower().replace("’", "'")
    return [pattern for pattern in REFUSAL_PATTERNS if pattern in normalized]
