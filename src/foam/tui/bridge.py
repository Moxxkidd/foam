"""loop 事件 → TUI 消息的桥(WP-09)。

:class:`TuiObserver` 实现 :class:`~foam.agent.loop.LoopObserver` 全部钩子,
把事件翻译成 textual :class:`Message` 投递给主界面;渲染状态全部由主界面
按消息到达顺序归约(observer 无渲染状态,可单测、可替换)。

线程模型:observer 各钩子由 loop 任务在 textual 事件循环线程内同步调用;
``post_message`` 本身线程安全,跨线程调用亦合法。

消息与钩子的对应(命名即契约,fake loop 契约测试直接投递这些消息):

- ``on_status`` → :class:`StatusMsg`(running/paused/killed/finished/error)
- ``on_text_delta`` → :class:`NarrativeMsg`(正文增量)
- ``on_reasoning_delta`` → :class:`ThinkingMsg`(思考增量,折叠块)
- ``on_tool_call`` → :class:`ToolCallMsg`(开卡)
- ``on_guard`` → :class:`GuardMsg`(护栏判定;拒绝触发卡片自动展开)
- ``on_tool_result`` → :class:`ToolResultMsg`(收卡)
- ``on_correction`` → :class:`CorrectionMsg`(主环纠正,警告块)
- ``on_retry`` → :class:`RetryMsg`(后端重试,警告块)
- ``on_compressed`` → :class:`CompressedMsg`(context 压缩留痕)
- ``on_phase`` → :class:`PhaseMsg`(阶段分隔条 + 侧栏)
"""

from __future__ import annotations

import json
from typing import Any

from textual.message import Message
from textual.message_pump import MessagePump

from foam.agent.backends.base import ToolCall
from foam.agent.loop import LoopObserver
from foam.guard.scope import GuardDecision


class StatusMsg(Message):
    """loop 状态变化:running / paused / killed / finished / error。"""

    def __init__(self, status: str) -> None:
        super().__init__()
        self.status = status


class NarrativeMsg(Message):
    """模型正文增量。"""

    def __init__(self, text: str) -> None:
        super().__init__()
        self.text = text


class ThinkingMsg(Message):
    """模型思考增量(ReasoningDelta;折叠思考块,审计只记哈希)。"""

    def __init__(self, text: str) -> None:
        super().__init__()
        self.text = text


class ToolCallMsg(Message):
    """工具调用开始(开一张工具卡);``arguments`` 为已解析的合法 dict。"""

    def __init__(self, name: str, arguments: dict[str, Any]) -> None:
        super().__init__()
        self.name = name
        self.arguments = arguments


class GuardMsg(Message):
    """scope 护栏对一条 run_command 的判定(仅 run_command 触发)。"""

    def __init__(
        self,
        *,
        allowed: bool,
        targets: list[str],
        violations: list[str],
        reason: str,
    ) -> None:
        super().__init__()
        self.allowed = allowed
        self.targets = targets
        self.violations = violations
        self.reason = reason


class ToolResultMsg(Message):
    """工具结果(收卡);``result`` 为工具返回的原始 dict。"""

    def __init__(self, name: str, result: dict[str, Any]) -> None:
        super().__init__()
        self.name = name
        self.result = result


class CorrectionMsg(Message):
    """主环自动纠正(幻觉执行/非法 JSON 回灌);警告块,始终展开。"""

    def __init__(self, reason: str) -> None:
        super().__init__()
        self.reason = reason


class RetryMsg(Message):
    """后端可重试错误(网络/超时/限流/5xx)的第 N 次重试。"""

    def __init__(self, attempt: int, error: str) -> None:
        super().__init__()
        self.attempt = attempt
        self.error = error


class CompressedMsg(Message):
    """context 压缩事件(两阶段压缩的账目 dict,见 loop._maybe_compress)。"""

    def __init__(self, info: dict[str, Any]) -> None:
        super().__init__()
        self.info = info


class PhaseMsg(Message):
    """当前阶段变化(来自 ENGAGEMENT.md 阶段字段,变化时恰一次)。"""

    def __init__(self, phase: str) -> None:
        super().__init__()
        self.phase = phase


def tool_call_display(name: str, arguments: dict[str, Any]) -> str:
    """工具卡的一行展示:run_command 显示命令本体,其余工具显示紧凑参数。

    全文不进卡片头部(防长命令撑破排版);完整内容在展开体/落盘文件里。
    """
    if name == "run_command":
        command = str(arguments.get("command", "")).strip()
        first_line = command.splitlines()[0] if command else "(空命令)"
        if len(command) > len(first_line):
            first_line += " …"
        return first_line
    args = json.dumps(arguments, ensure_ascii=False)
    if len(args) > 96:
        args = args[:96] + "…"
    return f"{name} {args}"


class TuiObserver(LoopObserver):
    """把 loop 钩子翻译成 textual 消息,投给目标(主界面)。"""

    def __init__(self, target: MessagePump) -> None:
        self._target = target

    def on_status(self, status: str) -> None:
        self._target.post_message(StatusMsg(status))

    def on_text_delta(self, text: str) -> None:
        self._target.post_message(NarrativeMsg(text))

    def on_reasoning_delta(self, text: str) -> None:
        self._target.post_message(ThinkingMsg(text))

    def on_tool_call(self, call: ToolCall) -> None:
        self._target.post_message(ToolCallMsg(call.name, dict(call.arguments)))

    def on_guard(self, decision: GuardDecision) -> None:
        self._target.post_message(
            GuardMsg(
                allowed=decision.allowed,
                targets=list(decision.targets),
                violations=list(decision.violations),
                reason=decision.reason,
            )
        )

    def on_tool_result(self, name: str, result: dict[str, Any]) -> None:
        self._target.post_message(ToolResultMsg(name, result))

    def on_correction(self, reason: str) -> None:
        self._target.post_message(CorrectionMsg(reason))

    def on_retry(self, attempt: int, error: str) -> None:
        self._target.post_message(RetryMsg(attempt, error))

    def on_compressed(self, info: dict[str, Any]) -> None:
        self._target.post_message(CompressedMsg(info))

    def on_phase(self, phase: str) -> None:
        self._target.post_message(PhaseMsg(phase))
