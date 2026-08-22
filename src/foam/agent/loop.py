"""agent 主环(WP-04):把 exec 层(WP-01)、护栏/审计(WP-02)、后端(WP-03)
拼成能跑的 agent。

结构速览:

- :class:`ToolRegistry`——可追加的工具注册表(WP-05 会话工具、WP-06 状态工具
  在本 WP 之后注册);未知工具名/非法参数回 error dict 给模型自我纠正,不炸环。
- :class:`AgentLoop`——消息状态机:user(objective)→ assistant(tool_call)→
  tool 结果 → …… 直到 assistant 无 tool_call(finish)。每个 run_command 先过
  scope 护栏,拒绝结果作为 tool 结果回给 LLM;全程写哈希链审计。
- context 预算:字符数/4 粗估;超限先压旧 tool 结果(占位含落盘路径+sha256),
  再压旧对话;system 与 ENGAGEMENT.md 消息永不压缩,objective 永不压缩。
- 操作员面:插话队列(turn 边界注入)、pause/resume(turn 边界)、kill(立即
  cancel 当前 turn + 杀全部活动 job)。
- 消化 WP-03 对 Kimi K3 的实测发现(见各常量注释):幻觉执行纠正、
  MalformedToolCallError 回灌、首事件超时默认 30s(K3 实测 max 16.24s)。

审计事件:复用 WP-02 的 scope_loaded/exec_request/exec_denied/exec_result_meta/
llm_exchange_meta/operator_interject/kill_switch;本 WP 新增 run_started/
run_finished/loop_correction/llm_retry/context_compressed(WP-02 明示允许后续
WP 扩展新 kind)。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from collections import deque
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from foam.agent.backends.base import (
    BackendError,
    LLMBackend,
    MalformedToolCallError,
    Message,
    RequestTimeoutError,
    TextDelta,
    ToolCall,
    ToolSpec,
    Usage,
)
from foam.agent.prompts import (
    ENGAGEMENT_FILENAME,
    build_engagement_message,
    render_engagement_template,
)
from foam.guard.audit import (
    KIND_EXEC_RESULT_META,
    KIND_KILL_SWITCH,
    KIND_LLM_EXCHANGE_META,
    KIND_OPERATOR_INTERJECT,
    AuditLog,
    llm_meta,
)
from foam.guard.scope import GuardDecision, Scope, check_command
from foam.tools.bash import TOOL_SCHEMAS, BashTool

# ---------------------------------------------------------------------------
# 常量(设计依据见注释)
# ---------------------------------------------------------------------------

#: 等 LLM 首事件的默认超时。WP-03 实测 Kimi K3 首事件延迟 max 16.24s(长思考),
#: 故默认 30s;不得沿用常见的 10s 默认值。
FIRST_EVENT_TIMEOUT_SECONDS = 30.0
#: context 预算默认值(token,字符数/4 粗估)。保守取 120k,给主流长上下文
#: 模型留足余量;CLI 可调。
DEFAULT_MAX_CONTEXT_TOKENS = 120_000
#: 压缩时保留的最近消息条数(不参与压缩的尾部窗口)。
DEFAULT_KEEP_RECENT_MESSAGES = 6
#: 可重试后端错误(网络/超时/限流/5xx)的最大重试次数。
DEFAULT_MAX_RETRIES = 3
#: 单条 tool 结果的字符上限(防模型用 read_output 一页拉回整文件灌爆上下文)。
MAX_TOOL_RESULT_CHARS = 200_000
#: 连续 MalformedToolCall 回灌纠正的上限,超过判定模型无法自愈,结束 run。
MAX_CONSECUTIVE_MALFORMED = 3
#: 连续「幻觉执行」纠正的上限,超过接受 finish(防止纠正死循环)。
MAX_CONSECUTIVE_CLAIM_CORRECTIONS = 2
#: 回灌给模型的坏 JSON 原文摘录上限。
_RAW_ARGS_ECHO_LIMIT = 4_000

#: 本 WP 新增的审计事件类型(WP-02 的 KNOWN_KINDS 明示允许扩展)。
KIND_RUN_STARTED = "run_started"
KIND_RUN_FINISHED = "run_finished"
KIND_LOOP_CORRECTION = "loop_correction"
KIND_LLM_RETRY = "llm_retry"
KIND_CONTEXT_COMPRESSED = "context_compressed"

#: 幻觉执行(K3 实测 A4:声称「已记录」却不发 tool_call)的动作声明特征。
#: 宁宽勿严:误报只多一轮纠正(有上限),漏报会污染 engagement 记录。
_ACTION_CLAIM_RE = re.compile(
    r"已(?:经)?(?:执行|运行|跑完|完成|扫描|探测|记录|保存|写入|写出|创建|启动|"
    r"获取|读取|下载|上传|收集|生成|部署)"
    r"|(?:执行|运行|扫描|记录|保存|写入|启动)(?:完毕|完成|好了)"
    r"|(?i:\b(?:executed|ran|scanned|saved|recorded|written|launched|created|"
    r"downloaded|uploaded|generated)\b)"
)

_CLAIM_CORRECTION_TEXT = (
    "【主环自动纠正】你上一条回复声称执行了动作,但本轮没有检测到任何工具调用 "
    "tool_call。在本环境中只有真正发出工具调用才会产生动作,纯文本描述不算执行。"
    "如需执行命令/读取输出/管理 job,请现在发出对应的工具调用;如任务确已全部"
    "完成,请直接给出最终结论,不要声称执行了未实际发出的动作。"
)

_COMPRESSED_TOOL_GENERIC = "[已压缩] 旧工具结果已移除以释放上下文(该结果无落盘路径)。"
_COMPRESSED_ASSISTANT = "[已压缩] 历史助手消息文本已省略。"
_COMPRESSED_USER = "[已压缩] 历史用户消息文本已省略。"

#: 常见信号名(POSIX 标准编号,不查 signal 模块以保持跨平台输出一致)。
_SIGNAL_NAMES = {
    1: "SIGHUP",
    2: "SIGINT",
    3: "SIGQUIT",
    4: "SIGILL",
    6: "SIGABRT",
    8: "SIGFPE",
    9: "SIGKILL",
    11: "SIGSEGV",
    13: "SIGPIPE",
    14: "SIGALRM",
    15: "SIGTERM",
}


def describe_exit_code(exit_code: Any) -> str | None:
    """把负数 exit_code(信号退出)翻译为人类可读说明;非信号退出返回 None。"""
    if not isinstance(exit_code, int) or exit_code >= 0:
        return None
    signum = -exit_code
    name = _SIGNAL_NAMES.get(signum)
    if name is None:
        return f"进程被信号 {signum} 终止(非常见信号,请查 kill -l)。"
    note = f"进程被 {name}(信号 {signum})终止"
    if signum == 9:
        note += ":常见于 kill_job、timeout 整组强杀,或系统 OOM killer。"
    elif signum == 15:
        note += ":常见于外部发来的优雅终止请求。"
    elif signum == 13:
        note += ":向已关闭的管道写入(常与 head/grep 截断联用,通常无害)。"
    elif signum == 11:
        note += ":段错误,目标程序自身崩溃。"
    elif signum == 2:
        note += ":键盘中断。"
    return note


def estimate_tokens(messages: Sequence[Message]) -> int:
    """字符数/4 粗估(规格认可的中文偏乐观估计,压缩阈值据此留余量)。"""
    chars = 0
    for message in messages:
        chars += len(message.content)
        for call in message.tool_calls:
            chars += len(call.name) + len(
                json.dumps(call.arguments, ensure_ascii=False)
            )
    return chars // 4


def message_to_dict(message: Message) -> dict[str, Any]:
    """消息的 provider 中立可序列化形式(审计哈希输入,replay 比对基准)。"""
    data: dict[str, Any] = {"role": message.role, "content": message.content}
    if message.tool_calls:
        data["tool_calls"] = [
            {"id": c.id, "name": c.name, "arguments": c.arguments}
            for c in message.tool_calls
        ]
    if message.tool_call_id is not None:
        data["tool_call_id"] = message.tool_call_id
    return data


# ---------------------------------------------------------------------------
# 工具注册表(可追加)
# ---------------------------------------------------------------------------

SingleDispatch = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]
ModuleDispatch = Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]]


class ToolRegistry:
    """工具注册表:schema + 分发函数;设计为可追加(WP-05/06 后续注册)。

    两种注册姿势:
    - ``register_module(TOOL_SCHEMAS, bash.dispatch)``:整组注册一个模块
      (WP-01 的形状,WP-06 同构);
    - ``register(schema, handler)``:单个工具(测试/小工具用)。

    模型发来的未知工具名、非法参数(TypeError/ValueError)一律回 error dict
    作为 tool 结果,让模型自我纠正——不抛异常炸环。
    """

    def __init__(self) -> None:
        self._handlers: dict[str, SingleDispatch] = {}
        self._schemas: dict[str, dict[str, Any]] = {}

    def register(self, schema: dict[str, Any], handler: SingleDispatch) -> None:
        name = schema.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError("工具 schema 必须有非空 name")
        if name in self._handlers:
            raise ValueError(f"工具 {name!r} 已注册,拒绝覆盖")
        self._schemas[name] = schema
        self._handlers[name] = handler

    def register_module(
        self, schemas: Sequence[dict[str, Any]], dispatch: ModuleDispatch
    ) -> None:
        for schema in schemas:
            name = schema["name"]

            async def _handler(
                arguments: dict[str, Any], _name: str = name
            ) -> dict[str, Any]:
                return await dispatch(_name, arguments)

            self.register(schema, _handler)

    def specs(self) -> list[ToolSpec]:
        return [
            ToolSpec(
                name=s["name"],
                description=s.get("description", ""),
                parameters=s.get("parameters", {"type": "object", "properties": {}}),
            )
            for s in self._schemas.values()
        ]

    def names(self) -> list[str]:
        return sorted(self._handlers)

    async def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        handler = self._handlers.get(name)
        if handler is None:
            return {
                "error": f"未知工具 {name!r}(已注册: {self.names()});请改用已注册工具。"
            }
        try:
            return await handler(arguments)
        except (TypeError, ValueError) as exc:
            return {"error": f"工具 {name!r} 参数非法: {exc};请按 schema 重发。"}


# ---------------------------------------------------------------------------
# 观察者(CLI/TUI 渲染钩子;全部默认空实现)
# ---------------------------------------------------------------------------


class LoopObserver:
    """主环事件钩子。CLI 打印、WP-09 TUI 渲染都实现本接口。"""

    def on_status(self, status: str) -> None:  # running/paused/killed/finished/error
        pass

    def on_text_delta(self, text: str) -> None:
        pass

    def on_tool_call(self, call: ToolCall) -> None:
        pass

    def on_guard(self, decision: GuardDecision) -> None:
        pass

    def on_tool_result(self, name: str, result: dict[str, Any]) -> None:
        pass

    def on_correction(self, reason: str) -> None:
        pass

    def on_retry(self, attempt: int, error: str) -> None:
        pass

    def on_compressed(self, info: dict[str, Any]) -> None:
        pass


# ---------------------------------------------------------------------------
# 运行结果与单轮产出
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RunResult:
    """一次 run 的结局。status: finished / killed / error。"""

    status: str
    summary: str
    rounds: int
    input_tokens: int
    output_tokens: int
    error: str | None = None


@dataclass
class _RoundOutcome:
    """一轮 LLM 调用的归集结果(含 MalformedToolCall 的恢复信息)。"""

    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)
    malformed: MalformedToolCallError | None = None


# ---------------------------------------------------------------------------
# 主环
# ---------------------------------------------------------------------------


class AgentLoop:
    """一个 engagement 一个实例;``run(objective)`` 跑到底返回 RunResult。

    控制面(由 CLI 信号/TUI 调用,须与本对象同一事件循环):
    - ``interject(text)``:操作员插话,turn 边界注入为 user 消息;
    - ``pause()`` / ``resume()``:turn 边界停住/继续;
    - ``kill(reason)``:立即 cancel 当前 turn,清理路径杀全部活动 job。
    """

    def __init__(
        self,
        *,
        backend: LLMBackend,
        bash: BashTool,
        scope: Scope,
        audit: AuditLog,
        workdir: str | Path,
        system_prompt: str,
        registry: ToolRegistry | None = None,
        observer: LoopObserver | None = None,
        max_context_tokens: int = DEFAULT_MAX_CONTEXT_TOKENS,
        keep_recent_messages: int = DEFAULT_KEEP_RECENT_MESSAGES,
        first_event_timeout: float = FIRST_EVENT_TIMEOUT_SECONDS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        max_rounds: int = 0,  # 0 = 不限;headless 兜底阀,正常靠 finish/kill
    ) -> None:
        if first_event_timeout <= 0:
            raise ValueError("首事件超时必须为正(默认 30s,见 K3 实测)")
        if max_context_tokens <= 0:
            raise ValueError("context 预算必须为正")
        self._backend = backend
        self._bash = bash
        self._scope = scope
        self._audit = audit
        self._workdir = Path(workdir)
        self._system_prompt = system_prompt
        if registry is None:
            registry = ToolRegistry()
            registry.register_module(TOOL_SCHEMAS, bash.dispatch)
        self._registry = registry
        self._observer = observer or LoopObserver()
        self._max_context_tokens = max_context_tokens
        self._keep_recent = max(0, keep_recent_messages)
        self._first_event_timeout = first_event_timeout
        self._max_retries = max_retries
        self._max_rounds = max_rounds

        self._messages: list[Message] = []
        self._objective = ""
        self._interjections: deque[str] = deque()
        self._pause_requested = False
        self._kill_requested = False
        self._kill_reason = ""
        self._wake = asyncio.Event()
        self._run_task: asyncio.Task[None] | None = None
        self._status = "idle"
        self._rounds = 0
        self._total_input = 0
        self._total_output = 0
        # tool_call_id → (output_path, sha256):压缩占位要用的落盘线索
        self._result_hints: dict[str, tuple[str, str]] = {}

    # ---------- 公开只读面 ----------

    @property
    def status(self) -> str:
        return self._status

    @property
    def messages(self) -> list[Message]:
        return list(self._messages)

    # ---------- 操作员控制面 ----------

    def interject(self, text: str) -> None:
        """操作员插话入队;下一 turn 边界注入为 user 消息(不打断在跑工具)。"""
        text = text.strip()
        if text:
            self._interjections.append(text)

    def pause(self) -> None:
        """请求暂停:当前 turn 跑完后停在下一边界。"""
        self._pause_requested = True

    def resume(self) -> None:
        self._pause_requested = False
        self._wake.set()

    def kill(self, reason: str = "") -> None:
        """kill switch:立即 cancel 当前 turn;清理路径杀活动 job、写审计。"""
        if self._kill_requested:
            return
        self._kill_requested = True
        self._kill_reason = reason
        self._wake.set()  # 唤醒 pause 等待,让边界看到 kill
        task = self._run_task
        if task is not None and not task.done():
            task.cancel()

    # ---------- 主入口 ----------

    async def run(self, objective: str) -> RunResult:
        if self._run_task is not None:
            raise RuntimeError("run 不可重入:一个 AgentLoop 同时只能跑一个 run")
        self._run_task = asyncio.current_task()  # type: ignore[assignment]
        self._objective = objective
        self._set_status("running")
        self._ensure_engagement_file()
        self._messages = [
            Message.system(self._system_prompt),
            Message.system(build_engagement_message(self._read_engagement())),
            Message.user(objective),
        ]
        self._audit.append(
            KIND_RUN_STARTED,
            {
                "objective": objective,
                "provider": self._backend.provider,
                "workdir": str(self._workdir),
            },
        )
        try:
            result = await self._main()
        except asyncio.CancelledError:
            if not self._kill_requested:
                self._run_task = None
                raise  # 外部取消:如实向上传
            result = await self._finalize_killed()
        except BackendError as exc:
            result = self._finalize_error(str(exc))
        except Exception as exc:  # 非预期异常:如实记 error,不炸 headless
            result = self._finalize_error(f"主环内部异常: {exc!r}")
        self._audit.append(
            KIND_RUN_FINISHED,
            {
                "status": result.status,
                "rounds": result.rounds,
                "input_tokens": result.input_tokens,
                "output_tokens": result.output_tokens,
                "error": result.error,
                "final_text_sha256": hashlib.sha256(
                    result.summary.encode("utf-8")
                ).hexdigest(),
                "final_text_chars": len(result.summary),
            },
        )
        self._set_status(result.status)
        self._run_task = None
        return result

    # ---------- 状态机主体 ----------

    async def _main(self) -> RunResult:
        consecutive_malformed = 0
        consecutive_claim_corrections = 0
        while True:
            # ---- turn 边界:插话 → kill → pause ----
            self._drain_interjections()
            if self._kill_requested:
                return await self._finalize_killed()
            await self._pause_if_requested()
            if self._kill_requested:
                return await self._finalize_killed()
            self._refresh_engagement_message()
            self._maybe_compress()
            if self._max_rounds and self._rounds >= self._max_rounds:
                return self._finalize_error(
                    f"达到最大轮数上限 {self._max_rounds},run 终止(可调 --max-rounds)"
                )

            outcome = await self._llm_round_with_retry()
            if outcome.malformed is None:
                consecutive_malformed = 0
            else:
                consecutive_malformed += 1

            tool_calls = list(outcome.tool_calls)
            malformed_call_id: str | None = None
            if outcome.malformed is not None:
                malformed_call_id = (
                    outcome.malformed.call_id or f"malformed-{self._rounds}"
                )
                # 不变量「ToolCall.arguments 必为 dict」不允许携带原文,
                # 故以空参数重建该调用帧,坏 JSON 原文走 tool 结果回灌。
                tool_calls.append(
                    ToolCall(
                        id=malformed_call_id,
                        name=outcome.malformed.tool_name or "unknown",
                        arguments={},
                    )
                )
            self._messages.append(
                Message.assistant(content=outcome.text, tool_calls=tool_calls)
            )

            if not tool_calls:
                # finish 或幻觉执行(K3 实测:声称完成却不发 tool_call)
                if (
                    _ACTION_CLAIM_RE.search(outcome.text)
                    and consecutive_claim_corrections
                    < MAX_CONSECUTIVE_CLAIM_CORRECTIONS
                ):
                    consecutive_claim_corrections += 1
                    self._audit.append(
                        KIND_LOOP_CORRECTION,
                        {
                            "reason": "no_tool_call_action_claim",
                            "excerpt": outcome.text[:200],
                        },
                    )
                    self._observer.on_correction("no_tool_call_action_claim")
                    self._messages.append(Message.user(_CLAIM_CORRECTION_TEXT))
                    continue
                return RunResult(
                    status="finished",
                    summary=outcome.text,
                    rounds=self._rounds,
                    input_tokens=self._total_input,
                    output_tokens=self._total_output,
                )
            consecutive_claim_corrections = 0

            for call in tool_calls:
                if call.id == malformed_call_id:
                    content = self._malformed_tool_result(outcome.malformed)
                    self._audit.append(
                        KIND_LOOP_CORRECTION,
                        {
                            "reason": "malformed_tool_call",
                            "tool": outcome.malformed.tool_name,
                            "call_id": call.id,
                            "raw_arguments_sha256": hashlib.sha256(
                                outcome.malformed.raw_arguments.encode("utf-8")
                            ).hexdigest(),
                        },
                    )
                    self._observer.on_correction("malformed_tool_call")
                    if consecutive_malformed > MAX_CONSECUTIVE_MALFORMED:
                        self._messages.append(Message.tool_result(call.id, content))
                        return self._finalize_error(
                            f"模型连续 {consecutive_malformed} 次发出非法 JSON 工具"
                            "参数,纠正无效,run 终止"
                        )
                else:
                    result = await self._execute_tool(call)
                    self._observer.on_tool_result(call.name, result)
                    content = self._tool_result_content(call, result)
                self._messages.append(Message.tool_result(call.id, content))

    # ---------- LLM 一轮(含重试) ----------

    async def _llm_round_with_retry(self) -> _RoundOutcome:
        attempt = 0
        while True:
            try:
                return await self._collect_round()
            except MalformedToolCallError:  # pragma: no cover - 防御,正常进不来
                raise
            except TimeoutError as exc:
                error: BackendError = RequestTimeoutError(
                    f"[loop] LLM 首事件超时(>{self._first_event_timeout}s;"
                    f" K3 实测最慢 16.24s,若持续超时请检查网络/代理)",
                    provider=self._backend.provider,
                )
                error.__cause__ = exc
            except BackendError as exc:
                if not exc.retryable:
                    raise
                error = exc
            attempt += 1
            if attempt > self._max_retries:
                raise error
            self._audit.append(
                KIND_LLM_RETRY,
                {"attempt": attempt, "error": str(error)[:300]},
            )
            self._observer.on_retry(attempt, str(error))
            retry_after = getattr(error, "retry_after", None)
            delay = retry_after if retry_after else min(2 ** (attempt - 1), 8)
            await asyncio.sleep(delay)

    async def _collect_round(self) -> _RoundOutcome:
        agen = self._backend.chat(self._messages, self._registry.specs())
        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        usage = Usage()
        malformed: MalformedToolCallError | None = None
        try:
            iterator = agen.__aiter__()
            first = True
            while True:
                try:
                    if first:
                        # 首事件超时(K3 实测 max 16.24s → 默认 30s)
                        event = await asyncio.wait_for(
                            iterator.__anext__(), timeout=self._first_event_timeout
                        )
                        first = False
                    else:
                        event = await iterator.__anext__()
                except StopAsyncIteration:
                    break
                except MalformedToolCallError as exc:
                    malformed = exc  # 已收集的文本/工具调用保留,回灌纠正
                    break
                if isinstance(event, TextDelta):
                    text_parts.append(event.text)
                    self._observer.on_text_delta(event.text)
                elif isinstance(event, ToolCall):
                    tool_calls.append(event)
                elif isinstance(event, Usage):
                    usage = event
        finally:
            await agen.aclose()

        self._rounds += 1
        self._total_input += usage.input_tokens
        self._total_output += usage.output_tokens
        text = "".join(text_parts)
        response_repr: dict[str, Any] = {
            "text": text,
            "tool_calls": [
                {"id": c.id, "name": c.name, "arguments": c.arguments}
                for c in tool_calls
            ],
        }
        if malformed is not None:
            response_repr["malformed_raw_arguments"] = malformed.raw_arguments
        payload = llm_meta(
            json.dumps(
                [message_to_dict(m) for m in self._messages],
                ensure_ascii=False,
                sort_keys=True,
            ),
            json.dumps(response_repr, ensure_ascii=False, sort_keys=True),
            prompt_tokens=usage.input_tokens or None,
            response_tokens=usage.output_tokens or None,
        )
        self._audit.append(KIND_LLM_EXCHANGE_META, payload)
        return _RoundOutcome(
            text=text, tool_calls=tool_calls, usage=usage, malformed=malformed
        )

    # ---------- 工具执行 ----------

    async def _execute_tool(self, call: ToolCall) -> dict[str, Any]:
        self._observer.on_tool_call(call)
        if call.name == "run_command":
            command = call.arguments.get("command")
            if not isinstance(command, str) or not command.strip():
                return {"error": "run_command 需要非空字符串参数 command。"}
            decision = check_command(command, self._scope, self._audit)
            self._observer.on_guard(decision)
            if not decision.allowed:
                return {
                    "status": "denied_by_scope_guard",
                    "violations": list(decision.violations),
                    "reason": decision.reason,
                }
        result = await self._registry.dispatch(call.name, call.arguments)
        if call.name == "run_command" and "error" not in result:
            result = dict(result)
            note = describe_exit_code(result.get("exit_code"))
            if note:
                result["exit_note"] = note
            self._audit.append(
                KIND_EXEC_RESULT_META,
                {
                    "job_id": result.get("job_id"),
                    "status": result.get("status"),
                    "exit_code": result.get("exit_code"),
                    "duration_ms": result.get("duration_ms"),
                    "sha256": result.get("sha256"),
                    "output_path": result.get("output_path"),
                    "total_bytes": result.get("total_bytes"),
                },
            )
        return result

    def _tool_result_content(self, call: ToolCall, result: dict[str, Any]) -> str:
        path, sha = result.get("output_path"), result.get("sha256")
        if isinstance(path, str) and isinstance(sha, str):
            self._result_hints[call.id] = (path, sha)
        text = json.dumps(result, ensure_ascii=False)
        if len(text) > MAX_TOOL_RESULT_CHARS:
            text = (
                text[:MAX_TOOL_RESULT_CHARS]
                + "\n[结果被主环截断:单条工具结果过长;大输出请用 read_output 分页]"
            )
        return text

    @staticmethod
    def _malformed_tool_result(exc: MalformedToolCallError) -> str:
        return json.dumps(
            {
                "error": "malformed_tool_call",
                "tool": exc.tool_name,
                "detail": (
                    "该工具调用的参数不是合法 JSON,未被执行。请重新发出调用,"
                    "arguments 必须是合法 JSON 对象(双引号、无尾逗号、换行正确转义)。"
                ),
                "raw_arguments_excerpt": exc.raw_arguments[:_RAW_ARGS_ECHO_LIMIT],
            },
            ensure_ascii=False,
        )

    # ---------- turn 边界:插话 / 暂停 ----------

    def _drain_interjections(self) -> None:
        while self._interjections:
            text = self._interjections.popleft()
            self._audit.append(KIND_OPERATOR_INTERJECT, {"text": text})
            self._messages.append(Message.user(f"【操作员插话】{text}"))

    async def _pause_if_requested(self) -> None:
        if not (self._pause_requested and not self._kill_requested):
            return
        self._set_status("paused")
        while self._pause_requested and not self._kill_requested:
            self._wake.clear()
            if not (self._pause_requested and not self._kill_requested):
                break  # 与 resume()/kill() 的竞态:clear 后复查再等待
            await self._wake.wait()
        if not self._kill_requested:
            self._set_status("running")

    # ---------- 收尾 ----------

    async def _finalize_killed(self) -> RunResult:
        """kill 清理:杀全部活动 job(尽力而为)、写 kill_switch 审计。"""
        killed_jobs: list[dict[str, Any]] = []
        try:
            jobs = await self._bash.list_jobs()
            for entry in jobs.get("jobs", []):
                if entry.get("status") != "running":
                    continue
                outcome = await self._bash.kill_job(entry["job_id"])
                killed_jobs.append(
                    {
                        "job_id": entry["job_id"],
                        "status": outcome.get("status"),
                        "error": outcome.get("error"),
                    }
                )
        except (BackendError, OSError, RuntimeError) as exc:
            killed_jobs.append({"error": f"清理异常: {exc!r}"})
        self._audit.append(
            KIND_KILL_SWITCH,
            {"reason": self._kill_reason, "jobs": killed_jobs},
        )
        return RunResult(
            status="killed",
            summary="",
            rounds=self._rounds,
            input_tokens=self._total_input,
            output_tokens=self._total_output,
            error=self._kill_reason or None,
        )

    def _finalize_error(self, error: str) -> RunResult:
        return RunResult(
            status="error",
            summary="",
            rounds=self._rounds,
            input_tokens=self._total_input,
            output_tokens=self._total_output,
            error=error,
        )

    # ---------- context 压缩 ----------

    def _protected_head(self) -> int:
        """头部保护条数:全部 system 消息 + 首条 user(objective)永不压缩。"""
        index = 0
        while index < len(self._messages) and self._messages[index].role == "system":
            index += 1
        if index < len(self._messages) and self._messages[index].role == "user":
            index += 1
        return index

    def _maybe_compress(self) -> None:
        estimated = estimate_tokens(self._messages)
        if estimated <= self._max_context_tokens:
            return
        before = estimated
        head = self._protected_head()
        tail_from = max(head, len(self._messages) - self._keep_recent)

        # 阶段一:先压旧 tool 结果(占位带落盘路径+sha256,可溯源)
        tool_hits = 0
        for i in range(head, tail_from):
            if estimated <= self._max_context_tokens:
                break
            message = self._messages[i]
            if message.role != "tool":
                continue
            placeholder = self._tool_placeholder(message.tool_call_id)
            saved = len(message.content) - len(placeholder)
            if saved <= 0:
                continue
            self._messages[i] = Message.tool_result(message.tool_call_id, placeholder)
            estimated -= saved // 4
            tool_hits += 1

        # 阶段二:仍超限再压旧对话(assistant 保留 tool_calls 以维持协议配对)
        conversation_hits = 0
        if estimated > self._max_context_tokens:
            for i in range(head, tail_from):
                if estimated <= self._max_context_tokens:
                    break
                message = self._messages[i]
                if message.role == "assistant" and message.content:
                    saved = len(message.content) - len(_COMPRESSED_ASSISTANT)
                    if saved <= 0:
                        continue
                    self._messages[i] = Message.assistant(
                        _COMPRESSED_ASSISTANT, message.tool_calls
                    )
                    estimated -= saved // 4
                    conversation_hits += 1
                elif message.role == "user":
                    saved = len(message.content) - len(_COMPRESSED_USER)
                    if saved <= 0:
                        continue
                    self._messages[i] = Message.user(_COMPRESSED_USER)
                    estimated -= saved // 4
                    conversation_hits += 1

        info = {
            "estimated_tokens_before": before,
            "estimated_tokens_after": estimated,
            "budget": self._max_context_tokens,
            "tool_results_compressed": tool_hits,
            "conversation_compressed": conversation_hits,
            "still_over_budget": estimated > self._max_context_tokens,
        }
        self._audit.append(KIND_CONTEXT_COMPRESSED, info)
        self._observer.on_compressed(info)

    def _tool_placeholder(self, tool_call_id: str | None) -> str:
        hint = self._result_hints.get(tool_call_id or "")
        if hint is None:
            return _COMPRESSED_TOOL_GENERIC
        path, sha = hint
        return (
            "[已压缩] 旧工具结果已移除以释放上下文;完整输出已落盘 "
            f"{path} (sha256:{sha}),需要时用 read_output 分页读取。"
        )

    # ---------- ENGAGEMENT.md(WP-06 接管前的文件读写占位) ----------

    def _engagement_path(self) -> Path:
        return self._workdir / ENGAGEMENT_FILENAME

    def _ensure_engagement_file(self) -> None:
        path = self._engagement_path()
        if not path.exists():
            path.write_text(
                render_engagement_template(
                    objective=self._objective,
                    started_at=datetime.now(UTC).isoformat(timespec="seconds"),
                ),
                encoding="utf-8",
            )

    def _read_engagement(self) -> str:
        try:
            return self._engagement_path().read_text(encoding="utf-8")
        except FileNotFoundError:
            self._ensure_engagement_file()  # 被误删则按模板重建
            return self._engagement_path().read_text(encoding="utf-8")

    def _refresh_engagement_message(self) -> None:
        """每轮必载:重读文件并刷新 messages 中固定的第二条 system 消息。"""
        if len(self._messages) >= 2 and self._messages[1].role == "system":
            self._messages[1] = Message.system(
                build_engagement_message(self._read_engagement())
            )

    # ---------- 小工具 ----------

    def _set_status(self, status: str) -> None:
        if status != self._status:
            self._status = status
            self._observer.on_status(status)
