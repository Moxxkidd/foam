"""命令行入口初版(WP-04):headless ``run`` 子命令。

职责边界:本版只跑通「加载 scope → 建 engagement 目录 → 拼 AgentLoop →
headless 跑完一个 objective」。TUI 是 WP-09;resume/replay/report 闭环是
WP-10(届时本子命令由其收口)。

退出码:0 = finished;130 = killed(含 Ctrl-C);1 = error;2 = 参数/配置错误。
密钥只走环境变量(各后端自己的 env key);本文件不接触 key 本体。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from foam import __app_name__, __version__
from foam.agent.backends.base import ConfigError, LLMBackend, ToolCall
from foam.agent.backends.claude import DEFAULT_BASE_URL, ClaudeBackend
from foam.agent.backends.openai_compat import OpenAICompatBackend
from foam.agent.loop import (
    AgentLoop,
    LoopObserver,
    RunResult,
)
from foam.agent.prompts import build_system_prompt
from foam.guard.audit import KIND_SCOPE_LOADED, AuditLog
from foam.guard.scope import GuardDecision, load_scope, scope_payload
from foam.tools.bash import BashTool

#: openai_compat 的默认模型(WP-03 实测模型);可用 --model 或 env 覆盖。
DEFAULT_OPENAI_MODEL = "k3"
#: claude 后端的默认模型;可用 --model 或 env 覆盖。
DEFAULT_CLAUDE_MODEL = "claude-sonnet-5"
#: 非密钥配置环境变量(API key 由各后端自己的 env 读取,不经本文件)。
ENV_BASE_URL = "FOAM_LLM_BASE_URL"
ENV_MODEL = "FOAM_LLM_MODEL"

#: 退出码
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_KILLED = 130

BackendFactory = Callable[[argparse.Namespace], LLMBackend]


class _CliObserver(LoopObserver):
    """headless 渲染:模型文本流式上屏,工具/护栏/纠正各一行摘要。"""

    def __init__(self, out: Any = None) -> None:
        self._out = out or sys.stdout

    def _line(self, text: str) -> None:
        print(text, file=self._out, flush=True)

    def on_text_delta(self, text: str) -> None:
        print(text, end="", file=self._out, flush=True)

    def on_tool_call(self, call: ToolCall) -> None:
        args = json.dumps(call.arguments, ensure_ascii=False)
        if len(args) > 200:
            args = args[:200] + "…"
        self._line(f"\n[tool→] {call.name} {args}")

    def on_guard(self, decision: GuardDecision) -> None:
        if decision.allowed:
            targets = ", ".join(decision.targets) or "(无网络目标)"
            self._line(f"[guard] 放行:{targets}")
        else:
            self._line(f"[guard] 拒绝:越界目标 {list(decision.violations)}")

    def on_tool_result(self, name: str, result: dict[str, Any]) -> None:
        if "error" in result:
            self._line(f"[result] {name}: error={result['error'][:160]}")
            return
        parts = [f"[result] {name}:"]
        for key in ("status", "exit_code", "duration_ms", "total_bytes"):
            if result.get(key) is not None:
                parts.append(f"{key}={result[key]}")
        if result.get("sha256"):
            parts.append(f"sha256={str(result['sha256'])[:12]}…")
        if result.get("exit_note"):
            parts.append(f"({result['exit_note']})")
        self._line(" ".join(parts))

    def on_correction(self, reason: str) -> None:
        self._line(f"[纠正] {reason}:已向模型回灌纠正说明")

    def on_retry(self, attempt: int, error: str) -> None:
        self._line(f"[重试] 第 {attempt} 次:{error[:160]}")

    def on_compressed(self, info: dict[str, Any]) -> None:
        self._line(
            "[context] 压缩:估算 "
            f"{info['estimated_tokens_before']}→{info['estimated_tokens_after']} "
            f"tokens(预算 {info['budget']},压 tool 结果 "
            f"{info['tool_results_compressed']} 条、对话 "
            f"{info['conversation_compressed']} 条)"
        )

    def on_status(self, status: str) -> None:
        if status in ("paused", "killed", "error"):
            self._line(f"[status] {status}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="foam",
        description=f"{__app_name__} {__version__} —— 授权渗透测试 harness(headless)",
    )
    parser.add_argument(
        "--version", action="version", version=f"{__app_name__} {__version__}"
    )
    sub = parser.add_subparsers(dest="command")
    run = sub.add_parser(
        "run",
        help="headless 跑一个 objective(TUI 见后续版本)",
        epilog="Ctrl-C 一次触发 kill switch(杀活动 job、写审计、退出码 130);"
        "再按一次立即强制退出。",
    )
    run.add_argument("--scope", required=True, help="scope 授权范围文件路径")
    run.add_argument("--objective", required=True, help="本次 engagement 的目标描述")
    run.add_argument(
        "--backend",
        choices=["openai_compat", "claude"],
        default="openai_compat",
        help="LLM 后端(默认 openai_compat)",
    )
    run.add_argument(
        "--model",
        default=None,
        help=f"模型 id(默认取 env {ENV_MODEL},再退内置默认:openai_compat="
        f"{DEFAULT_OPENAI_MODEL} / claude={DEFAULT_CLAUDE_MODEL})",
    )
    run.add_argument(
        "--base-url",
        default=None,
        help=f"API base url(openai_compat 必填,可取 env {ENV_BASE_URL};"
        "claude 默认为官方端点)",
    )
    run.add_argument(
        "--workdir",
        default=None,
        help="engagement 目录(默认 engagements/eng-<UTC 时间戳>)",
    )
    run.add_argument(
        "--max-context-tokens",
        type=int,
        default=None,
        help="context 压缩预算(token 粗估,默认 120000)",
    )
    run.add_argument(
        "--max-rounds",
        type=int,
        default=0,
        help="LLM 轮数上限,0 为不限(默认 0;headless 兜底阀)",
    )
    run.add_argument(
        "--first-event-timeout",
        type=float,
        default=None,
        help="等 LLM 首事件的超时秒数(默认 30,实测最慢 16.24s)",
    )
    return parser


def _build_backend(args: argparse.Namespace) -> LLMBackend:
    """按参数构造后端;密钥由后端自己从 env 读取(缺失抛 ConfigError)。"""
    model = args.model or os.environ.get(ENV_MODEL)
    if args.backend == "claude":
        return ClaudeBackend(
            model=model or DEFAULT_CLAUDE_MODEL,
            base_url=args.base_url or DEFAULT_BASE_URL,
        )
    base_url = args.base_url or os.environ.get(ENV_BASE_URL)
    if not base_url:
        raise ConfigError(
            f"openai_compat 需要 base url:--base-url 或环境变量 {ENV_BASE_URL}",
            provider="openai_compat",
        )
    return OpenAICompatBackend(base_url=base_url, model=model or DEFAULT_OPENAI_MODEL)


def _default_workdir() -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    return Path("engagements") / f"eng-{stamp}"


async def _cmd_run(args: argparse.Namespace, backend_factory: BackendFactory) -> int:
    try:
        scope = load_scope(args.scope)
    except (OSError, ValueError) as exc:
        print(f"[错误] scope 加载失败: {exc}", file=sys.stderr)
        return EXIT_USAGE
    try:
        backend = backend_factory(args)
    except ConfigError as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        return EXIT_USAGE

    workdir = Path(args.workdir) if args.workdir else _default_workdir()
    outputs = workdir / "outputs"
    outputs.mkdir(parents=True, exist_ok=True)
    audit = AuditLog(workdir / "audit.jsonl")
    audit.append(KIND_SCOPE_LOADED, scope_payload(scope, str(args.scope)))

    bash = BashTool(outputs)
    loaded_at = datetime.now(UTC).isoformat(timespec="seconds")
    system_prompt = build_system_prompt(
        scope, source=str(args.scope), loaded_at=loaded_at, workdir=workdir
    )
    loop_kwargs: dict[str, Any] = {}
    if args.max_context_tokens is not None:
        loop_kwargs["max_context_tokens"] = args.max_context_tokens
    if args.first_event_timeout is not None:
        loop_kwargs["first_event_timeout"] = args.first_event_timeout
    loop = AgentLoop(
        backend=backend,
        bash=bash,
        scope=scope,
        audit=audit,
        workdir=workdir,
        system_prompt=system_prompt,
        observer=_CliObserver(),
        max_rounds=args.max_rounds,
        **loop_kwargs,
    )

    print(f"[run] workdir={workdir} backend={args.backend}", flush=True)
    print(
        f"[scope] {len(scope.rules)} 条规则已加载({args.scope});"
        "越界命令将被护栏拒绝并记审计",
        flush=True,
    )

    # Ctrl-C:第一次走 kill switch;第二次立即强制退出(审计每条已 flush,不丢)。
    running_loop = asyncio.get_running_loop()
    sigint_seen = False

    def _on_sigint() -> None:
        nonlocal sigint_seen
        if loop.status in ("finished", "error", "killed"):
            return
        if sigint_seen:
            os._exit(EXIT_KILLED)
        sigint_seen = True
        print(
            "\n[操作员] Ctrl-C:触发 kill switch(再按一次强制退出)",
            file=sys.stderr,
            flush=True,
        )
        loop.kill("操作员 Ctrl-C")

    running_loop.add_signal_handler(signal.SIGINT, _on_sigint)
    try:
        result: RunResult = await loop.run(args.objective)
    finally:
        running_loop.remove_signal_handler(signal.SIGINT)
        audit.close()
        await backend.aclose()

    print(
        f"\n[run {result.status}] {result.rounds} 轮,"
        f"tokens 输入 {result.input_tokens} / 输出 {result.output_tokens}",
        flush=True,
    )
    if result.error:
        print(f"[error] {result.error}", file=sys.stderr)
    return {
        "finished": EXIT_OK,
        "killed": EXIT_KILLED,
        "error": EXIT_ERROR,
    }.get(result.status, EXIT_ERROR)


def main(
    argv: Sequence[str] | None = None, *, backend_factory: BackendFactory | None = None
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "run":
        factory = backend_factory or _build_backend
        try:
            return asyncio.run(_cmd_run(args, factory))
        except KeyboardInterrupt:
            return EXIT_KILLED
    parser.print_help()
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
