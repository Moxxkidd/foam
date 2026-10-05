"""run 级运行时资源所有权与统一关闭(R03)。

CLI/TUI 共享同一关闭服务 :func:`close_run`——修复前各入口各自为战(CLI
``_drive`` finally、TUI ``_cleanup_resources`` 顺序还倒挂:先关审计后收割),
后台 job 在 finished/error/cancel 路径无人收割(E04)。

固定顺序(D5):

1. **收割本 run 进程**:``bash.aclose()`` → ``session.aclose()``(各自幂等、
   各自有总上界;loop 收尾已先收割时此处为幂等空转)。收割阶段总上界 =
   两层上界之和(文档化约定,单层见 tools/bash.py、tools/session.py 的
   ``CLOSE_REAP_TIMEOUT_SECONDS``)。
2. **关闭索引/状态**:state(StateTool 的 Index 连接)→ engagement(含其
   懒加载 Index)。
3. **关闭审计**(永远最后:终态记录必须先于它落链;loop 在调用本服务前
   已写妥 run_finished)。
4. **关闭后端**(httpx 连接等)。
5. **释放单写者锁**(R02;TUI 未接锁时 lock 为 None)。

任一步失败如实记入返回报告(``cleanup_status="partial"`` +
``remaining_resources``/``errors``),**不跳过后续步骤**(AC06);全程幂等,
二次调用短路返回首次结果对象(AC04)。停止派发由两层承担:loop 终态置
``_dispatch_stopped``(主闸),工具层 aclose 后拒绝新命令/新会话(兜底)。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class RunRuntime:
    """一次 run 的资源句柄集(全部可选:装配中途失败也走同一关闭面)。

    CLI 的 ``_Runtime`` 与 TUI 的 run 装配共用本结构;``loop`` 只作引用
    (派发停止由 loop 自己落,本服务不反向调用)。
    """

    bash: Any = None  # BashTool
    session: Any = None  # SessionTool
    state: Any = None  # StateTool
    engagement: Any = None  # Engagement
    audit: Any = None  # AuditLog
    backend: Any = None  # LLMBackend
    lock: Any = None  # EngagementLock(R02;TUI 未接锁时为 None,见 R03 §7 D3)
    loop: Any = None  # AgentLoop(引用;不由本服务驱动)
    closed: bool = False
    close_result: dict[str, Any] | None = None


async def close_run(
    runtime: RunRuntime, *, run_id: str = "", reason: str = ""
) -> dict[str, Any]:
    """统一关闭入口;固定顺序(见模块 docstring),全程幂等。

    ``run_id``/``reason`` 只进返回报告,供入口层(CLI stderr / TUI 通知)
    展示;本服务不写审计——终态记录由 loop 在收割后、本调用前落链(D6)。
    返回 ``{cleanup_status, remaining_resources, errors, run_id, reason}``;
    二次调用短路返回首次结果对象。
    """
    if runtime.close_result is not None:
        return runtime.close_result
    runtime.closed = True
    remaining: list[dict[str, Any]] = []
    errors: list[str] = []

    # 1. 收割本 run 进程(各自有界;总上界 = 两层之和,见模块 docstring)
    for label, tool in (("bash", runtime.bash), ("session", runtime.session)):
        if tool is None:
            continue
        try:
            report = await tool.aclose()
        except Exception as exc:
            errors.append(f"{label} 收割异常: {exc!r}")
            continue
        if report:  # 旧式 None 返回(测试桩)按 ok 处理
            remaining.extend(report.get("remaining_resources", []))
            errors.extend(report.get("errors", []))

    # 2. 关闭索引/状态
    if runtime.state is not None:
        try:
            runtime.state.close()
        except Exception as exc:
            errors.append(f"state 关闭异常: {exc!r}")
    if runtime.engagement is not None:
        try:
            runtime.engagement.close()
        except Exception as exc:
            errors.append(f"engagement 关闭异常: {exc!r}")

    # 3. 审计永远最后关闭(终态记录须先落链;修复 CLI 先关审计后收割的倒挂)
    if runtime.audit is not None:
        try:
            runtime.audit.close()
        except Exception as exc:
            errors.append(f"audit 关闭异常: {exc!r}")

    # 4. 关闭后端
    if runtime.backend is not None:
        try:
            await runtime.backend.aclose()
        except Exception as exc:
            errors.append(f"backend 关闭异常: {exc!r}")

    # 5. 释放单写者锁
    if runtime.lock is not None:
        try:
            runtime.lock.release()
        except Exception as exc:
            errors.append(f"锁释放异常: {exc!r}")

    result: dict[str, Any] = {
        "cleanup_status": "partial" if (remaining or errors) else "ok",
        "remaining_resources": remaining,
        "errors": errors,
        "run_id": run_id,
        "reason": reason,
    }
    runtime.close_result = result
    return result


def cleanup_warning_text(result: dict[str, Any]) -> str | None:
    """cleanup_pending 展示面(D2):partial 时给中文警示行,否则 None。

    AC06:清理失败必须可见,不得呈现「全部完成」。CLI 上 stderr、TUI 上
    叙述流通知,共用这个文本;退出码契约不变(不由本函数干预)。
    """
    if result.get("cleanup_status") != "partial":
        return None
    parts = ["清理未全部完成(cleanup_pending)"]
    remaining = result.get("remaining_resources") or []
    if remaining:
        desc = ", ".join(
            "{}:{}(pid {})".format(
                r.get("kind", "?"),
                r.get("job_id") or r.get("session_id") or "?",
                r.get("pid", "?"),
            )
            for r in remaining
        )
        parts.append(f"上界内未收割 {len(remaining)} 项:{desc}")
    errors = result.get("errors") or []
    if errors:
        parts.append("异常:" + ";".join(str(e)[:200] for e in errors))
    parts.append("请人工核查残留进程")
    return ";".join(parts)
