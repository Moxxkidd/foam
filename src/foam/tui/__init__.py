"""TUI 包(WP-09):迎宾屏(呼号门)→ 主界面(叙述流/侧栏/输入坞)。

对外契约(WP-10 的 ``foam tui`` 子命令只经本处接入):

- :func:`foam.tui.app.main` —— CLI 入口(args 携带 --scope/--backend 等,
  返回进程退出码 0/130/1/2);
- :class:`TUIConfig` + :func:`run_tui` —— 程序化启动配置与同步入口;
- :func:`default_loop_factory` / :class:`RunContext` / :class:`RunHandle`
  —— loop 装配钩子协议(默认装配与 headless run 同构:exec/会话/状态 +
  工具地图;自定义 factory 可换可扩);
- :class:`TuiApp` —— textual App 本体(pilot 测试直接驱动)。
"""

from foam.tui.app import (
    RunContext,
    RunHandle,
    TuiApp,
    TUIConfig,
    default_loop_factory,
    main,
    run_tui,
)

__all__ = [
    "RunContext",
    "RunHandle",
    "TUIConfig",
    "TuiApp",
    "default_loop_factory",
    "main",
    "run_tui",
]
