# HANDOVER —— 交接文档(append-only 修订,见 AGENTS.md §3)

> 读法:先看「当前状态」定位,再看「下一 WP」,「已知陷阱」防重复踩坑。
> 每个 WP 关闭时更新本文件(契约第 2.3 条)。

## 当前状态

- 2026-08-19:**阶段 0 完成**——仓库骨架(pyproject/LICENSE/README/
  scopes/包目录)、开发契约(AGENTS.md)、本文件、台账、全部 WP 规格
  文档就绪;GitHub 私有 repo 已建并推送 main。尚无任何功能代码。
- 2026-08-20:**WP-02 关闭**——scope 护栏 v0(`guard/scope.py`:CIDR/
  主机名/通配域/URL 前缀解析,启发式目标提取,拒绝时给 LLM 可行动纠正
  说明)+ 哈希链审计(`guard/audit.py`:append-only JSONL,`verify`
  全链重算,LLM 内容只记哈希与 token 数)。绕过面清单与误判案例见
  `docs/dev-logs/WP-02.md`。
- 2026-08-20:**WP-01 关闭**——exec 层(`tools/bash.py`:run_command /
  read_output / list_jobs / kill_job,进程组强杀防孤儿,timeout 默认
  放宽到 1800s、显式 null 不限时,list_jobs 带超时剩余秒数)+ 智能输出
  层(`tools/output.py`:合流 + stdout/stderr 分流三文件、三个流式
  sha256 全量落盘,head+tail 截断视图,字节级分页,ring buffer 有界
  ——100MB 实测 Python 峰值 0.80MB)。工具 schema 为 provider 中立
  `{name, description, parameters}` 纯 dict(`TOOL_SCHEMAS` +
  `BashTool.dispatch`):WP-03 负责翻译、WP-04 直接注册、WP-06 同构。
  设计取舍与踩坑见 `docs/dev-logs/WP-01.md`。
- 2026-08-20:**WP-03 关闭**——LLM 后端(`agent/backends/`:统一
  `chat(messages, tools)` 异步事件流,事件仅 TextDelta/ToolCall/Usage
  三种,ToolCall.arguments 必为合法 dict;结构化错误树区分可重试
  (网络/超时/限流/5xx)与 provider 拒绝(审核/鉴权/坏请求);
  provider 错误回显 key 的脱敏有专项测试)。OpenAI 兼容层实测 Kimi K3
  (`k3`,思考型,reasoning_content 本层 v1 不消费):参数合法 JSON 率
  100%,授权渗透 prompt 审核拦截 0/8,首事件延迟中位约 4.3s。Claude
  端凭据未提供未实测。详见 `docs/dev-logs/WP-03.md`。

## 下一 WP

**WP-04(agent 主环)依赖已全部就绪**:WP-01(exec)、WP-02(护栏/
审计)、WP-03(LLM 后端)均已 closed,可开工——注意 WP-03 实测发现
K3 会偶发「声称完成却不发 tool_call」(幻觉执行),loop 侧需校验。
WP-05(PTY,依赖 01)与 WP-06(状态层,依赖 01)亦已解锁,可开工。

## WP 依赖速查

```
WP-01 ──┬─ WP-04 ──┬─ WP-08 ── WP-11(场景一)
WP-02 ──┤          ├─ WP-09(TUI)
WP-03 ──┘          └─ WP-10(CLI 闭环)
WP-05(会话)── WP-12(场景二)
WP-06 ── WP-07(parse)
WP-13(整合)依赖全部
```

## 已知陷阱

1. **品牌名禁令**:写代码/文档时不得出现品牌字符串(AGENTS.md §0)——
   违者后续改名时逐处返工。
2. **运行时产物别入库**:engagements/ 已被 .gitignore 挡住;提交前
   `git status` 自查。
3. **WP-03 实测任务**:Kimi K3 对渗透类 prompt 的审核容忍度与 JSON 纪律
   是实测项,被拦就如实记录,**不改写 prompt 去规避审核**。
4. **共享 .venv 的 editable install 在并行开发时会被踩坏**(`import
   kalicode` 突然失败):先查 `.venv` 状态,`PYTHONPATH=src` 可绕过;
   pyproject 已配 `pythonpath = ["src"]`(pytest)与 tests 目录 S101 豁免。
   另:本机 pip 走 SOCKS 代理但缺 `pysocks`,联网安装会失败。
5. **护栏语义细节**(WP-02):URL 前缀与 CIDR 是「或」关系——要端口级细
   粒度,scope 里就不能有更宽的 CIDR;`*.example.com` 不匹配裸域;CIDR
   目标必须 `subnet_of` scope 网段。完整绕过面见 `docs/dev-logs/WP-02.md`。
6. **裸 python 脚本要手动 `PYTHONPATH=src`**(陷阱 4 同源):pytest 靠
   pyproject `pythonpath=["src"]` 免配置,但直接 `.venv/bin/python` 跑
   临时脚本时 editable .pth 可能不生效。另:ruff ASYNC230/240 已对
   `tests/**` 豁免(测试内小文件阻塞读是有意的),源码目录不豁免——
   WP-05 复用 `tools/output.py` 时保持同步原子写,别在协程里加阻塞调用。
7. **.pth 失效的根因(WP-03 查明)**:sandbox 写出的文件带 macOS
   `UF_HIDDEN` 旗标,Homebrew 补丁版 site.py **跳过 hidden .pth**;
   `chflags nohidden <pth>` 可修,但任何人重装 editable 会复发——别修
   了,直接用陷阱 6 的 `PYTHONPATH=src`。另:httpx 走 socks5 代理需
   `socksio`(本机 .venv 已装,环境工具非项目依赖)。
