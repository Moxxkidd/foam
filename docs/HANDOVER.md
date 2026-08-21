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
- 2026-08-20:**仓库历史重写**(非 WP 动作,与开发条目正交)——为让
  GitHub 贡献正确归属,全部 commit 的作者/提交者统一重写为
  `Moxxkidd <Moxxkidd@users.noreply.github.com>`,5 个 commit 哈希全部
  变更(重写前后逐对校验 tree 字节一致,内容零变化);旧哈希在仓库跟踪
  文件中无任何引用,无需替换。本地单一工作区、无其他克隆,无连带影响。
  此后新 commit 均带正确身份,无需再做此类重写。
- 2026-08-21:**WP-06 关闭**——状态层(`state/files.py`:engagement
  目录布局幂等创建/校验,`engagement.json` 记 scope 文件 sha256,
  `ENGAGEMENT.md` 读写接口留 loop 每轮调用;`state/index.py`:SQLite
  六表 upsert/关系查询/通用 query;`tools/state.py`:state_query /
  state_add_note / state_add_loot 三工具,schema 与 WP-01 同构)。
  **outputs/ 契约**:`Engagement.paths.outputs` 即 WP-01 输出层的
  output_root,WP-04/WP-10 接线时传入 `BashTool(output_dir=...)`;
  creds 对 LLM 默认掩码中段(完整值仅在落盘 index.sqlite,WP-10 经
  索引层取)。详见 `docs/dev-logs/WP-06.md`。
- 2026-08-21:**WP-05 关闭**——持久 PTY 会话层(`tools/session.py`:
  session_open/send/read/close/list,复用 WP-01 输出层 `split=False`
  全量落盘 + 流式 sha256,分流字段固定 None;pty 显式取 ctty,ssh
  `/dev/tty` 密码提示可达;提示识别正则库(msf6/meterpreter/password/
  ssh yes-no/sqlmap Y-n)命中返回结构化 `waiting_for_input` 事件,尾部
  锚定 + offset 去重防误报/重复;ANSI 清洗只作用 LLM 视图,落盘原文;
  会话上限默认 8 按未关闭计,进程组 SIGKILL 回收孤儿,`aclose()` 供
  WP-04 kill switch)。msfconsole/ssh 两项环境门控 skip 待补测,见
  `docs/dev-logs/WP-05.md`。
- 2026-08-21:**WP-04 关闭**——agent 主环(`agent/loop.py`:消息状态机
  user→assistant(tool_call)→tool 结果直至 finish;可追加 ToolRegistry
  (未知工具名/非法参数回 error dict 让模型自我纠正);每条 run_command
  先过 scope 护栏,拒绝连同纠正说明回消息流;两阶段 context 压缩(先旧
  tool 结果→占位含落盘路径+sha256,再旧对话,system/ENGAGEMENT.md/
  objective/最近窗口永不压缩);插话 turn 边界注入、pause/resume、kill
  立即 cancel 当前 turn 并杀全部活动 job;消化 K3 实测:幻觉执行动作
  声明纠正(预算 2 次)、MalformedToolCall 空参重建帧+坏 JSON 回灌
  (连续 3 次熔断)、首事件超时默认 30s;新增审计 kind:run_started/
  run_finished/loop_correction/llm_retry/context_compressed)。
  `agent/prompts.py`:授权声明(scope 规则原文+加载时间)、方法论骨架、
  红线、工具地图注入点,快照测试逐字锁定、零品牌名。`cli.py` 初版:
  `kalicode run` headless(退出码 0/130/1/2,Ctrl-C 两次语义)。
  本会话无 LLM 凭据,真实模型 e2e 未跑(见日志「踩坑 5」)。接线点与
  已知限制见 `docs/dev-logs/WP-04.md`。

## 下一 WP

**WP-08(工具地图)、WP-09(TUI)已随 WP-04 关闭解锁;WP-10(CLI 闭环)
依赖(02/04/06)亦全部就绪**。WP-10 接线要点(详见 WP-04 日志「留给
后续 WP」):① cli 建目录换 WP-06 `Engagement.create`(布局已与现状
一致:根下 ENGAGEMENT.md、outputs/、audit.jsonl);② loop 的
ENGAGEMENT.md 读写占位换 `state/files.py` 接口;③ WP-05 会话工具与
WP-06 状态工具经 `ToolRegistry.register_module` 直接挂(两者与 WP-01
schema 同构);④ kill 清理面扩到会话层 `aclose()`(当前只杀 BashTool
jobs)。WP-07(parse,依赖 06)仍解锁待认领。
**WP-12 开工前**先在 Kali 补跑 WP-05 的 msfconsole 门控测试(见上条)。

## WP 依赖速查

```
WP-01 ──┬─ WP-04 ──┬─ WP-08 ── WP-11(场景一)
WP-02 ──┤          ├─ WP-09(TUI)
WP-03 ──┘          └─ WP-10(CLI 闭环)
WP-05(会话)── WP-12(场景二)
WP-06 ── WP-07(parse)
WP-13(整合)依赖全部
```

## 里程碑门(2026-08-21 挂牌;WP 制不变,门口纪律见台账同名节)

- **M1 = WP-04 关闭**(能力演示:真实 K3 `kalicode run` 跑 lab scope
  无害链 + 方向复评)——**当前触发中**,WP-04 关闭时未跑真实模型 e2e
  (其日志「踩坑 5」),此门即补跑动作,过了 M1 再开 WP-08/09/10。
- M2 = WP-09+10 关闭(TUI/CLI 演示,对照 strix/Claude Code 观感)。
- M3 = WP-11+12 关闭(双场景实弹,对照唯一目标:1+1≫2?)。
- M4 = WP-13 关闭(发布评审)。
门口产出三选一:放行 / 规格更正当 / 砍后续 WP;不开新坑;波次中途
不受理方向争论。

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
8. **noqa 后不能跟括号说明文字**(WP-02/WP-06 各踩一次):`# noqa: Sxxx(理由)`
   被 ruff 判非法指令,理由须写成上方独立注释。S105/S106 还会误伤**名字
   含 secret 的变量/键名**(如 `secret_note` 键)——测试目录已豁免,源码
   目录起名避开。SQL 白名单拼接(表名/列名常量化、值参数化)触 S608 时
   用 noqa 并注明依据。
9. **PTY 三坑**(WP-05):① 子进程光 setsid 不够,要 `ioctl(0, TIOCSCTTY)`
   拿控制终端,否则 ssh 读 `/dev/tty` 拿不到密码提示;② PTY EOF 在
   Linux 报 EIO、macOS 报空读,两种都要按 EOF 处理;③ 「被杀」与
   「自然退出」要靠 closing 旗标区分——收割协程先醒,直接标 exited 会
   把被杀的会话标错。另:async 等待循环里 `event.clear()` 必须先于读
   数据,否则丢唤醒傻等到超时。
10. **护栏测试里的引号坑**(WP-04):`echo "recon 127.0.0.1"` 经 shlex
    分词后 `recon 127.0.0.1` 是**一个词元**,护栏正确地提取不到目标——
    写护栏相关用例先想词元边界,目标要裸写(`echo recon 127.0.0.1`)。
11. **压缩/预算测试先算后写**(WP-04):`estimate_tokens` 是字符数/4;
    keep_recent 默认 6 条会把小对话几乎全保护(无可压对象导致假失败)——
    构造超限用例时显式传小窗口,并按总字符数/4 精确定预算,别拍脑袋。
    另:ruff E501 对字符串内长行同样生效,长快照文本拆拼接串(noqa 在
    字符串里会变成内容,无效)。
