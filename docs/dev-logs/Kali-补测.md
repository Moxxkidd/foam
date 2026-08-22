# Kali 补测:WP-05 msfconsole + WP-08 盘点 + 全量首跑

日期:2026-08-22|执行:Kali 实机补测会话|状态:已回传总指挥

> 本文是三笔「待 Kali 补测」欠账的实测记录:WP-05 的 msfconsole/ssh 门控
> 测试、WP-08 的工具盘点真实覆盖率、以及本测试套件首次在真实目标平台
> 的全量运行。**未改动任何源码与测试**;发现的缺陷如实记录,修不修由
> 总指挥定。

## 0. 环境与前置检查

- 机器:Kali GNU/Linux Rolling(arm64),`kali-linux-default 2025.3.2`。
- `python3 --version` → **Python 3.13.7**(≥3.12 ✓,未动系统 python)。
- venv:`python3 -m venv .venv` 成功;`pip install pytest pytest-asyncio
  httpx rich textual ruff` 全部成功,网络正常,未走任何兜底。
  关键版本:pytest 9.1.1 / pytest-asyncio 1.4.0 / httpx 0.28.1 /
  ruff 0.16.4 / textual 8.2.8 / rich 15.0.0。
  (比开发机锁的版本新,本次结果均在此版本组合下取得。)
- `which msfconsole` → `/usr/bin/msfconsole`,**已预装**
  (`metasploit-framework 6.4.84-0kali1`),未执行 apt install。
- sshd:`ssh.service active (running)`,`/usr/sbin/sshd` 在——ssh 门控
  条件满足。
- 仓库:rsync 自开发机,**无 `.git` 目录**,本机无法 commit/push;
  本文件留在 `~/foam`,报告全文已贴回总指挥会话。

## 1. 任务 A —— WP-05 msfconsole 补测

命令:`.venv/bin/python -m pytest tests/test_session.py -v -rs`

结果:**48 项,47 通过 1 失败,用时 185.13s**。

```
tests/test_session.py::test_ssh_localhost_password_prompt PASSED  [ 97%]
tests/test_session.py::test_msfconsole_full_flow FAILED           [100%]
=================== 1 failed, 47 passed in 185.13s (0:03:05) ===================
```

### 1.1 ssh 门控测试:真跑,通过 ✓

本机 sshd 在跑且允许口令登录(`_ssh_would_prompt_password()` 探测为真),
`test_ssh_localhost_password_prompt` **真实执行并通过**:真实 ssh 的
`password:` 提示经 PTY `/dev/tty` 路径到达,`wait_pattern` 命中,
`waiting_for_input` 事件的 `prompt_type == "password"` 断言成立。
WP-05 验收 3 在真实平台核销。

### 1.2 msfconsole 门控测试:真跑,失败 —— 根因已定位,附原文

`test_msfconsole_full_flow` 真实启动 `msfconsole -q`,在第一步
`session_read(wait_pattern=r"msf6 >", timeout_seconds=180)` 超时:

```
    s = await tool.session_open("msfconsole -q")  # -q 抑制启动 banner
    sid = s["session_id"]
    r = await tool.session_read(sid, wait_pattern=r"msf6 >", timeout_seconds=180)
>       assert r["matched"] is True
E       assert False is True
```

**不是启动慢,是提示符变了。** 会话落盘原文(输出层全量落盘,26 字节,
`cat -v` 视图,`^[` 即 ESC):

```
^[[?1034h^[[4mmsf^[[0m ^[[0m> 
```

ANSI 清洗后的 LLM 视图即 **`msf > `**。本机 metasploit-framework
**6.4.84** 的提示符是 `msf >`,不是测试等待的 `msf6 >`——上游在 6.4 系
已把提示符从 `msf6` 改回 `msf`。180 秒内提示符早已打印(落盘文件时间
戳与启动几乎同时),测试只是永远等不到字面量 `msf6 >`。

### 1.3 手工全链验证(不改测试,独立脚本走同一路径)

为确认 harness 层无恙,用 harness 公共接口按测试同路径走了一遍,仅把
wait_pattern 换成新版真实提示符(脚本在 /tmp,未入库;全程本机,未触
任何外部目标,`use`+`info` 不触发 listener):

```
session_open ok, sid=s-5c94b1c7dd
[   4.4s] 等 'msf >' matched=True events=[{'type': 'waiting_for_input',
  'prompt_type': 'msf6', 'text': 'msf >',
  'hint': 'msfconsole 提示符就绪,可 session_send 下一条命令(use/set/exploit 等)。',
  'offset': 26}]
[   4.5s] 等模块提示符 matched=True events=[{'type': 'waiting_for_input',
  'prompt_type': 'msf6', 'text': 'msf exploit(multi/handler) >', ... 'offset': 181}]
    模块提示符输出尾部: 'Using configured payload generic/shell_reverse_tcp\nmsf exploit(multi/handler) > '
[   4.5s] info matched=True Payload options=False Name:=True
    info 输出头 200 字节: 'info\n\n       Name: Generic Payload Handler\n     Module: exploit/multi/handler\n   Platform: Android, Apple_iOS, ...'
[   4.5s] close: status=closed sha256=6ca84cc1088cd3e989134331e87cea4d36c88a7301e7538b360bd8c9b63078fc
全链走通
```

真实行为观察(全部如实):

1. **启动耗时**:热缓存下 `msfconsole -q` 从 session_open 到提示符
   识别仅 **4.4s**(首次失败那轮提示符同样在 180s 内早早出现,失败与
   启动速度无关)。arm64 上 ruby 进程 CPU 占用高属正常。
2. **提示符怪癖**:新版提示符带 ANSI 装饰——`ESC[?1034h` 前缀、
   `msf` 加下划线(`ESC[4m`)、`exploit(multi/handler)` 中模块名红色
   高亮。harness 的 ANSI 清洗与提示识别**全部正确处理**:清洗视图
   `msf > `,事件 `prompt_type` 正确归 `msf6` 家族(与 fixture
   `msf > → msf6` 一致),模块切换后 `msf exploit(multi/handler) >`
   同样命中,offset 锚定无重复事件。
3. **info 输出**:新版无 `Payload options` 字样(断言项
   `Payload options=False`),但 `Name:` 在——测试该断言有 `or`
   兜底,换 pattern 后不影响通过。
4. **exit 与收割**:自然退出、状态 `closed`、落盘 sha256 完整。

**结论:harness(会话层/提示库/清洗/落盘)零缺陷;缺陷在测试——
两处 wait_pattern 写死 `msf6 >` / `msf6 exploit\(multi/handler\) >`,
与 metasploit ≥6.4 的真实提示符 `msf >` / `msf exploit(...) >` 不匹配。
修法建议(总指挥定):pattern 放宽为 `msf6? >`、`msf6? exploit\(...`
同时兼容新旧,提示库无需动(它本来就两者都认)。**

## 2. 任务 B —— WP-08 工具盘点 Kali 实测

命令:`.venv/bin/python -m pytest tests/test_toolmap.py -v -rs`

结果:**16 项,15 通过 1 失败,用时 0.38s**。

```
tests/test_toolmap.py::test_scan_real_machine_smoke FAILED        [ 43%]
========================= 1 failed, 15 passed in 0.38s =========================
```

失败即该测试自己预告过的待补项——它硬断言了开发机(macOS)无 dpkg:

```
        # 本机无 dpkg → 明确降级标记;Kali 补测时此项应翻真(验收 4 待补)
>       assert scan.dpkg_available is False
E       AssertionError: assert True is False
```

Kali 上 `dpkg_available` 如实翻真,**探测链本身工作正常**;缺陷仍是
测试把平台假设写死(修法建议:按实际探测断言,或拆成两个平台分支)。
其余 15 项(含 ≤2KB 预算、降级链、注入契约、零品牌名)在 Kali 全绿。

### 2.1 真实盘点结果(独立脚本,`scan_tools()` 无注入)

```
dpkg_available = True
覆盖率 = 96/137 = 70.1%
startup_line: 工具盘点:96/137 可用 [recon 27/33, vuln 12/17, web 10/18,
  password 10/15, sniff 22/29, post 11/17, report 4/8]
via 分布 = {"which": 91, "dpkg": 5}
tool_map 渲染字节数 = 1884   (≤2048 预算 ✓)
```

**覆盖率 = 目录中本机实装比例 = 96/137 ≈ 70.1%。**
探测路径分布:which 直接命中 91、dpkg 包名兜底命中 5(三级探测链的
dpkg 兜底在真实 Kali 首次被验证有效)、路径直查 0。

缺失 41 个,按组摘要(括号内为 apt 包名):

- recon(6):rustscan、naabu、sublist3r、assetfinder、mtr、enum4linux-ng
- vuln(5):joomscan、droopescan、lynis、tplmap、wig
- web(8):feroxbuster、katana、hakrawler、gau、waybackurls、xsstrike、
  arjun、jwt_tool(jwt-tool)
- password(5):crowbar、name-that-hash、cupp、fcrackzip、pdfcrack
- sniff(7):bettercap、mdk4、ghidra、gdb、foremost、steghide、volatility3
- post(6):ncat、rlwrap、chisel、sshuttle、crackmapexec、bloodhound
- report(4):eyewitness、gowitness、dradis、keepassxc

缺失集中在 Go 系新工具(katana/naabu/feroxbuster 等,kali-linux-default
未预装)与 GUI/重型件(ghidra/bloodhound/keepassxc);目录标注的 apt
包名可直达,装不装由 engagement 决定(盘点器不自动装,符合规格)。

## 3. 任务 C —— 首次全量套件在 Kali

命令:`.venv/bin/python -m pytest -q`

结果:**337 项,335 通过 2 失败,用时 192.14s**。

```
........................................................................ [ 21%]
........................................................................ [ 42%]
........................................................................ [ 64%]
........................................................................ [ 85%]
...F...................................F.........                        [100%]
FAILED tests/test_session.py::test_msfconsole_full_flow - assert False is True
FAILED tests/test_toolmap.py::test_scan_real_machine_smoke - AssertionError: ...
2 failed, 335 passed in 192.14s (0:03:12)
```

两个失败即任务 A/B 已定位的两项,**根因均为测试写死了过期环境假设
(旧 msf 提示符字面量、开发机无 dpkg),均非 harness 缺陷**。

除此之外**零新增平台相关失败**:首次在真实 Linux/arm64 目标平台运行,
PTY 三坑(Linux EIO 报 EOF、ctty 获取、被杀/自然退出区分)涉及的全部
用例、输出层分流落盘、哈希链审计、护栏、后端、主环、状态层、工具地图
共 335 项一次全绿。WP-05 关闭时担心的 PTY 平台差异在 Kali 上未出现。

## 4. 缺陷清单(移交总指挥裁决)

| # | 位置 | 现象 | 根因 | 修法建议 |
|---|---|---|---|---|
| D1 | `tests/test_session.py::test_msfconsole_full_flow` | 等 `msf6 >` 180s 超时 | metasploit 6.4 系提示符已改回 `msf >`(落盘原文实证);harness 提示库本身兼容 | wait_pattern 放宽为 `msf6? >` / `msf6? exploit\(...`;无需动 `tools/session.py` |
| D2 | `tests/test_toolmap.py::test_scan_real_machine_smoke` | `assert scan.dpkg_available is False` 在 Kali 翻真 | 断言写死开发机(macOS)无 dpkg | 改为按实际探测断言,或按平台分支;无需动 `agent/toolmap.py` |

两处在 Kali 均为**稳定复现**(任务 A 一次、全量一次,表现一致),非
偶发。修复后预计 Kali 全量 337 项全绿。

## 5. 证据与回传

- 关键原始输出已贴入本文 §1.2/§1.3(pytest 失败段、落盘原文
  `cat -v` 视图、手工验证全链输出、盘点全文、全量尾部)。
- 本会话侧证据副本:`/tmp/kali-retest-evidence/`(msf 会话落盘原文、
  手工验证落盘与日志)、`/tmp/taskA_session.log`、`/tmp/taskB_*.log`、
  `/tmp/taskC_full.log`——均为运行时产物,按契约不入库。
- 本工作区无 `.git`(rsync 未携带),无法执行约定的 commit/push;
  本文件留在 `~/foam/docs/dev-logs/Kali-补测.md`,全文已贴回总指挥会话。

> 总指挥补记(2026-08-22):本文随回传原文入库(仓内路径即
> `docs/dev-logs/Kali-补测.md`);D1/D2 已按建议修复——D1 取
> `msf[56]?`(连 msf5 也覆盖,是建议写法的超集),D2 改平台自适应
> 断言,均见 commit `437c5ce`;D1 的 pytest 形态复跑留下次 Kali 会话
> (WP-12 开工时),D2 修复后两平台同绿已经开发机验证。
