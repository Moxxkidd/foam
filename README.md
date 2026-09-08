# Foam

Kali 原生的 LLM 渗透测试 harness:让大模型直接使用 Kali 的完整工具链,
在明确授权的范围内自主完成渗透测试任务。

模型自行规划攻击路径、选择并驱动工具、处理输出、管理交互会话;
人只需定义授权范围(scope)与目标。类比:Claude Code 之于软件工程,
Foam 之于授权安全测试。

## 实弹验证

以下运行均为 `foam run` 一次启动到底,全程无人工干预,模型未被告知
应使用何种工具:

| 靶场 | 攻击链(模型自主决策) | 轮次 / 耗时 / token | 结果 |
|---|---|---|---|
| Juice Shop(容器) | nmap → ffuf → 登录 SQLi 绕过 → UNION 注入 | 18 轮 / 5m57s / 318k+13k | Users 表 23 行 dump |
| Metasploitable2(docker) | nmap → 自选 UnrealIRCd 后门 → msfconsole 持久 PTY 交互 | 29 轮 / 6m34s / 290k+5k | uid=0 root shell |
| HTB Starting Point Meow(外网) | nmap → 探测挂起后自主切换 PTY 驱动 telnet → root 空密码 | 15 轮 / 8m53s / 102k+2.4k | root flag |

每场 engagement 的审计链均可通过 `foam replay` 逐条重放校验。
汇总战绩表与证据说明:**docs/track-record.md**;未达标项与已知缺陷
如实记录在 **docs/known-issues.md**。

## 核心能力

- **自由 bash + 智能输出层**:LLM 通过 bash 使用 Kali 任意已装工具,
  无需逐工具适配;输出全量落盘并记录 sha256,模型视图为 head+tail
  截断(100MB 级输出下内存占用有界,实测 < 1MB)。
- **持久 PTY 会话**:msfconsole / ssh / sqlmap 等交互式工具的一等
  支持;内置提示识别(password 提示、Y/n 确认、`msf >` 等),命中即
  向模型返回结构化「等待输入」事件。
- **解析增强 + 状态索引**:nmap / sqlmap / gobuster / nikto / hydra /
  whatweb 输出自动解析为原子事实,写入 SQLite 索引(hosts / ports /
  creds / vulns / loot);未识别的工具回退通用路径,不影响执行。
- **scope 护栏**:每条命令先经授权范围校验,越界拒绝并向模型返回
  可行动的纠正说明;放行与拒绝全程留痕。
- **哈希链审计**:append-only JSONL,语义字段级防篡改;`replay`
  先校验后只读重放,链断即拒。

## 法律与边界

Foam 仅用于你拥有**明确书面授权**的安全测试、教学与靶场演练。
scope 护栏用于防止误伤,不构成对恶意使用的约束——目标选择与合规
责任由使用者承担。

## 快速开始

环境:Kali Linux(裸机或 VM),Python ≥ 3.12;运行时依赖仅
httpx / rich / textual(均在 Kali 官方源)。LLM 密钥只走环境变量。

```bash
git clone https://github.com/Moxxkidd/foam && cd foam
pipx install .          # 也可 python3 -m venv 安装

# 1. 定义授权范围(每行一个:CIDR / 主机名 / 通配域 / URL 前缀)
printf '192.168.56.0/24\n' > my.scope

# 2. 配置后端(openai_compat 万能适配;实弹使用 Kimi K3 系)
export FOAM_LLM_API_KEY=... FOAM_LLM_BASE_URL=... FOAM_LLM_MODEL=...

# 3. 运行
foam run --scope my.scope \
  --objective "对 scope 内主机做侦察,汇总存活主机与开放服务"

# 4. 回放与报告
foam replay engagements/<id>
foam report engagements/<id> --out report.md
```

全屏 TUI:`foam tui --scope my.scope`(objective 即首条消息,支持
随时插话;Ctrl-C 触发 kill switch,回收全部活动任务与会话)。

## 命令速览

| 命令 | 作用 |
|---|---|
| `foam run` | headless 执行一个 objective(`--max-rounds` 等兜底阀可调) |
| `foam tui` | 全屏 TUI(连续对话、插话、斜杠命令、侧栏状态) |
| `foam resume <dir>` | 审计链校验 + objective/scope 对账后从现场继续 |
| `foam replay <dir>` | 哈希链校验 + 只读重放审计时间线 |
| `foam report <dir>` | 生成中文 markdown 报告(凭证节为全值,注意去向) |

`fm` 为等价短别名。engagement 运行时产物(原始输出 / loot / 索引库)
不入库(`.gitignore` 拦截)。

## 文档

- 战绩表与证据说明:`docs/track-record.md`
- 实弹报告:`docs/e2e/scenario1-report.md`、`docs/demo/scenario2-report.md`、
  `docs/demo/htb-meow-20260908/`
- 已知问题:`docs/known-issues.md`
- 交接文档(含 23 条已知陷阱与里程碑记录):`docs/HANDOVER.md`
- 规格与逐条核销:`docs/work-packages/`、`docs/spec-verification.md`

## 项目状态

**v0.1.0(2026-09-08)**:13/13 工作包关闭,里程碑门 M1–M4 全部通过,
383 项测试通过。后续分两条线:

- **v0.1.x 维护批**:实战反复验证的审计与核验缺口(会话操作进审计链、
  `foam verify` 子命令、结项证据页等)
- **v0.2 波次**:nftables 网络级出口护栏、多后端 failover、报告模板化、
  meterpreter 语义层等

完整清单见 `docs/HANDOVER.md`「v1 立项清单」节。

## License

GPL-3.0-only,见 `LICENSE`。
