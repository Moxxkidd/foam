# Foam

Foam 是一个 **Kali 原生的 LLM 渗透 harness**:让大模型与 Kali 整个工具
生态有机结合——不是把几个工具包成僵硬的模板,而是给 LLM 一个为重型安全
工具专门设计的运行环境。类比:Claude Code 之于软件工程,Foam 之于
**明确授权**的安全测试。

差异化锚点:

- **自由 bash + 智能输出层**:LLM 经 bash 使用 Kali 里任何工具;输出
  全量落盘并记 sha256,LLM 视图 head+tail 截断(100MB 级输出内存有界)。
- **持久 PTY 交互会话**:msfconsole/ssh 这类交互工具的一等公民;内置
  提示识别(password 提示、yes/no、msf 提示符、sqlmap Y/n),命中即给
  LLM 结构化「等待输入」事件。
- **解析增强 + 状态索引**:nmap/sqlmap/gobuster/nikto/hydra/whatweb 输出
  自动解析入 SQLite 索引(hosts/ports/creds/vulns/loot/notes);增强而非
  门槛——不认识的工具走通用路径照跑。
- **scope 硬护栏**:每条命令先过授权范围校验;越界拒绝并给 LLM 可行动
  的纠正说明,拒绝与放行全程进审计。
- **全程哈希链审计可回放**:append-only JSONL,语义字段级防篡改,篡改即
  断链;`replay` 校验先行、只读重放,绝不回放不可信历史。

## 法律与边界

Foam 仅服务于**你对目标拥有明确书面授权**的安全测试、教学与靶场演练。
scope 护栏是产品底线而非可选项。使用者对目标选择与合规负全责。

## 运行环境

- Kali Linux(裸机/VM;实弹与安装实测:Kali rolling arm64,Python 3.13.7),
  Python ≥ 3.12。运行时依赖仅三条:httpx / rich / textual(均在 Kali 官方源)。
- LLM 后端二选一(密钥只走环境变量,永不入仓):
  - `openai_compat`(默认):`FOAM_LLM_API_KEY` + `FOAM_LLM_BASE_URL` +
    `FOAM_LLM_MODEL`——OpenAI 兼容端点万能适配,实弹用的是 Kimi K3 系。
  - `claude`:`FOAM_ANTHROPIC_API_KEY`(Anthropic Messages,httpx 直连)。

## 安装

```bash
git clone <repo> && cd foam
pipx install .        # 推荐;Kali 源内自带 pipx
# 或:python3 -m venv .venv && .venv/bin/pip install .
```

命令:`foam`(短别名 `fm`)。全新环境安装实测(Kali pipx / Mac venv 双
平台,含双场景 replay 与真实后端冒烟)见 `docs/demo/walkthrough.md` §3。

## Quickstart

1. 写 scope 授权文件(每行一个:CIDR / 主机名 / `*.` 通配域 / URL 前缀;
   示例见 `scopes/lab.scope`):

   ```bash
   printf '192.168.56.0/24\n' > my.scope
   ```

2. headless 跑一个 objective:

   ```bash
   foam run --scope my.scope \
     --objective "对 scope 内主机做侦察,汇总存活主机与开放服务" \
     --backend openai_compat
   ```

3. 回放与报告:

   ```bash
   foam replay engagements/<id>     # 哈希链校验先行,链断拒放
   foam report engagements/<id> --out report.md
   ```

4. 全屏 TUI(连续对话、思考块折叠、紧凑工具卡、侧栏状态、插话与斜杠命令):

   ```bash
   foam tui --scope my.scope --backend openai_compat   # objective = 主界面首条消息
   ```

5. 中断与恢复:Ctrl-C 一次 = kill switch(杀活动 job/会话、写审计、退出码
   130),再按一次强制退出;`foam resume engagements/<id>` 从审计链校验过的
   现场继续(最近 N 轮简报,非全量回放)。

## 双场景实弹摘要

2026-08-25/26,Kimi K3 系后端,`foam run` 一次启动到底,全程零人工触碰、
零插话;2026-08-27 双场景 replay 复核双双 exit 0。

| 场景 | 链(模型自主,无剧本) | 收官 | 指标 |
|---|---|---|---|
| 场景一:容器靶场 Web 全链(Juice Shop @ 127.0.0.1:3000) | nmap → ffuf(工具地图自荐)→ 登录 SQLi auth bypass → 搜索接口 UNION 注入 → Users 表 23 行 dump 与 PoC 两档 loot | finished,审计链 56 条 | 18 轮 / 5m57s / token 输入 317,641 / 输出 13,095 |
| 场景二:Metasploitable2 + msfconsole(172.17.0.3) | nmap 全端口 25 口(解析层自动入库 hosts 1/ports 25)→ **自选** UnrealIRCd 后门(非剧本首选)→ 持久 PTY 驱动 msfconsole use/set×4/exploit 一击成功 → root shell 内 id/uname 取证落 loot | finished,审计链 49 条 | 29 轮 / 6m33.7s / token 输入 290,166 / 输出 5,227 |

- 报告与走查:`docs/e2e/scenario1-report.md`、`docs/demo/scenario2-report.md`、
  `docs/demo/walkthrough.md`
- 未达标项不隐瞒(索引缺口、护栏误报形态、会话审计断档等):
  `docs/known-issues.md`

## 命令速览

| 命令 | 作用 |
|---|---|
| `foam run` | headless 跑一个 objective(新 engagement;`--max-rounds`/`--max-context-tokens` 等兜底阀可调) |
| `foam tui` | 全屏 TUI(迎宾呼号门 → 主界面;scope/backend 走参数,objective 走首条消息) |
| `foam resume <dir>` | 链验 + objective/scope 对账后从现场继续(drift 拒绝,显式 `--scope` 视为重新授权) |
| `foam replay <dir>` | 哈希链校验 + 只读重放审计时间线(链断报首个断点 seq) |
| `foam report <dir>` | 中文 markdown 报告(索引库 + ENGAGEMENT.md + 审计链;凭证节为全值,注意去向) |

`fm` 为等价短别名。engagement 运行时产物(工具原始输出/loot/索引库)
永不入库(`.gitignore` 拦截)。

## 文档地图

- 交接与当前状态:`docs/HANDOVER.md`(含 23 条已知陷阱、里程碑门、v1 立项清单)
- 工作包台账:`docs/wp-ledger.md`(13 份规格状态 + M1–M4 门口记录)
- 规格与核销:`docs/work-packages/WP-01`–`WP-13`;逐条核销表 `docs/spec-verification.md`
- 开发日志:`docs/dev-logs/`(每 WP 一份,含真实命令输出)
- 场景与演示:`docs/e2e/`(环境准备 + 场景一报告)、`docs/demo/`(走查 + 场景二报告)
- 已知问题总表:`docs/known-issues.md`

## 状态与路线图

Pre-alpha(v0.0.1):13/13 工作包全部关闭,里程碑门 M1–M4 全放行,项目
发布就绪。v1 立项方向(完整优先级排序见 `docs/HANDOVER.md`「v1 立项
清单」):nftables 网络级出口护栏、会话操作审计补齐、护栏目标提取器
改进、state 登记面补全、claim-correction 误报治理、多后端 failover、
报告模板化、meterpreter 语义层、跨 engagement 经验库……

## License

GPL-3.0-only,见 `LICENSE`。
