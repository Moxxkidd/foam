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
- **scope 护栏**:每条 `run_command` 先经授权范围校验,越界拒绝并向模型
  返回可行动的纠正说明;放行与拒绝全程留痕。
- **哈希链审计**:append-only JSONL,语义字段级防篡改;`replay`
  先校验后只读重放,链断即拒。
- **证据清单与只读核验**:run 终态自动生成 manifest 与结项页;`verify`
  分别核验审计链、产物 hash、证据引用和覆盖状态,不改被检查数据。

**边界**:PTY 会话命令与输入不经过 `run_command` 的命令级 scope 检查;
审计可见不等于授权隔离。v0.2.0 的 protected 网络边界仅支持以 root 启动的
Linux 与 CIDR scope,不支持 raw socket/AF_PACKET 或入站监听;创建、恢复或换代
失败会停止,不静默回退 legacy。真实 Kali 的受支持安装与 protected 用户旅程
尚未验收并明确延期,既有 Docker/linuxkit 结果不冒充 Kali。本地哈希链也未外部
锚定,不能证明未截尾或整体重写。

## 法律与边界

Foam 仅用于你拥有**明确书面授权**的安全测试、教学与靶场演练。
scope 护栏用于防止误伤,不构成对恶意使用的约束——目标选择与合规
责任由使用者承担。

## 快速开始

环境:Kali Linux(裸机或 VM),Python ≥ 3.12;运行时依赖仅
httpx / rich / textual(均在 Kali 官方源)。LLM 密钥只走环境变量。

```bash
git clone https://github.com/Moxxkidd/foam && cd foam
pipx install .          # pipx 仅用于 legacy;protected 见下文

# 1. 配置后端(openai_compat 万能适配;实弹使用 Kimi K3 系)
export FOAM_LLM_API_KEY=... FOAM_LLM_BASE_URL=... FOAM_LLM_MODEL=...

# 2. 显式选择传统执行路径并启动 TUI,首条消息声明目标与授权范围
foam tui --execution-mode legacy
#    → 确认卡展示编译出的 scope 规则(canonical 形态 + sha256 短哈希):
#      确认冻结 / 用自然语言修正重编译 / 取消;确认后冻结进审计链
#    → 运行中随时 /scope 查看当前规则,/scope <描述> 经同一仪式修改

# 3. 回放、证据核验与报告
foam replay engagements/<id>
foam verify engagements/<id>          # 人读;--json 输出机读结果
foam report engagements/<id> --out report.md
# 分享视图只脱敏凭证节,其余章节仍须人工审阅:
foam report engagements/<id> --redact --out report-share.md
```

`run` / `resume` / `tui` 必须显式给 `--execution-mode protected` 或
`--execution-mode legacy`;不从环境变量或 profile 猜测。legacy 仅提供
Bash 参数级护栏,不做网络强制,工具继承完整环境,已有连接不随 scope
撤销。protected 当前仅支持已以 root 启动 Foam 的 Linux,且 scope 只能
含 CIDR;创建或换代失败会停止执行,绝不自动回退 legacy。protected 的
`/scope` 换代会作废旧 job/PTY 并终止其已有连接,成功后才恢复新派发。

headless/CI 场景可用 scope 文件(零确认仪式,行为照旧;每行一条:
CIDR / 主机名 / 通配域 / URL——URL 规则按规范化 origin(scheme/host/
有效端口)匹配,再按路径前缀收窄;畸形 URL 目标与畸形 URL 规则一律拒绝;
protected 不支持其中的主机名、通配域或 URL):

```bash
printf '192.168.56.0/24\n' > my.scope
foam run --execution-mode legacy --scope my.scope \
  --objective "对 scope 内主机做侦察,汇总存活主机与开放服务"
# 或一句话声明(headless 非交互自动确认,编译结果上屏+落审计):
foam run --execution-mode legacy \
  --scope-text "仅限 192.168.56.0/24 网段" --objective "..."
```

全屏 TUI 也接受 `foam tui --execution-mode legacy --scope my.scope`
(文件流零仪式照旧);TUI 内 objective 即首条消息,支持随时插话;
Ctrl-C 触发 kill switch,回收全部活动任务与会话。

## protected 安装

pipx 仅用于 legacy;用户目录中的解释器或 helper 源可被普通用户修改,
不满足 protected 的受信启动路径要求。protected 的受支持安装约定是由 root
在 `/opt/foam` 创建 venv 并安装发布 wheel,不要用 pipx、`sudo pip` 直接写系统
Python 或源码目录代替:

```bash
sudo python3 -m venv /opt/foam
sudo /opt/foam/bin/pip install /path/to/foam-0.2.0-py3-none-any.whl
```

`/opt`、`/opt/foam`、venv 解释器的解析路径以及安装后的 helper 源路径必须
逐级 root 所有且非组/他人可写;Foam 启动 helper 前仍会逐项检查,不信任
文档或目录名本身。禁止用 `sudo -E`、`--break-system-packages`、chmod/chown
或其他放宽权限的办法绕过拒绝。

启动时只用 sudo 白名单传递四个变量,不把整个调用者环境带入 root 控制面:

```bash
export FOAM_LLM_API_KEY=... FOAM_LLM_BASE_URL=... FOAM_LLM_MODEL=...
sudo --preserve-env=FOAM_LLM_API_KEY,FOAM_ANTHROPIC_API_KEY,FOAM_LLM_MODEL,FOAM_LLM_BASE_URL \
  /opt/foam/bin/foam tui --execution-mode protected
```

这些密钥只进入 Foam 控制面;R11 的工具最小环境保证不把它们传给工具进程。
protected 产生的 engagement 保持 root 所有、0700,不 chown 给调用用户,
以免 root 后续 tmp+rename 写入引入符号链接/TOCTOU 提权面。读取报告与只读
核验也使用同一安装路径经 sudo 执行:

```bash
sudo /opt/foam/bin/foam report engagements/<id> --out report.md
sudo /opt/foam/bin/foam verify engagements/<id>
```

`.env` 的查找位置是当前工作目录的 `.env`,不是 `HOME` 或 `/opt/foam`;
它在 Foam 启动后只读注入缺省环境变量,不覆盖已有同名变量。sudo 后的
`HOME` 以及 profile(`~/.foam/config.json`)实际指向 root 还是调用用户,
取决于系统/sudoers 配置,**尚未在真实 Kali 实测**;上述示例不依赖 profile,
不要预设 sudo 后仍能读到调用用户的配置。

`doctor` 已有 R13-B 只读诊断与 protected/无权限处置,`status` 已接入 R13-C
心跳活性与运行结局。R13 分片已完成不代表 protected 安装已验证:本小节只发布
R29-A 安装约定与诊断说明。真实 Kali 的干净系统安装、sudo、wheel 与 protected
run/resume/verify 均未验证;用户已明确裁定 R29-B 延期,不自动指定后续版本。

## v0.2.0 已知边界

- 旧版本 TUI 不持单写者锁,不能与新版形成互斥;不得手删 `engagement.lock`。
- macOS 进程身份使用秒级启动时间,同秒 PID reuse 仍可能误认;
  `test_status_pid_reuse_and_stale` 有高负载时间敏感间歇失败记录。
- R14-A/B/D 只覆盖收窄的笔记上下文、已定位总结框架/命令与权限证据;其他表达
  保持保守或通用路径。真实 token 节省(R22)与真实能力失败频率(R30)未证。
- 本版没有新 SQLite schema;`heartbeat.json` 是独立 0600 活性快照,R14-C 的
  JobExitEvent 新字段在末尾提供默认值。既有 v4 索引迁移与备份规则不变。

## 配置持久化

后端、模型与 base-url 可存为命名 profile,免去每次重给;存于
`~/.foam/config.json`(写入后权限 0600,与 TUI 呼号同文件、互不影响)。
`run` / `resume` / `tui` 均支持 `--profile` 与 `--save-profile`;
执行模式仍需每次显式选择,不写入 profile:

```bash
# 本次装配成功后存为 profile,并记为默认(之后不带参数即沿用)
foam run --execution-mode legacy --scope my.scope \
  --objective "..." --save-profile k3

# 显式选用某个 profile
foam run --execution-mode legacy --scope my.scope \
  --objective "..." --profile k3
```

profile 生效时启动行打印 `[config] profile 'k3':backend=… model=…`
以便核对。解析优先级:CLI 参数 > 环境变量(`FOAM_LLM_MODEL` /
`FOAM_LLM_BASE_URL`;`--backend` 无环境变量通道)> profile
(`--profile` 指定,否则默认 profile)> 内置默认。

当前目录的 `.env` 会在启动时注入环境变量(不覆盖已存在的同名变量);
注入成功时打印 `[config] .env 注入 N 个变量:…`,只列键名、绝不
打印值。**API key 仍只走环境变量**:foam 读 `.env` 但永不写它;
profile 白名单只存 backend / model / base_url 三项,任何
key/token/secret 字样的键一律剔除、不落盘。

## 命令速览

| 命令 | 作用 |
|---|---|
| `foam run` | headless 执行一个 objective(`--max-rounds` 等兜底阀可调) |
| `foam tui` | 全屏 TUI(NL scope 确认仪式 + `/scope` 热换;连续对话、插话、斜杠命令、侧栏状态) |
| `foam resume <dir>` | 审计链校验 + objective/scope 对账后从现场继续 |
| `foam replay <dir>` | 哈希链校验 + 只读重放审计时间线 |
| `foam verify <dir>` | 只读核验证据;0=pass,1=fail,2=使用错误,3=unknown/pending |
| `foam doctor` | R13-B 只读诊断配置/后端/工具/workdir/protected;默认零网络,`--online` 仅 DNS/TCP/TLS |
| `foam status <dir>` | 只读显示运行结局与心跳活性(alive/stale/gone/unknown/none)、最近活动与 manifest/索引 |
| `foam report <dir>` | 生成中文 markdown 报告;默认凭证全值,`--redact` 仅脱敏凭证节 |

`fm` 为等价短别名。engagement 运行时产物(原始输出 / loot / 索引库)
不入库(`.gitignore` 拦截)。

## 文档

- 当前候选、迁移/回退与发布证据:`docs/releases/v0.2.0.md`
- R 条目规格与逐条验收:`docs/items/README.md`
- 战绩表与证据说明:`docs/track-record.md`
- 实弹报告:`docs/e2e/scenario1-report.md`、`docs/demo/scenario2-report.md`、
  `docs/demo/htb-meow-20260908/`
- 已知问题:`docs/known-issues.md`
- 交接文档(含已知陷阱与里程碑记录):`docs/HANDOVER.md`
- 历史 WP 规格与核销:`docs/work-packages/`、`docs/spec-verification.md`

## 项目状态

**v0.2.0 候选准备中,待发布**:包含 R10 研究结论、R11 Linux protected
执行边界、R12 预算与恢复、R13 doctor/status、R14 误报/等待/能力解释改进及
R28 TUI 单写者锁。R29-B 真实 Kali 验收经用户明确授权延期;本版只含 R29-A
文档与诊断约定,不宣称真实 Kali 安装或 protected 用户旅程已验证。候选三门、
CI、构建与安装验收仍在本次执行,详见 `docs/releases/v0.2.0.md`。

上一正式发布为 **[v0.1.3](https://github.com/Moxxkidd/foam/releases/tag/v0.1.3)**
(2026-10-24):包含 R06–R09 并承接未单独发布的 v0.1.2(R01–R05)全部变更。
annotated tag 指向 `fad75d9`,wheel/sdist/SHA256SUMS 已上传并下载回验;完整
记录见 `docs/releases/v0.1.3.md`。

- v0.1.2 不补打历史 tag,其剩余版本级验收由 v0.1.3 承接。
- 历史发布:v0.1.0 有 GitHub release;v0.1.1 仅有 tag,且当时包元数据
  仍为 0.1.0。历史 tag 不改动,异常记录于 `docs/releases/v0.1.2.md`。

## License

GPL-3.0-only,见 `LICENSE`。
