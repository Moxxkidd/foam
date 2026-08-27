# 演示走查记录 —— 双场景回放(WP-13 演示材料,操作记录文本)

> 规格口径:「asciinema 录屏或操作记录文本二选一」——本文件取**操作记录文本**
> 路线(零新增依赖,命令均可原样复演)。素材来自两次实弹的 engagement 目录
> 与 replay/report 输出,**未重新实弹**。
>
> 复核人:WP-13 执行会话;复核日:2026-08-27;复核环境:macOS 开发机 +
> Kali rolling arm64(安装冒烟)。所有命令退出码与输出均为当日真实复核实录。

## 0. 复演命令(任何人可原样执行)

```bash
# 仓内(开发机)
PYTHONPATH=src .venv/bin/python -m foam.cli replay  engagements/wp11-scenario1-20260825
PYTHONPATH=src .venv/bin/python -m foam.cli replay  engagements/wp12-scenario2-20260826
PYTHONPATH=src .venv/bin/python -m foam.cli report  engagements/wp12-scenario2-20260826 \
    --out docs/demo/scenario2-report.md
# 安装后(Kali pipx / Mac venv):foam replay <dir> / foam report <dir>
```

engagement 目录为运行时产物(gitignored,不入库);场景一报告已入库
`docs/e2e/scenario1-report.md`,场景二报告由上面的命令现生成
`docs/demo/scenario2-report.md`(116 行,凭证节「无凭证记录」)。

## 1. 场景一:容器靶场 Web 全链(WP-11,2026-08-25 实弹)

- objective:对 127.0.0.1:3000(Juice Shop)完整渗透:识别服务、枚举 Web
  资产、找到注入点实际验证、取数据库样例落 loot。
- 后端:openai_compat / Kimi K3;启动方式:`foam run` 一次启动到底。
- **复核:`foam replay` → 「审计链完整,56 条记录」exit 0**(与 M3 监理
  独立复验一致)。

关键时间线(seq 号为审计链序号,全文见 replay 输出):

| seq | 事件 | 看点 |
|---|---|---|
| 1–2 | scope 加载(lab.scope:2 CIDR+1 主机+1 URL 前缀)→ run 启动 | 授权先行 |
| 4–5 | `nmap -sV -p 3000 … \| tail -20` → `parse_fallback no_match` | 模型自截断输出致解析器静默回退(M3 挂账③),通用路径照跑不炸 |
| 10 | `ffuf -u http://127.0.0.1:3000/FUZZ …` | **ffuf 不在预期链上,模型从工具地图自荐**(1+1≫2 实证之一) |
| 12–13 | 登录接口 `' OR 1=1--` SQLi auth bypass → exit 0 | 注入点一:认证绕过 |
| 15–16 | 搜索接口 `')) UNION SELECT id,email,password,… FROM Users--` | 注入点二:UNION 取数 |
| 20–21 | 全量 dump 落 loot | Users 表 23 行(邮箱+哈希+角色) |
| 28–29 | PoC 写 loot/login-sqli-admin-bypass.txt | loot 两档齐 |
| 31/33 | **护栏拒绝 ×2**(`[越界: unparseable]`,heredoc 写笔记) | fail-closed;模型自行改写 base64/python -c 形式通过(seq 35–39)——WP-02 绕过面清单的真实复现 |
| 44/49/52/54 | 主环纠正 ×4(`no_tool_call_action_claim`) | 全部打在合法总结文本上(M3 挂账② 稳定误触发实录) |
| 56 | `run 结束:finished,18 轮,tokens 输入 317641 / 输出 13095` | 全程 5m57s,零人工零插话 |

复核对账(2026-08-27,sqlite3 直查):loot 表 2 行 ↔ 盘上两文件
(`users-table-sqli-dump.json` 23 行用户数据、`login-sqli-admin-bypass.txt`
PoC);hosts/ports/creds/vulns 四表 = 0(未达标项,已如实收录 → M3 挂账①③)。

## 2. 场景二:Metasploitable2 + msfconsole 交互拿 shell(WP-12,2026-08-26 实弹)

- objective:对 scope 内靶机(172.17.0.3/32,scopes/ms2.scope)自主渗透
  拿 shell 并取证;持久 PTY 驱动 msfconsole 完成 use/set/exploit。
- 后端:openai_compat / k3-256k;Kali 实弹,Mac 经 SSH(BatchMode)协调。
- **复核:`foam replay` → 「审计链完整,49 条记录」exit 0**(与 M3 复验一致)。

关键时间线:

| seq | 事件 | 看点 |
|---|---|---|
| 4–5 | `nmap -sV -sC -p- --min-rate=2000 172.17.0.3`(166.8s) | 25 个开放端口,**解析层自动入库 hosts 1 / ports 25 带指纹**(场景一索引空表缺口未复现) |
| 10/12 | **护栏拒绝 ×2**(`[越界: 4.7p1,3.2.8.1]` / `[越界: 4.7p1]`) | 服务版本号被误判为越界 IP(WP-02 提取器新误报形态,M3 挂账⑦);模型改写笔记措辞后 seq 14 通过 |
| 16–33 | 纯 LLM 交换段(msfconsole 交互期) | **会话操作本就不入审计链**(M3 挂账④,replay 时间线在此只剩 LLM 交换元记录——如实呈现);模型**自选 UnrealIRCd 后门**(非剧本首选 vsftpd,四选一决策) |
| 34–35 | msf 会话转录 `cp … outputs/sessions/s-c63f47bf19.log → loot/` | use/set×4/exploit **一击成功**;root shell 内 `id`/`uname -a` 取证 |
| 41 | 主环纠正 ×1(总结段误触发) | 模型以真实二次核验响应 |
| 49 | `run 结束:finished,29 轮,tokens 输入 290166 / 输出 5227` | 全程 6m33.7s,零人工零插话零 kill |

复核对账(2026-08-27):loot 表 1 行 ↔ `loot/msf-unrealircd-session.log`;
`grep -n 'uid=0'` 命中**行 42 与行 70**:`uid=0(root) gid=0(root)
groups=0(root)`(与 WP-12 台账记录逐字一致);hosts 1 / ports 25。
提示识别生产实证:真实转录字节离线复演 `detect_prompt` 12 命中/6 位置
(含 metasploit 6.4.84 无版本号 `msf >`,陷阱 16 再坐实,记录见
docs/dev-logs/WP-12.md 验收 3 节)。

## 3. 安装后冒烟摘录(发布 checklist 证据,2026-08-27)

Kali rolling arm64(Python 3.13.7,pipx 1.7.1),干净目录自 git HEAD
archive 安装(`~/foam` rsync 副本全程未碰):

```
$ pipx install /home/doma/foam-install-test
  installed package foam 0.0.1, installed using Python 3.13.7
  These apps are now globally available: fm, foam
$ foam replay eng-smoke/wp11-scenario1-20260825   → 审计链完整,56 条记录(exit 0)
$ foam replay eng-smoke/wp12-scenario2-20260826   → 审计链完整,49 条记录(exit 0)
$ <pipx venv python 直调后端,env 取 ~/.zshenv 三变量>
  first-event=6.73s total=8.03s reply='就绪' reasoning_chars=142
  usage: in=91 out=47
```

Mac 对照组:`git clone --depth 1 file://<repo>` + Homebrew Python 3.12.14
venv + `pip install`(需先摘除本机失效代理 env,陷阱 4/20 族):安装成功,
双场景 replay 均 exit 0。系统 python3=3.9.10 被 `requires-python>=3.12`
正确拒装(版本地板生效)。

## 4. 链接

- 场景一报告(入库):`docs/e2e/scenario1-report.md`
- 场景二报告(现生成):`docs/demo/scenario2-report.md`
- 场景环境准备:`docs/e2e/scenario1-setup.md`、`docs/e2e/scenario2-setup.md`
- 13 份规格逐条核销:`docs/spec-verification.md`
- 实弹全记录:`docs/dev-logs/WP-11.md`、`docs/dev-logs/WP-12.md`
