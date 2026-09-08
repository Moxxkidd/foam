# 战绩表(Track Record)

> Foam 的实弹记录汇总。每场均可复现:engagement 运行时产物(审计链
> `audit.jsonl`、loot、工具原文输出)按纪律 gitignored 不入库——审计链
> 哈希链 + 报告内 sha256 清单即防篡改证据;持有副本者可用 `foam replay
> <engagement_dir>` 只读重放校验。截图与报告原文入库,IP/flag 公开版
> 脱敏。

| # | 靶场 | 攻击链(模型自主,无剧本) | 指标 | 战果 | 证据 |
|---|---|---|---|---|---|
| 1 | **Juice Shop**(容器,127.0.0.1:3000)2026-08-25 | nmap → ffuf(工具地图自荐)→ 登录 SQLi bypass → UNION 注入 | 18 轮 / 5m57s / 318k+13k token | Users 表 23 行 dump,2 件 loot | 审计 56 条 replay exit 0;`docs/e2e/scenario1-report.md` |
| 2 | **Metasploitable2**(docker)2026-08-26 | nmap → 自选 UnrealIRCd 后门 → msfconsole 持久 PTY(use/set×4/exploit) | 29 轮 / 6m34s / 290k+5k token | uid=0 root shell,session 全文落 loot | 审计 49 条 replay exit 0;`docs/demo/scenario2-report.md` |
| 3 | **HTB Starting Point「Meow」**(真实外网靶机)2026-09-08 | nmap 全端口 → nc 探测挂起自主诊断 → 切 PTY 会话驱动 telnet → login 提示识别 → root 空密码 | 15 轮 / 8m53s / 102k+2.4k token | root flag + uid=0,零插话零纠正 | 审计 28 条哈希链经安装体 `verify()` 独立复核 PASS;`docs/demo/htb-meow-20260908/` |

共同口径:全程零人工触碰工具(仅自然语言 objective);loot 路径逐一
落盘带 sha256;每场的未达标项与走偏如实写入对应报告(`docs/known-issues.md`
汇总)。靶场均为教学/授权级,难度上限声明见各报告。
