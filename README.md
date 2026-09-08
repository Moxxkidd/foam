# Foam

给大模型一把 Kali 的钥匙。

不是把 nmap、msfconsole 包成几个僵硬模板让模型填空——是把**整个**
Kali 工具库直接交给 LLM:它自己看工具地图挑工具、自己开 bash 跑、
自己处理几百 MB 的输出、自己在 msfconsole 里一个命令一个命令敲。
人只干一件事:写清楚授权范围,然后看戏。

类比:Claude Code 之于写代码,Foam 之于**明确授权**的渗透测试。

## 凭什么说它行

先看战绩,再听吹:

| 靶场 | 它自己打出来的链 | 花了多少 | 结果 |
|---|---|---|---|
| Juice Shop(容器) | nmap → ffuf(自己从工具地图翻出来的)→ SQLi 绕过登录 → UNION 注入 | 18 轮 / 5m57s | Users 表 23 行,拖走 |
| Metasploitable2 | nmap → 四个洞选了 UnrealIRCd(不是剧本指定的)→ 开 msfconsole 交互打完 | 29 轮 / 6m34s | root shell |
| HTB Meow(真实外网) | nmap → nc 探测卡死,自己诊断「得用交互会话」→ 切 PTY 开 telnet → root 空密码 | 15 轮 / 8m53s | root flag |

三场全程零人工插手,零提示该用什么工具。每一场的审计链都能
`foam replay` 逐条重放校验——不信自己验。完整战绩表:
**docs/track-record.md**。

当然也有丢人的事,都在 docs/known-issues.md 里写着:护栏误拦过、
索引漏登过、审计链在纯会话阶段断过档。哪条修了哪条没修,白纸黑字。

## 四个安身立命的东西

- **自由 bash + 智能输出层**:模型想用啥工具用啥,不用等我适配。
  输出再大也不怕——全量落盘记 sha256,模型只看掐头去尾的视图,
  100MB 输出内存占用不到 1MB(实测)。
- **持久 PTY 会话**:msfconsole、ssh、sqlmap 的交互提示(password、
  Y/n、`msf >`)都能识别,模型像人一样「等提示符出现再敲下一句」。
  Meow 那场就是靠这个:nc 卡死,它自己判断「这活得交互着干」,
  换 PTY 重开 telnet 一把过。
- **scope 硬护栏**:每条命令先过授权校验,越界直接拒,拒绝和放行
  全进审计。这是底线,不是卖点。
- **哈希链审计**:每个动作 append-only 落链,改一个字就断链。
  打完仗能逐帧回放:模型每一步想了什么、干了什么、被拦了什么。

## 法律与边界(这段不是玩笑)

只准打你有**明确书面授权**的目标:自己的靶场、授权测试、教学环境。
护栏防的是误伤,防不了存心越界的人——目标选错了,责任全是你的。

## 跑起来

Kali Linux,Python ≥ 3.12,运行时依赖就三条(httpx/rich/textual,
Kali 官方源全有)。密钥只走环境变量,永不入仓。

```bash
git clone https://github.com/Moxxkidd/foam && cd foam
pipx install .

# 写授权范围(每行一个:CIDR / 主机名 / 通配域 / URL)
printf '192.168.56.0/24\n' > my.scope

# 开跑
export FOAM_LLM_API_KEY=... FOAM_LLM_BASE_URL=... FOAM_LLM_MODEL=...
foam run --scope my.scope \
  --objective "对 scope 内主机做侦察,汇总存活主机与开放服务"

# 打完回放+出报告
foam replay engagements/<id>
foam report engagements/<id> --out report.md
```

全屏 TUI 也有:`foam tui --scope my.scope`,objective 就是首条消息,
随时插话,Ctrl-C 一键 kill switch。

## 现状

**v0.1.0(2026-09-08 封包)**:13 个工作包全关,383 测试全绿。
后面两条线:v0.1.x 修实战暴露的审计缺口(会话操作进审计链、
`foam verify` 一键核验、结项自动出证据页);v0.2 上大件
(nftables 网络级护栏、多后端 failover、报告模板化……)。
清单全文在 docs/HANDOVER.md——那份文档还记着开发过程踩过的
23 条坑,比 README 好看。

## License

GPL-3.0。拿去打该打的靶子。
