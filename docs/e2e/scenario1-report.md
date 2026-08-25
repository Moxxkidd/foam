# e2e 场景一:结果报告(容器靶场 Web 全链)

> WP-11 产物。执行:2026-08-25,`foam run` headless,后端 openai_compat /
> Kimi K3(`k3`)。环境准备见 `scenario1-setup.md`。
> **engagement 目录:`engagements/wp11-scenario1-20260825/`**(运行时产物,
> gitignored;审计链 56 条,`foam replay` 校验通过)。

## 结果摘要

**目标达成**。agent 全程自主(零人工触碰、零插话)完成:服务识别
(nmap)→ 登录处 SQLi auth bypass 验证 → 搜索接口 UNION 注入 →
Users 表全量 23 行 dump(邮箱 + MD5 口令哈希 + 角色)→ loot 两档
登记入库并落盘可核 → 结论/证据/修复建议写进 ENGAGEMENT.md →
`finished` 收官。

| 指标 | 值(如实记录) |
|---|---|
| 轮次 / 命令 | 18 轮 / 14 条(护栏拒绝 2 条) |
| 耗时 | 约 5 分 57 秒(07:46:14 → 07:52:11 UTC) |
| token | 输入 317,641 / 输出 13,095 |
| 操作员插话 | **0 次**(headless run 无插话通道,只有 kill;未动用) |
| provider 审核事件 | **0 次**(无拦截/无 llm_retry) |
| 护栏拒绝 | 2 次,均为 `[越界: unparseable]`(heredoc 写 ENGAGEMENT.md,
  静态分析取不到目标,fail-closed);模型自行改写成 base64/python -c
  形式后通过——静态护栏对编码载荷的天然天花板,WP-02 绕过面清单
  已在册,本次为真实复现 |
| 主环纠正(claim-correction) | 4 次,全部打在**合法最终总结文本**上
  (总结引用历史已完成动作被启发式误判为幻觉执行;模型甚至补写
  「不声称任何新动作」仍触发)。预算机制(连续 2 次、工具调用重置)
  挡住死循环,但多耗 4 轮 + 约 3.5 万输入 token——见「未达标与
  观察项」 |
| parse_fallback | 1 次 `no_match`:模型的 `nmap -sV … \| tail -20`
  把扫描报告表格截掉,只剩服务指纹尾段,解析器正确判无匹配,
  静默走通用视图——「增强而非门槛」设计按预期工作 |

## loot(索引库登记,路径可核)

| 路径 | 种类 | 大小 | 内容 |
|---|---|---|---|
| `loot/users-table-sqli-dump.json` | dump | 5640 B | UNION 注入 dump
  的 Users 表 23 行(邮箱/MD5 哈希/角色;首行 admin@juice-sh.op) |
| `loot/login-sqli-admin-bypass.txt` | evidence | 365 B | 登录绕过 PoC
  记录(完整响应在 outputs/1069f212981e.log) |

## 未达标与观察项(不隐瞒;HANDOVER 已知问题同步收录)

1. **索引库 hosts/ports/creds/vulns = 0**(loot 2 / notes 1)。原因两层:
   ① 唯一一条 nmap 被模型自己 `| tail -20` 截成不可解析形态
   (parse_fallback no_match,主机/端口 facts 未产生);② creds/vulns
   目前**只能**经解析层 facts 入库——state 工具面只有
   query/add_note/add_loot,模型用 curl 手工打出的注入成果没有
   `state_add_vuln`/`state_add_cred` 可登记。解析覆盖外的手工成果
   进不了索引,这是产品面缺口(M3 参考;是否开登记工具属后续决策,
   本 WP 排除项不改 oracle)。
2. **sqlmap 未被选用**。模型用 curl 直接完成注入与 dump(目标它很熟)。
   预期链的「sqlmap 经 PTY 会话」未发生——目标达成不走剧本,如实记录;
   「全库工具真被用上?」留给 M3 复评(本次用了 nmap/ffuf/curl/
   sha256sum/python3,其中 ffuf 为模型自主选用)。
3. **claim-correction 启发式过发**(4/18 轮)。WP-04 设计内机制 +
   WP-10 live 已记录同类交互;本次样本显示「总结历史动作」是稳定
   误触发形态,建议后续 WP 调启发式或豁免「无新动作声明」的总结段
   (进 HANDOVER 已知问题,不在本 WP 修)。
4. **护栏 fail-closed 对写文件 heredoc 误伤 2 次**(unparseable)。
   模型自救成功(base64 改写),但这同时演示了编码形态可滑过静态
   目标提取——WP-02 在册绕过面的真实案例,非新发现。

## 完整报告(`foam report` 输出,含全时间线)

```markdown
# Engagement 报告:wp11-scenario1-20260825

- 生成时间:2026-08-25T07:57:13+00:00
- engagement 目录:engagements/wp11-scenario1-20260825
- 状态:closed
- 审计链:完整(56 条记录,全链哈希校验通过)

## 统计

- run 1 次 / LLM 18 轮 / 命令 14 条(拒绝 2)/ 插话 0 条 / kill 0 次
- 索引库:hosts 0 / ports 0 / creds 0 / vulns 0 / loot 2 / notes 1
```

> 全量 128 行报告(逐条时间线 seq 1–56、loot 清单带 sha、笔记)
> 可由 `PYTHONPATH=src .venv/bin/python -m foam.cli report
> engagements/wp11-scenario1-20260825` 随时重现;关键片段已并入上文
> 摘要与本文件下节。

### 时间线关键锚点(节选自 `foam report`)

```
[seq   4] $ nmap -sV -p 3000 127.0.0.1 2>&1 | tail -20  [目标: 127.0.0.1]
[seq   5] parse_fallback no_match(tail 截断扫描报告,见观察项 1①)
[seq  10] $ mkdir -p … && ffuf -u 'http://127.0.0.1:3000/FUZZ' …(模型自选 ffuf)
[seq  12] $ curl -X POST …/rest/user/login … ' OR 1=1--(auth bypass 验证)
[seq  15] $ curl …/rest/products/search?q=test')) UNION SELECT … FROM Users--(注入确认)
[seq  20] $ curl …(UNION dump 全表落盘前奏)
[seq  31] 护栏拒绝:cat > ENGAGEMENT.md <<'EOF' …[越界: unparseable]
[seq  33] 护栏拒绝:python3 heredoc …[越界: unparseable]
[seq  35] $ python3 -c base64 写 ENGAGEMENT.md(模型自救通过)
[seq  44] 主环纠正 no_tool_call_action_claim(总结误触发 1/4)
[seq  46] $ sha256sum loot/* && python3 -c json 校验(模型自核 loot)
[seq  49/52/54] 主环纠正(总结误触发 2–4/4)
[seq  56] run 结束:finished,18 轮,tokens 输入 317641 / 输出 13095
```
