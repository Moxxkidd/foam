# 规格核销表 —— 13 份规格验收条款 × 实现逐条核销(WP-13 产出)

> 核销口径:**✅ 达标**(证据可点)/ **🟡 降级达标**(偏差如实记录,有 v1 去向)/
> **❌ 未达标**(摆上台面,M4 裁决输入)。**⏳** = WP-13 自核销行,关闭时由本 WP 产物兑现。
>
> 证据代码:**S**=源码(文件:行)、**T**=测试(文件,括号=测试函数数)、
> **L**=开发日志(docs/dev-logs/ 节)、**E**=engagement 产物(路径/命令+exit)、
> **G**=里程碑门口记录、**K**=Kali 补测(docs/dev-logs/Kali-补测.md 及各日志补测节)、
> **W13**=本 WP 现场复核(2026-08-27,输出实录见 docs/dev-logs/WP-13.md)。
>
> 测试基线:全仓 **383 passed + 2 skipped**(环境门控,2026-08-27 复跑 40.82s,exit 0);
> ruff `All checks passed!`。2 个 skip 即 WP-05 的 ssh/msfconsole Mac 侧环境门控,
> 均已经 Kali 实机核销(见 WP-05 行)。

## WP-01 exec 层 + 智能输出层(closed 2026-08-20)

| # | 验收条款(缩写) | 现状 | 证据 | 备注/v1 去向 |
|---|---|---|---|---|
| 1 | 单测全绿:截断字节账目精确、分页与全量落盘一致、sha256、timeout、后台 kill | ✅ | T:tests/test_bash.py(19)+test_output.py(12),383 基线全绿;L:WP-01 | |
| 2 | 长跑命令后台化前台不阻塞 | ✅ | T:test_bash.py 后台 job 用例;L:WP-01 | |
| 3 | 二进制/乱码不崩(错误替换),100MB 级内存可控 | ✅ | T:test_output.py(ring buffer 有界);L:WP-01(100MB 实测 Python 峰值 0.80MB) | |
| 4 | 开发日志记录真实 pytest 输出 | ✅ | L:WP-01(含真实输出 3 处) | |

## WP-02 scope 护栏 v0 + 哈希链审计(closed 2026-08-20)

| # | 验收条款(缩写) | 现状 | 证据 | 备注/v1 去向 |
|---|---|---|---|---|
| 1 | scope 解析表驱动单测(CIDR/通配域/URL 前缀/注释空行) | ✅ | T:tests/test_scope.py(23);L:WP-02 | |
| 2 | 命令目标提取(常见 flag+裸位置参数),误判案例进日志 | ✅ | S:guard/scope.py `extract_targets`;L:WP-02 误判案例 | 生产新误报形态(版本号误判越界 IP,场景二 2 次 fail-closed)= M3 挂账⑦ → v1 提取器改进 |
| 3 | 越界拒绝+`exec_denied` 审计,合法命令不受影响 | ✅ | T:test_scope.py/test_audit.py;E:场景一 replay seq31/33、场景二 seq10/12 护栏真实拒绝(fail-closed 生产实证) | |
| 4 | 篡改任一记录任一字节 verify 必失败;1 万条追加 <1s | ✅ | T:test_audit.py(17);E:WP-10 live 篡改断点 seq=9 精确命中(L:WP-10);W13:现场复测 append 10k 条 0.118s、verify True 0.058s | |
| 5 | 日志含真实 pytest 输出与绕过面清单 | ✅ | L:WP-02(绕过面清单完整) | 绕过面根治=网络出口级强制,spec 已明示 v1 立项(nftables) |

## WP-03 LLM 后端(closed 2026-08-20)

| # | 验收条款(缩写) | 现状 | 证据 | 备注/v1 去向 |
|---|---|---|---|---|
| 1 | 契约测试:OpenAI/Anthropic 两格式归一化事件逐字节相同 | ✅ | T:tests/test_backends.py(20);L:WP-03 | |
| 2 | 错误分类单测(超时/5xx/审核 4xx → 正确错误类型) | ✅ | T:test_backends.py;L:WP-03 | |
| 3 | 配置单测:base_url/model/env key 注入;缺 key 报错不含 key 片段 | ✅ | T:test_backends.py 脱敏专项;L:WP-03 | |
| 4 | 日志含 K3 实测(纪律+审核)与其余后端连通性记录 | 🟡 | L:WP-03(Kimi K3 实测完整:参数合法 JSON 率 100% 15/15、审核拦截 0/8、首事件延迟中位 ~4.3s);Claude 及 DeepSeek/GLM/OpenRouter 无凭据未实测,日志如实记录 | 偏差=「其余后端连通性」无凭据未测 → v1 多后端 failover 项一并处理 |

## WP-04 agent 主环(closed 2026-08-21)

| # | 验收条款(缩写) | 现状 | 证据 | 备注/v1 去向 |
|---|---|---|---|---|
| 1 | 合成 e2e:fake 后端跑无害命令,审计链完整、scope 校验被调用、finish | ✅ | T:tests/test_loop.py(24);L:WP-04;G:M1 真实 K3 补跑(L:WP-04「补跑」节:195 起) | |
| 2 | 越界 e2e:拒绝+纠正说明回消息流+exec_denied | ✅ | T:test_loop.py;E:M1 补跑/场景一/场景二护栏真实拦截后模型据纠正说明改写自救 | |
| 3 | 压缩单测:压缩顺序与 system/ENGAGEMENT.md 保留 | ✅ | T:test_loop.py;L:WP-04 | |
| 4 | 插话/kill/pause 单测 | ✅ | T:test_loop.py;L:WP-04;更正当 idle-wake 后 24 项零改动通过(L:WP-09 更正当节) | claim-correction 对「总结历史动作」稳定误触发(场景一 4 次/场景二 1 次)= M3 挂账② → v1 |
| 5 | system prompt 快照:含授权声明与红线,零品牌名 | ✅ | T:tests/test_prompts.py(6);W13:`git grep "Foam" -- src/` 零命中 | |
| 6 | 日志记录真实 pytest 输出 | ✅ | L:WP-04 | |

## WP-05 持久 PTY 会话层(closed 2026-08-21)

| # | 验收条款(缩写) | 现状 | 证据 | 备注/v1 去向 |
|---|---|---|---|---|
| 1 | 单测:python -i 多轮/cat 回显/超时关闭/提示识别 fixture 命中不误报 | ✅ | T:tests/test_session.py(27);L:WP-05 | |
| 2 | PTY 输出全量落盘+哈希可校验;LLM 视图 ANSI 已清洗 | ✅ | T:test_session.py;E:场景二 loot/msf-unrealircd-session.log 转录原文落盘可核 | |
| 3 | ssh localhost 集成(环境门控,允许 skip) | ✅ | K:ssh localhost 真跑通过(Kali-补测.md、L:WP-05 补测节);Mac 侧门控 skip(基线 2 skipped 之一) | |
| 4 | msfconsole Kali 实测:启动→banner→提示识别→use/info/exit,行为进日志 | ✅ | K:真跑核销(6.4.84 提示符漂移 `msf >`,测试修 `msf[56]?`,陷阱 16);WP-12 顺手 pytest 复跑 2 passed 回填;E:场景二生产全链 use/set×4/exploit 一击成功 | sqlmap 类交互向导实弹零覆盖 = M3 挂账⑨(演示项,WP-13 不做,留 M4 门口) |
| 5 | 会话上限与孤儿进程回收策略单测 | ✅ | T:test_session.py;E:场景二 run 收尾 aclose() 正确回收 msfconsole | 会话操作不入审计链/提示事件不落盘 = M3 挂账④⑤ → v1(④为门口裁决项) |

## WP-06 状态层(closed 2026-08-21)

| # | 验收条款(缩写) | 现状 | 证据 | 备注/v1 去向 |
|---|---|---|---|---|
| 1 | 目录创建/校验单测,重复 init 幂等 | ✅ | T:tests/test_state.py(29);L:WP-06 | |
| 2 | 索引单测:upsert 与关系查询(端口反查 host、host 汇总攻击面) | ✅ | T:test_state.py;L:WP-06 | creds/vulns 仅经解析 facts 入库、state 工具面无 add_vuln/add_cred = M3 挂账① → v1 |
| 3 | 脱敏单测:state_query creds 掩码,落盘完整 | ✅ | T:test_state.py 专项;L:WP-06 | |
| 4 | state 工具 schema 与 WP-01 同构,可被 WP-04 直接注册 | ✅ | S:tools/state.py TOOL_SCHEMAS;T:test_state.py;L:WP-10(经 ToolRegistry 全量注册) | |
| 5 | 日志记录真实 pytest 输出 | ✅ | L:WP-06 | loot 登记尺寸快照语义(M3 挂账⑥)、ENGAGEMENT.md 占位文案 nit(M3 挂账⑧)→ v1 |

## WP-07 parse 增强库(closed 2026-08-22)

| # | 验收条款(缩写) | 现状 | 证据 | 备注/v1 去向 |
|---|---|---|---|---|
| 1 | 每解析器合成 fixture(无真实目标数据),summary/facts 快照单测 | ✅ | tests/fixtures/ 8 个合成样本;T:tests/test_parse.py(33) | |
| 2 | facts 进 WP-06 索引集成单测:nmap fixture → hosts/ports 可查 | ✅ | T:test_parse.py;E:场景二 nmap 自动入库 hosts 1/ports 25 带指纹(场景一索引空表缺口未复现) | |
| 3 | 未知工具与格式损坏两条回退路径单测 | ✅ | T:test_parse.py;E:场景一 replay seq5 `parse_fallback no_match` 真实审计(模型自截断 `\| tail -20` 致 nmap 输出不可解析,静默回退未炸)= M3 挂账③ → v1 prompts 引导 | |
| 4 | 日志记录真实 pytest 输出 | ✅ | L:WP-07(ultracode 对抗审查 20 项修复+回归测试记录) | |

## WP-08 工具地图(closed 2026-08-22)

| # | 验收条款(缩写) | 现状 | 证据 | 备注/v1 去向 |
|---|---|---|---|---|
| 1 | 目录数据完整性单测:分组齐全、每条有句用途、无拼写死链 | ✅ | T:tests/test_toolmap.py(16);S:agent/tool_catalog.py(7 组 137 工具) | |
| 2 | 盘点器单测:fake PATH/假 dpkg 下可用/缺失判定 | ✅ | T:test_toolmap.py | |
| 3 | 注入单测:地图文本 ≤2KB、含当前实装工具、不含品牌名 | ✅ | T:test_toolmap.py;W13:src 品牌串零命中 | |
| 4 | Kali 实测:真实 Kali 盘点,覆盖率记录进日志 | ✅ | K:96/137=70.1%(which 91+dpkg 5)已核销(Kali-补测.md、L:WP-08 补测节);WP-12 顺手 dpkg 测试复跑 2 passed 回填 | WP-12 观察:盘点漂移 93/137(目录新鲜度随环境)= 已如实记录 → v1 目录维护机制 |

## WP-09 TUI(closed 2026-08-22)

| # | 验收条款(缩写) | 现状 | 证据 | 备注/v1 去向 |
|---|---|---|---|---|
| 1 | textual pilot 单测:呼号门→主界面、叙述流、jobs 面板、kill 二次确认 | ✅ | T:tests/test_tui.py(26);L:WP-09 | |
| 2 | loop 事件→TUI 渲染契约单测(fake 事件序列) | ✅ | T:test_tui.py;L:WP-09 | |
| 3 | 人工观感验收:对照 strix/Claude Code 自查记录进日志 | ✅ | L:WP-09 观感自查节(逐屏文字描述);G:M2 总指挥实机演示打分通过 | |
| 4 | 日志记录真实 pytest 输出 | ✅ | L:WP-09(含 textual 踩坑 11 条) | |
| 5 | TUI 字标读 `__app_name__` 常量,grep 无硬编码品牌串 | ✅ | S:tui/banner.py:1-3、tui/app.py:43/772/790 全部经 `__app_name__`;W13:src 零硬编码 | |
| 6 | ReasoningDelta 链路单测:fake reasoning→loop 透传→observer;审计只有哈希 | ✅ | T:test_tui.py/test_backends.py;L:WP-09;G:M2 演示(思考块折叠、首事件重试可见) | |

## WP-10 CLI 闭环(closed 2026-08-22)

| # | 验收条款(缩写) | 现状 | 证据 | 备注/v1 去向 |
|---|---|---|---|---|
| 1 | replay 篡改 e2e:改动 audit.jsonl 任一字节 → 报断链位置 | ✅ | T:tests/test_replay.py(10);E:m1-demo 副本篡改断点 seq=9 精确命中(L:WP-10 live 证据) | |
| 2 | report 快照单测:合成 engagement → 报告含全部必备节 | ✅ | T:test_replay.py;E:docs/e2e/scenario1-report.md 入库(场景一实弹报告) | |
| 3 | resume 单测:恢复后 system 含 ENGAGEMENT.md 摘要;缺 audit.jsonl 报错明确 | ✅ | T:tests/test_cli.py(13);E:m1-demo resume live(L:WP-10) | |
| 4 | `--help` 全子命令可用且无品牌名外泄 | ✅ | W13:五子命令 help 均可用;help 中品牌串仅经 `__app_name__` 常量渲染(S:cli.py:193-197/719),代码面 `git grep "Foam" -- src/` 零命中 | |
| 5 | 日志记录真实 pytest 输出 | ✅ | L:WP-10 | |

## WP-11 e2e 场景一(closed 2026-08-25)

| # | 验收条款(缩写) | 现状 | 证据 | 备注/v1 去向 |
|---|---|---|---|---|
| 1 | 全程零人工触碰工具机械细节(只允许自然语言插话) | ✅ | E:engagements/wp11-scenario1-20260825 审计链 56 条零 operator_interject,18 轮一次启动到底;G:M3 监理独立复验 | |
| 2 | loot 进索引库且路径可核 | ✅ | E:loot 两档登记(Users 表 23 行 dump + 登录绕过 PoC),index.sqlite 可查;G:M3 loot/索引/算术逐项重算一致 | |
| 3 | 审计链 verify 通过;报告含完整时间线 | ✅ | W13:`foam replay` 56 条 exit 0(2026-08-27 复核);E:docs/e2e/scenario1-report.md | |
| 4 | 如实记录:provider 审核、走偏纠正、插话次数、耗时、token | ✅ | L:WP-11(审核 0、claim-correction 误触发 4、护栏 fail-closed 2 次自救、零插话、5m57s、token 317,641/13,095) | |
| 5 | 未达标项不得隐瞒 | ✅ | L:WP-11 + HANDOVER M3 挂账(索引四表空、sqlmap 未选用、误触发) | 挂账①②③⑨ → v1 |

## WP-12 e2e 场景二(closed 2026-08-26)

| # | 验收条款(缩写) | 现状 | 证据 | 备注/v1 去向 |
|---|---|---|---|---|
| 1 | agent 自主 use→set→exploit→session 全程,无人触碰键盘 | ✅ | E:engagements/wp12-scenario2-20260826 审计链 49 条零 operator_interject,29 轮一次启动到底,msf PTY 一击成功;G:M3 复验 | |
| 2 | id/uname 输出在 loot 且路径可核;审计链 verify 通过 | ✅ | E:loot/msf-unrealircd-session.log 行 42/70 `uid=0(root)`(WP-13 复核命中);W13:`foam replay` 49 条 exit 0(2026-08-27 复核) | |
| 3 | msfconsole 结构化提示识别在真实 run 中生效(日志引用事件) | ✅ | L:WP-12 验收 3 节:真实转录字节离线复演 detect_prompt 12 命中/6 位置(含 6.4.84 无版本号 `msf >`,陷阱 16 再坐实) | 提示事件不落盘(验收引用靠运行日志+转录补强)= M3 挂账⑤ → v1 |
| 4 | 如实记录:尝试次数、失败形态分类、provider 审核、耗时 | ✅ | L:WP-12(exploit 失败 0、护栏拒绝 2、msf 用法插曲 1、误触发 1、审核 0、6m33.7s、token 290,166/5,227) | |
| 5 | 未达标项不得隐瞒 | ✅ | L:WP-12 未达标 6+1 条 + HANDOVER M3 挂账 | 挂账④⑤⑥⑦⑧ → v1 |

## WP-13 总体整合 + 发布准备(本 WP,关闭时核销)

| # | 验收条款(缩写) | 现状 | 证据 | 备注/v1 去向 |
|---|---|---|---|---|
| 1 | 双场景 replay 双双通过哈希链校验 | ✅ | W13:2026-08-27 复核,场景一 56 条/场景二 49 条均 exit 0,与 M3 复验记录一致(实录 L:WP-13 §验收1) | |
| 2 | 全新环境安装实测记录进日志 | ✅ | W13:Kali rolling arm64 干净目录 pipx install(自 git HEAD archive,~/foam 副本未碰)→ --help/fm/双场景 replay/真实后端冒烟全过;Mac 干净 clone + venv 对照组同过(实录 L:WP-13 §验收2) | |
| 3 | 发布 checklist 逐项打勾或有 v1 去向 | ✅ | W13:checklist 汇总表(pipx 实测/依赖 Kali 源可得性/GPL·许可证/.gitignore/密钥/品牌占位/演示材料),逐项打勾或 v1 去向(实录 L:WP-13 §验收3) | |
| 4 | 密钥扫描零命中(合成 fixture 除外) | ✅ | W13:高信号模式当前树+全 29 commit 历史扫描,唯一命中=3 处 TESTONLY 合成 fixture(test_backends.py:38/39、test_tui.py:83);宽模式仅 env 名常量/测试字符串/文档占位;JWT 零命中(实录 L:WP-13 §验收4) | |
| 5 | 中文开发日志 + 台账关闭 | ✅ | L:WP-13(含真实命令输出);台账 WP-13 行 closed + 关闭记录条目(2026-08-27) | |

## 汇总

- 条款总数 **63**:✅ **62**(含 WP-13 自核销 5 条);🟡 **1**(WP-03④ 其余后端无凭据未实测,偏差已记录,v1 去向明确);❌ **0**。
- M3 挂账 9 条全部落位到相关条款旁注并映射 v1 立项清单(HANDOVER「v1 立项清单」节):①→WP-06②、②→WP-04④、③→WP-07③、④⑤→WP-05⑤/③、⑥⑧→WP-06⑤、⑦→WP-02②、⑨→WP-05④(演示项,留 M4 门口)。

## M1–M3 门口记录齐全核对(WP-13 补充条款)

| 门 | 台账门表行 | HANDOVER 门口节 | 证据链 | 结论 |
|---|---|---|---|---|
| M1(WP-04 关闭) | ✅ 已通过 2026-08-21,演示+放行+开闸记录齐 | ✅ 一致 | L:WP-04「补跑」节(:195 起,真实 K3 finished/6 轮/链完整/幻觉纠正真实触发/零越界零泄漏) | 齐全 |
| M2(WP-09+10 关闭) | ✅ 已通过 2026-08-25,更正当+演示打分+放行记录齐 | ✅ 一致 | L:WP-09「更正当」节(:218 起,commit 4c19e02);总指挥实机演示观感打分 | 齐全 |
| M3(WP-11+12 关闭) | ✅ 已通过 2026-08-26,监理复验+复评+放行+挂账移交记录齐 | ✅ 一致 | 监理独立复验(两场景 replay exit 0,loot/索引/算术重算);W13 复核一致 | 齐全 |
| M4(WP-13 关闭) | 待触发 | 待触发 | 本 WP 关闭即触发,门口动作留总指挥 | — |

门口纪律核对:M1=放行、M2=更正当+放行、M3=放行(挂账随 WP-13 候选,不改既有验收口径)——
三门口产出均在「放行/更正当/砍 WP」三选一内,无开新坑,无波次中途方向争论。记录齐全,无缺口。
