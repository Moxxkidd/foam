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

## 下一 WP

**WP-01(exec 层 + 智能输出层)**,规格:`docs/work-packages/WP-01.md`。
无依赖,可直接开工。WP-03 亦无依赖。注意:本工作区可能有 WP-01/WP-03
的并行进行(未跟踪文件已出现);WP-04 须等 01/03 均关闭。

## WP 依赖速查

```
WP-01 ──┬─ WP-04 ──┬─ WP-08 ── WP-11(场景一)
WP-02 ──┤          ├─ WP-09(TUI)
WP-03 ──┘          └─ WP-10(CLI 闭环)
WP-05(会话)── WP-12(场景二)
WP-06 ── WP-07(parse)
WP-13(整合)依赖全部
```

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
