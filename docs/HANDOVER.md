# HANDOVER —— 交接文档(append-only 修订,见 AGENTS.md §3)

> 读法:先看「当前状态」定位,再看「下一 WP」,「已知陷阱」防重复踩坑。
> 每个 WP 关闭时更新本文件(契约第 2.3 条)。

## 当前状态

- 2026-08-19:**阶段 0 完成**——仓库骨架(pyproject/LICENSE/README/
  scopes/包目录)、开发契约(AGENTS.md)、本文件、台账、全部 WP 规格
  文档就绪;GitHub 私有 repo 已建并推送 main。尚无任何功能代码。

## 下一 WP

**WP-01(exec 层 + 智能输出层)**,规格:`docs/work-packages/WP-01.md`。
无依赖,可直接开工。

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
4. (随 WP 关闭持续追加)
