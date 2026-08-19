# AGENTS.md —— 仓库开发契约(所有 agent/LLM 的入口)

> 任何 agent(任何 LLM、全新记忆)接手本仓库前,**先读完本文件**,再读
> `docs/HANDOVER.md` 了解当前状态。这两份文档是跨会话唯一事实源。

## 0. 命名纪律

项目名「Kali Code」是暂用代号,**任何阶段都可能整体改名**。品牌字符串只
允许出现在 `pyproject.toml` 与 `src/kalicode/__init__.py` 的
`__app_name__` 常量;其余代码、注释、文档一律称「本项目」。写文档时禁止
出现品牌名。

## 1. 项目定位(唯一目标)

以 harness 形式把 **Kali 整个工具库**与 LLM 有机结合,做到 1+1≫2:

- LLM 通过自由 bash 使用 Kali 里**任何**工具;专用解析器/适配器是增强,
  不是门槛——不认识的工具走通用路径照样能跑。
- 不限制 LLM 的策略思路:system prompt 只给方法论骨架与工具地图,不内置
  playbook。
- 差异化锚点:持久 PTY 交互会话、智能输出层、engagement 状态索引、
  scope 硬护栏、全程哈希链审计可回放。

## 2. WP 制开发

1. 每个工作包先有规格文档 `docs/work-packages/WP-XX.md`(目标/排除项/
   涉及文件/验收标准/依赖),**先评审规格再写代码**。
2. 一次只做一个 WP;WP 之间开发互不影响、互不干扰。
3. 每个 WP 关闭时必须同时满足:
   - 规格文档验收条款逐条达标;
   - pytest 全绿,真实测试输出写进开发日志;
   - 中文开发日志 `docs/dev-logs/WP-XX.md`(含设计取舍、踩坑、真实输出);
   - `docs/wp-ledger.md` 追加/更新本 WP 行(append-only);
   - `docs/HANDOVER.md` 更新「当前状态」与「下一 WP」;
   - **封闭性 commit 直接推 main**(私有 repo,不走 PR):commit message
     格式 `WP-XX: <短标题>`。
4. 所有 WP 落地后,由最终整合 WP(WP-13)统一收口。

## 3. 文件所有权

- 每个 WP 规格文档声明它**拥有**的文件/目录;其他 WP 不得修改。
- 跨 WP 共享文件只有三个:`docs/HANDOVER.md`、`docs/wp-ledger.md`、
  `AGENTS.md`——全部 **append-only**,改之前重读最新版本,只追加或最小
  修订自己的条目,绝不整段覆写。
- 确需动别人的文件:先在自己 WP 的开发日志里声明原因与影响面。

## 4. 安全与合规红线(不可协商)

- 本项目仅服务**明确授权**的目标;scope 护栏是产品底线,任何 WP 不得削弱
  护栏来让测试或演示通过。
- 密钥只走环境变量(`KALICODE_LLM_API_KEY` 等);任何代码、日志、文档、
  测试、fixture 不得出现真实 key/token。
- 测试 fixture 里的凭据必须是明显合成的(example.com / TESTONLY)。
- engagement 运行时产物(工具原始输出、loot、索引库)永不入库
  (`.gitignore` 已挡,提交前自查 `git status`)。

## 5. 工程纪律

- Python ≥ 3.12,`asyncio`;依赖保持保守(长期目标 Kali/Debian 官方源),
  新增依赖必须在该 WP 开发日志写明理由。
- 代码风格:ruff(配置在 pyproject);注释/文档用中文,标识符用英文。
- 测试:pytest + pytest-asyncio;每个模块配单测,解析器配 fixture。
- 不引入重型框架;标准库优先(sqlite3、pty、asyncio 都是标准库)。

## 6. 已知陷阱(随 WP 关闭持续追加)

- (待第一个 WP 补充)
