"""engagement 目录布局:创建 / 校验 / 元数据 / ENGAGEMENT.md 读写接口。

布局(WP-06 规格):

    engagements/<id>/
      engagement.json      # 元数据:objective、scope 文件哈希、起止时间、状态
      ENGAGEMENT.md        # 每轮必载的进展摘要(loop 维护,本 WP 只提供读写接口)
      audit.jsonl          # WP-02 审计链(创建空占位;WP-04 接线 AuditLog)
      outputs/             # 工具原始输出(WP-01 输出层落盘处)
      loot/                # 战利品文件(dump、截图、key)
      notes/               # 自由笔记
      index.sqlite         # state/index.py 的索引库

outputs/ 契约(重要):outputs/ 就是 WP-01 输出层未来的 output_root——
WP-01 的 BashTool(output_dir=...) 由调用方注入输出目录,本 WP 不改 WP-01
任何文件;接线方式:WP-04/WP-10 拿到 Engagement 后把 ``eng.paths.outputs``
作为 ``BashTool(output_dir=...)`` 传入。

幂等约定:同参数重复 create 安全(不重置任何已有文件);objective/scope
与已有 engagement.json 冲突时报 ValueError——防止两个 engagement 误用同一
目录。audit.jsonl 只 touch 占位,不初始化哈希链(空文件对 WP-02 的
AuditLog 即「全新链」)。

WP-14a 动态段契约(D12):ENGAGEMENT.md 开箱即含 scope 动态段 markers
(``SCOPE_SECTION_BEGIN``/``SCOPE_SECTION_END``,定义权在本模块,14d 模板
逐字一致);``update_scope_section`` 仅「markers 间原子重写」单一形态。
**``update_progress`` 与动态段互斥**:它整文件重写会抹掉 markers;目前
运行期无调用方(仅 tests/test_state.py 触达),未来若给 update_progress
接运行期调用方,必须同步改造为保留动态段。

R02(2026-10-06)持久化契约:

- **engagement.json 全量原子写**:create 首写与 ``_write_metadata`` 一律走
  ``_atomic_write_text``(tmp+rename)——崩溃要么留旧文件要么留新文件,
  不留半截 JSON。
- **单写者锁**:``acquire_engagement_lock`` 以 flock(LOCK_EX|LOCK_NB)持
  ``engagement.lock``,持期 = 一次 run 的生命周期;进程死亡(含崩溃)由
  内核自动释放——崩溃写者的锁自然空闲,存活第二写者立即被拒
  (``EngagementLockedError``)。只读命令(replay/report/verify)不取锁。
- **修订提交协议**(scope/objective):审计追加是不可变事实,先行落链;
  随后 ``commit_revision`` 原子重写 engagement.json,携带提交标记
  ``meta["revision"] = {"seq", "hash"}``(确认记录的 seq/hash)。legacy
  目录(无 revision 键)首次提交前原样备份 engagement.json 为
  ``engagement.json.pre-r02.bak``(只供检查,不自动恢复授权);audit.jsonl
  永不被重写。
- **恢复对账**(``reconcile_with_chain``,调用方须先经 chain_errors 校验
  链内一致性):有 marker 且与链一致 → 接受;链上投影相关记录
  (scope_confirmed/scope_updated/run_started)比 marker 新(审计与 meta
  之间崩溃)→ 从链重建 scope/objective 投影并推进 marker;marker 所指
  seq 不在链上(截尾/缺条)或同 seq 异 hash(分叉)→ ValueError 明确
  拒绝,绝不猜。无 marker 的 legacy 目录原样返回,既有
  meta-first/drift/链回退路径不变(不从链重建)。
- **状态生命周期**:start/resume 经 ``mark_active`` 置 active 并清
  closed_at;finished 经 ``mark_closed`` 置 closed(re-close 刷新
  closed_at)。killed/crash 不经 mark_closed,保持 active + 锁已随进程
  释放 = 中断可恢复(文档化边界;退出路径资源收口归 R03)。
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from foam.guard.audit import KIND_SCOPE_CONFIRMED, KIND_SCOPE_UPDATED
from foam.state.index import Index

#: 布局必需项(相对 engagement 根):"f" 文件 / "d" 目录。
LAYOUT: dict[str, str] = {
    "engagement.json": "f",
    "ENGAGEMENT.md": "f",
    "audit.jsonl": "f",
    "outputs": "d",
    "loot": "d",
    "notes": "d",
    "index.sqlite": "f",
}

DEFAULT_ENGAGEMENTS_DIR = Path("engagements")

#: scope 动态段 markers(WP-14a,边界契约 1:定义权在本模块;14d
#: ``_ENGAGEMENT_TEMPLATE`` 的动态段占位与写入助手消费同一字面量)。
SCOPE_SECTION_BEGIN = "<!-- foam:scope:begin -->"
SCOPE_SECTION_END = "<!-- foam:scope:end -->"

#: ENGAGEMENT.md 目标行(create 模板 ``- 目标:`` 与 prompts 模板
#: ``- 目标(objective):`` 两种形态都认),update_objective 据此定位。
_OBJECTIVE_LINE_RE = re.compile(r"^- 目标(\(objective\))?[:：]")


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _atomic_write_text(path: Path, text: str) -> None:
    """tmp+rename 原子写回(同目录临时文件,rename 后无残留)。"""
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def _slugify(text: str, max_len: int = 24) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return (slug[:max_len].strip("-") or "engagement")


#: 单写者锁文件名(engagement 目录根下;R02)。
ENGAGEMENT_LOCK_NAME = "engagement.lock"

#: legacy 目录首次新格式提交前的元数据备份文件名(R02;只供检查,不自动恢复授权)。
REVISION_BACKUP_NAME = "engagement.json.pre-r02.bak"

#: run_started 的 kind 字面量。定义权在 agent.loop(KIND_RUN_STARTED),依赖
#: 方向 agent→state 单向,本模块只能引字面量——审计 kind 串是稳定契约
#: (replay 归一化同样依赖这些字面量)。
_KIND_RUN_STARTED = "run_started"

#: 会改变 engagement.json 投影(scope/objective)的审计 kind。
_PROJECTION_KINDS = frozenset(
    {KIND_SCOPE_CONFIRMED, KIND_SCOPE_UPDATED, _KIND_RUN_STARTED}
)


class EngagementLockedError(RuntimeError):
    """同目录已有另一个运行中的写者(engagement.lock 被持有)。"""


class EngagementLock:
    """engagement 目录单写者锁(flock LOCK_EX|LOCK_NB;进程死亡自动释放)。

    持期 = 一次 run 的生命周期:崩溃写者的锁由内核回收(自然空闲),存活
    第二写者在 flock 处立即被拒。只读命令(replay/report/verify)不取锁。
    锁文件本体只是占位,内容无意义;勿手删——持有者可能仍在写。
    """

    def __init__(self, root: str | Path):
        self._path = Path(root) / ENGAGEMENT_LOCK_NAME
        self._fh = open(self._path, "a+b")  # noqa: SIM115
        try:
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self._fh.close()
            raise EngagementLockedError(
                f"engagement 目录 {Path(root)} 已有另一个运行中的写者"
                f"({ENGAGEMENT_LOCK_NAME} 被持有)"
            ) from None

    @property
    def path(self) -> Path:
        return self._path

    def release(self) -> None:
        """释放锁(幂等);进程退出/崩溃时内核亦自动回收,此处是正常路径。"""
        if self._fh is not None:
            try:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            self._fh.close()
            self._fh = None

    def __enter__(self) -> EngagementLock:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.release()


def acquire_engagement_lock(root: str | Path) -> EngagementLock:
    """获取 engagement 目录的单写者锁;已被持有时抛 EngagementLockedError。

    仅写者命令(run/resume/TUI 装配)使用;只读命令不取锁。
    """
    return EngagementLock(root)


def _default_engagement_id(objective: str) -> str:
    date = datetime.now(UTC).strftime("%Y%m%d")
    return f"{date}-{_slugify(objective)}"


def _scope_meta_conflict(
    stored: dict[str, Any] | None, given: dict[str, Any]
) -> bool:
    """create 幂等复开的 scope 冲突判定(R02 对抗评审收口,规范化比较)。

    - ``stored`` 为 None(目录未记 scope)→ 冲突(既有行为,防 scope 与
      无 scope engagement 混用同目录);
    - sha256 不一致 → 冲突(既有 drift 语义:内容不同即不同授权物);
    - sha256 一致时,路径 exact-equal 或 ``resolve()``-equal 视为同一授权
      物——legacy 相对路径目录的同 cwd 幂等复开(pre-R02 可用流程)不再
      误报;不同 cwd 复开 legacy 相对路径目录 pre-R02 已在文件缺失处
      失败,语义不变(不新增义务)。resolve() 相对串按当前 cwd 归一,
      与 pre-R02 as-given 记录的读取口径一致。
    """
    if stored is None:
        return True
    if stored.get("sha256") != given.get("sha256"):
        return True
    stored_path = str(stored.get("path") or "")
    given_path = str(given.get("path") or "")
    if stored_path == given_path:
        return False
    return Path(stored_path).resolve() != Path(given_path).resolve()


class EngagementPaths:
    """布局各路径的集中访问点(WP-04 接线、WP-07/WP-10 消费都用它)。"""

    def __init__(self, root: Path):
        self.root = Path(root)

    @property
    def metadata(self) -> Path:
        return self.root / "engagement.json"

    @property
    def progress_md(self) -> Path:
        return self.root / "ENGAGEMENT.md"

    @property
    def audit_jsonl(self) -> Path:
        return self.root / "audit.jsonl"

    @property
    def outputs(self) -> Path:
        """WP-01 输出层的 output_root(见模块 docstring「outputs/ 契约」)。"""
        return self.root / "outputs"

    @property
    def loot(self) -> Path:
        return self.root / "loot"

    @property
    def notes(self) -> Path:
        return self.root / "notes"

    @property
    def index_db(self) -> Path:
        return self.root / "index.sqlite"


class Engagement:
    """一个 engagement 的目录与元数据。索引库另开 :class:`Index`。"""

    def __init__(self, root: str | Path):
        self.paths = EngagementPaths(Path(root))
        self._index: Index | None = None

    # ---------- 创建 / 打开 ----------

    @classmethod
    def create(
        cls,
        base_dir: str | Path = DEFAULT_ENGAGEMENTS_DIR,
        objective: str = "",
        *,
        scope_path: str | Path | None = None,
        engagement_id: str | None = None,
        scope_bytes: bytes | None = None,
    ) -> Engagement:
        """创建(或幂等复开)一个 engagement 目录。

        - 目录/id 不存在:按布局全新创建;
        - 已存在且 objective/scope 参数一致:幂等复开,不动任何已有内容
          (scope 冲突判定经 ``_scope_meta_conflict`` 规范化:sha256 一致
          且路径 exact/resolve 等价即同一授权物);
        - 已存在但参数冲突:ValueError(防两个 engagement 混用同一目录)。

        ``scope_bytes``(R02,单次读盘绑定):与 ``scope_path`` 同给时,
        scope 元数据的 sha256 取调用方提供的字节(加载期已读出的同一份),
        不二次读盘——消灭「解析用旧字节、落盘用新字节」的 TOCTOU 窗口;
        给定时跳过文件存在性检查(调用方既已读出字节,文件必存在过)。
        """
        engagement_id = engagement_id or _default_engagement_id(objective)
        root = Path(base_dir) / engagement_id
        if scope_path is not None and scope_bytes is not None:
            scope_meta = {
                "path": str(Path(scope_path)),
                "sha256": hashlib.sha256(scope_bytes).hexdigest(),
            }
        else:
            scope_meta = cls._scope_metadata(scope_path)

        if (root / "engagement.json").exists():
            meta = json.loads((root / "engagement.json").read_text(encoding="utf-8"))
            conflicts = []
            if objective and meta.get("objective") != objective:
                conflicts.append(
                    f"objective 不一致:已有 {meta.get('objective')!r} "
                    f"vs 传入 {objective!r}"
                )
            if scope_meta is not None and _scope_meta_conflict(
                meta.get("scope"), scope_meta
            ):
                conflicts.append("scope 与已有记录不一致(路径或哈希不同)")
            if conflicts:
                raise ValueError(
                    f"engagement 目录 {root} 已被占用,参数冲突:{'; '.join(conflicts)}"
                )
        else:
            now = _utc_now_iso()
            meta = {
                "id": engagement_id,
                "objective": objective,
                "created_at": now,
                "closed_at": None,
                "status": "active",
                "scope": scope_meta,
            }

        root.mkdir(parents=True, exist_ok=True)
        for name, kind in LAYOUT.items():
            target = root / name
            if kind == "d":
                target.mkdir(exist_ok=True)
            elif name != "engagement.json":
                # audit.jsonl 空占位;index.sqlite 由 Index 建
                target.touch(exist_ok=True)
        # R02:首写同样原子——崩溃要么无文件要么完整文件,不留半截 JSON
        _atomic_write_text(
            root / "engagement.json",
            json.dumps(meta, ensure_ascii=False, indent=2) + "\n",
        )
        if not (root / "ENGAGEMENT.md").exists() or not (
            root / "ENGAGEMENT.md"
        ).read_text(encoding="utf-8").strip():
            (root / "ENGAGEMENT.md").write_text(
                cls._render_initial_md(meta), encoding="utf-8"
            )
        # 建库(DDL 幂等),顺便保证 index.sqlite 落盘
        with Index(root / "index.sqlite"):
            pass
        return cls(root)

    @classmethod
    def open(cls, root: str | Path) -> Engagement:
        """打开已有 engagement(不创建任何文件);结构问题由 validate 报告。"""
        root = Path(root)
        if not root.is_dir():
            raise FileNotFoundError(f"engagement 目录不存在:{root}")
        return cls(root)

    @staticmethod
    def _scope_metadata(scope_path: str | Path | None) -> dict[str, Any] | None:
        """scope 文件元数据:源路径 + 内容 sha256(与 WP-02 护栏/审计呼应——
        事后可用哈希对账 scope 是否被改动;不复制文件本体,避免双源漂移)。"""
        if scope_path is None:
            return None
        path = Path(scope_path)
        if not path.is_file():
            raise FileNotFoundError(f"scope 文件不存在:{path}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        return {"path": str(path), "sha256": digest}

    # ---------- 元数据 ----------

    def metadata(self) -> dict[str, Any]:
        return json.loads(self.paths.metadata.read_text(encoding="utf-8"))

    def _write_metadata(self, meta: dict[str, Any]) -> None:
        # R02:engagement.json 一律 tmp+rename 原子写(崩溃不留半截 JSON)
        _atomic_write_text(
            self.paths.metadata,
            json.dumps(meta, ensure_ascii=False, indent=2) + "\n",
        )

    def mark_active(self) -> dict[str, Any]:
        """标记 engagement (重新)进入活动态(R02):start/resume 启动时调用。

        status 置 active、closed_at 清空(re-finish 时 mark_closed 才能刷新
        closed_at)。幂等:已 active 且无 closed_at 时不落盘。killed/crash
        不调本方法也不调 mark_closed——保持 active = 中断可恢复(文档化边界)。
        """
        meta = self.metadata()
        if meta.get("status") != "active" or meta.get("closed_at") is not None:
            meta["status"] = "active"
            meta["closed_at"] = None
            self._write_metadata(meta)
        return meta

    def mark_closed(self) -> dict[str, Any]:
        """标记 engagement 结束(记录 closed_at,状态置 closed)。幂等。"""
        meta = self.metadata()
        if meta.get("status") != "closed":
            meta["status"] = "closed"
            meta["closed_at"] = _utc_now_iso()
            self._write_metadata(meta)
        return meta

    def set_operator(self, operator: str) -> dict[str, Any]:
        """记录操作员呼号(WP-09 迎宾屏收集,写 engagement.json;幂等覆盖)。

        呼号同时进 loop 的 operator_interject 审计载荷(loop 构造参数),
        本字段是 engagement 元数据侧的可对账落点。
        """
        meta = self.metadata()
        meta["operator"] = operator
        self._write_metadata(meta)
        return meta

    def update_scope_metadata(self, scope_path: str | Path) -> dict[str, Any]:
        """幂等重写 engagement.json 的 ``meta["scope"]``(WP-14a,供冻结助手复用)。

        内部 ``Path.resolve()`` 落绝对路径(定案 D13:cli.py:739 的
        ``is_file`` 判定不依赖 resume 时的 cwd)+ 文件字节 sha256;文件不存在
        抛 FileNotFoundError。create 路径的 ``_scope_metadata`` 行为不变
        (仍记 as-given 原串)。返回更新后的完整元数据。
        """
        path = Path(scope_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"scope 文件不存在:{path}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        meta = self.metadata()
        meta["scope"] = {"path": str(path), "sha256": digest}
        self._write_metadata(meta)
        return meta

    def update_scope_metadata_bytes(
        self, scope_path: str | Path, data: bytes
    ) -> dict[str, Any]:
        """以调用方提供字节重写 ``meta["scope"]``(R02,单次读盘绑定)。

        sha256 取 ``data``(加载期读出的同一份字节),不二次读盘——消灭
        「内存规则与落盘哈希各读一次」的 TOCTOU 窗口;不做文件存在性检查。
        ``scope_path`` 按给定串落盘(str(Path(...)) 形态化,不 resolve):
        as-given/absolute 口径由调用方定(TUI file 流须与 start_run 幂等
        复开的 ``_scope_metadata`` 同串,故保持 as-given)。返回完整元数据。
        """
        meta = self.metadata()
        meta["scope"] = {
            "path": str(Path(scope_path)),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        self._write_metadata(meta)
        return meta

    # ---------- ENGAGEMENT.md(loop 每轮调用的读写接口) ----------

    @property
    def index(self) -> Index:
        """懒加载索引库句柄(仅 update_progress 统计计数时用)。"""
        if self._index is None:
            self._index = Index(self.paths.index_db)
        return self._index

    def read_progress(self) -> str:
        """ENGAGEMENT.md 全文(loop 每轮必载,进 system/context)。"""
        return self.paths.progress_md.read_text(encoding="utf-8")

    def update_progress(
        self,
        *,
        phase: str,
        current_objective: str,
        note: str | None = None,
    ) -> str:
        """由 loop 在每轮结束调用:重写 ENGAGEMENT.md 的进展段。

        关键发现计数自动从索引库统计;note 为可选自由段落(一句话级,
        保持文件小而可整载入 context)。返回渲染后的全文。

        WP-14a 声明(定案 D12):本方法整文件重写,会抹掉 scope 动态段
        markers——**与动态段互斥**。目前运行期无调用方(仅
        tests/test_state.py 触达),行为保持不变;未来若接运行期调用方,
        必须同步改造为保留动态段。
        """
        meta = self.metadata()
        counts = self.index.counts()
        counts_line = " / ".join(
            f"{name} {counts[name]}"
            for name in ("hosts", "ports", "creds", "vulns", "loot", "notes")
        )
        lines = [
            f"# Engagement {meta['id']}",
            "",
            f"- 目标:{meta.get('objective', '')}",
        ]
        status = meta.get("status", "active")
        if status == "closed":
            lines.append(
                f"- 状态:closed(创建 {meta['created_at']},"
                f"关闭 {meta.get('closed_at')})"
            )
        else:
            lines.append(f"- 状态:active(创建于 {meta['created_at']})")
        scope = meta.get("scope")
        if scope:
            lines.append(f"- scope:{scope['path']} (sha256:{scope['sha256']})")
        else:
            lines.append("- scope:(未记录)")
        lines += [
            "",
            "## 进展(loop 每轮更新)",
            "",
            f"- 最近阶段:{phase}",
            f"- 当前目标:{current_objective}",
            f"- 关键发现:{counts_line}",
            f"- 更新时间:{_utc_now_iso()}",
        ]
        if note:
            lines += ["", "## 备注", "", note]
        lines.append("")
        text = "\n".join(lines)
        self.paths.progress_md.write_text(text, encoding="utf-8")
        return text

    @staticmethod
    def _render_initial_md(meta: dict[str, Any]) -> str:
        lines = [
            f"# Engagement {meta['id']}",
            "",
            f"- 目标:{meta.get('objective', '')}",
            f"- 状态:active(创建于 {meta['created_at']})",
        ]
        scope = meta.get("scope")
        if scope:
            lines.append(f"- scope:{scope['path']} (sha256:{scope['sha256']})")
        # WP-14a(定案 D12):create 路径开箱即含 scope 动态段 markers,与 14d
        # _ENGAGEMENT_TEMPLATE 的动态段逐字合一(14d 一致性请求 2)——写入助手
        # 据此只需「markers 间原子重写」单一形态,无插入特例。markers 间占位行
        # 与 markers 外说明引用块均为模板静态文本,不经写入助手重写。
        lines += [
            "",
            "## 授权范围",
            "",
            SCOPE_SECTION_BEGIN,
            "(scope 尚未冻结——确认后由 harness 写入当前生效的范围规则)",
            SCOPE_SECTION_END,
            "",
            "> 以上「授权范围」段由 harness 维护,勿手改——护栏判定以代码为准,手改不",
            "> 影响执行且会被下次写入覆盖。",
            "",
            "## 进展(loop 每轮更新)",
            "",
            "(loop 尚未写入进展;每轮结束由 loop 调 update_progress 维护本节)",
            "",
        ]
        return "\n".join(lines)

    def update_scope_section(self, section: str) -> None:
        """动态段写入助手(WP-14a,定案 D12 **单形态**):markers 间内容整段
        替换,tmp+rename 原子写回,markers 外字节不变。

        - ``section``:markers 之间的新内容(不含 markers 本身)。渲染唯一
          来源为 14d ``prompts.render_scope_section``,调用方一律消费其输出,
          本助手不自建渲染。
        - 「markers 间」以 marker 字面量本身为界:BEGIN 字面量之后、END
          字面量之前的全部内容(含同行残留文本)都算段内,整段替换——故
          同行 markers、END 行前缀残留等模型手改形态同样收敛。
        - 容错分支(D12 单形态的细化,D6 信息面容错):模型可写
          ENGAGEMENT.md;markers 缺失/不成对(END 在 BEGIN 前、只剩其一)
          时,先剥离游离 marker 字面量,再将完整段(标题 + markers + 内容)
          附加到文件末尾一次以恢复 markers——这是容错恢复,不构成第二写入
          形态;正常路径永远是 markers 间重写。
        """
        path = self.paths.progress_md
        text = path.read_text(encoding="utf-8") if path.is_file() else ""
        body = section.strip("\n") + "\n"

        begin_idx = text.find(SCOPE_SECTION_BEGIN)
        end_idx = (
            text.find(SCOPE_SECTION_END, begin_idx + len(SCOPE_SECTION_BEGIN))
            if begin_idx != -1
            else -1
        )
        if begin_idx != -1 and end_idx != -1:
            # 正常路径(唯一形态):marker 字面量间整段重写,markers 外字节不动
            content_start = begin_idx + len(SCOPE_SECTION_BEGIN)
            new_text = text[:content_start] + "\n" + body + text[end_idx:]
        else:
            # 容错恢复:剥离游离 marker 字面量,完整段附加到文件末尾一次
            cleaned = text.replace(SCOPE_SECTION_BEGIN, "").replace(
                SCOPE_SECTION_END, ""
            )
            block = (
                "## 授权范围\n\n"
                + SCOPE_SECTION_BEGIN
                + "\n"
                + body
                + SCOPE_SECTION_END
                + "\n"
            )
            if not cleaned.strip():
                new_text = block
            else:
                sep = "" if cleaned.endswith("\n") else "\n"
                new_text = cleaned + sep + "\n" + block
        _atomic_write_text(path, new_text)

    def _rewrite_objective_line(self, objective: str) -> None:
        """ENGAGEMENT.md 目标行替换(独立原子写;信息面与 meta 一致)。

        首个匹配 ``^- 目标(\\(objective\\))?[:：]`` 的行替换为
        ``- 目标:{objective}``(无匹配行则在首个 ``# `` 标题行后插入)。
        update_objective 与 commit_revision/reconcile 共用——meta 与
        ENGAGEMENT.md 不同事务,本写永远在 meta 写之后(信息面跟随事实面)。
        """
        path = self.paths.progress_md
        text = path.read_text(encoding="utf-8") if path.is_file() else ""
        lines = text.splitlines()
        new_line = f"- 目标:{objective}"
        for i, line in enumerate(lines):
            if _OBJECTIVE_LINE_RE.match(line):
                lines[i] = new_line
                break
        else:
            for i, line in enumerate(lines):
                if line.startswith("# "):
                    lines.insert(i + 1, new_line)
                    break
            else:
                lines.insert(0, new_line)
        new_text = "\n".join(lines)
        if text.endswith("\n") or not text:
            new_text += "\n"
        _atomic_write_text(path, new_text)

    def update_objective(self, objective: str) -> None:
        """冻结时以最新文本覆盖 objective(WP-14a,定案 D8 落点)。

        engagement.json objective 覆盖 + ENGAGEMENT.md 目标行替换,tmp+rename。
        """
        meta = self.metadata()
        meta["objective"] = objective
        self._write_metadata(meta)
        self._rewrite_objective_line(objective)

    # ---------- R02:修订提交与恢复对账 ----------

    def backup_pre_r02(self) -> bool:
        """legacy 目录(meta 无 revision 键)的原样备份(幂等)。

        R02:第一次 R02 写(状态迁移/修订提交)之前调用,把升级前
        engagement.json 原文留作 ``engagement.json.pre-r02.bak``;已有
        revision 键(已是新格式)或备份已存在时不动作(保留最初的升级前
        状态)。备份只供检查,不自动恢复授权(R02 规格 §1/§7);
        audit.jsonl 永不在此触及。返回是否新建了备份。
        """
        if "revision" in self.metadata():
            return False
        backup = self.paths.root / REVISION_BACKUP_NAME
        if backup.exists():
            return False
        data = self.paths.metadata.read_bytes()
        backup.write_bytes(data)
        json.loads(data.decode("utf-8"))  # 验证备份可读(坏 meta 直接炸,不写备份)
        return True

    def commit_revision(
        self,
        *,
        scope: dict[str, str] | None = None,
        objective: str | None = None,
        marker: dict[str, Any],
    ) -> dict[str, Any]:
        """提交一次 scope/objective 修订(R02 提交协议)。

        前置:确认记录已落审计链(不可变事实;``marker`` 即该记录,取其
        ``seq``/``hash``)。本方法随后原子重写 engagement.json,携带提交
        标记 ``meta["revision"]``——恢复对账据此判定「meta 投影反映到链的
        哪个位置」。崩溃窗口(审计已落、本写未达)由
        ``reconcile_with_chain`` 在下次恢复时从链重建。

        - ``scope``:``{"path", "sha256"}``(调用方口径:CLI file 流为绝对
          路径 + 文件字节 sha256);``objective``:新目标文本;None 的维度不动。
        - legacy 目录(无 revision 键)首次提交前自动备份 engagement.json
          (``engagement.json.pre-r02.bak``,已存在不覆盖)。
        - ``objective`` 给定时同步重写 ENGAGEMENT.md 目标行(信息面一致;
          两段各自原子写,meta 写在前——崩溃至多留信息面滞后,不丢事实面)。
        """
        meta = self.metadata()
        if "revision" not in meta:
            self.backup_pre_r02()
        if scope is not None:
            meta["scope"] = {"path": str(scope["path"]), "sha256": str(scope["sha256"])}
        if objective is not None:
            meta["objective"] = str(objective)
        meta["revision"] = {"seq": int(marker["seq"]), "hash": str(marker["hash"])}
        self._write_metadata(meta)
        if objective is not None:
            self._rewrite_objective_line(str(objective))
        return meta

    def reconcile_with_chain(self, records: list[dict[str, Any]]) -> dict[str, Any]:
        """恢复对账(R02):meta 提交标记与审计链比对,返回(可能重建后的)meta。

        前置:调用方须先经 chain_errors 校验链内一致性(本方法不重算链
        hash——marker 是 meta↔链之间唯一的跨文件对账点)。

        - 无 marker(legacy):原样返回 meta——既有 meta-first/drift/链回退
          路径不变,不从链重建、不猜(R02 规格边界);
        - marker 所指 seq 不在链上(链被截尾/缺条)或同 seq 异 hash(链被
          整条替换的分叉,链自验合法但非原链)→ ValueError 明确拒绝;
        - 链上投影相关记录(scope_confirmed/scope_updated/run_started)比
          marker 新(审计落链与 meta 提交之间崩溃)→ 从链重建投影:scope 取
          最新 scope_confirmed/scope_updated 的 path/canonical_sha256(与 meta
          现值同 sha 时保留 meta 的 path 形态——绝对路径口径不被审计
          as-given 串回退),objective 取最新 run_started;marker 推进到最新
          相关记录,原子重写落盘;旧审计字节不动(AC08);
        - 否则(链不领先)原样返回,接受已提交状态。
        """
        meta = self.metadata()
        marker = meta.get("revision")
        if not isinstance(marker, dict):
            return meta
        marked_seq = marker.get("seq")
        marked_hash = marker.get("hash")
        marked_record = next(
            (rec for rec in records if rec.get("seq") == marked_seq), None
        )
        if marked_record is None:
            raise ValueError(
                f"engagement.json 提交标记指向审计链 seq={marked_seq},"
                "但链上无此记录(链被截尾/缺条);完整性存疑,拒绝恢复,"
                "请人工核查 engagement 目录(备份见 engagement.json.pre-r02.bak)"
            )
        if marked_record.get("hash") != marked_hash:
            raise ValueError(
                f"engagement.json 提交标记与审计链 seq={marked_seq} 记录的 "
                "hash 不符(meta 与链分叉,链疑似被整条替换);拒绝恢复,"
                "请人工核查 engagement 目录"
            )

        last_scope: dict[str, Any] | None = None
        last_objective: dict[str, Any] | None = None
        newest_relevant: dict[str, Any] | None = None
        for rec in records:
            kind = rec.get("kind")
            if kind not in _PROJECTION_KINDS:
                continue
            newest_relevant = rec  # records 按 seq 升序,末个相关记录即最新
            if kind in (KIND_SCOPE_CONFIRMED, KIND_SCOPE_UPDATED):
                last_scope = rec
            else:  # run_started
                last_objective = rec
        if newest_relevant is None or newest_relevant["seq"] <= marked_seq:
            return meta

        new_objective: str | None = None
        if last_scope is not None and last_scope["seq"] > marked_seq:
            payload = last_scope.get("payload") or {}
            path, sha = payload.get("path"), payload.get("canonical_sha256")
            if path and sha:
                current = meta.get("scope") or {}
                if current.get("sha256") != sha:
                    # 新授权内容:采纳链上口径(同 sha 仅 path 形态不同时,
                    # 保留 meta 现有 path——绝对路径不被 as-given 回退)
                    meta["scope"] = {"path": str(path), "sha256": str(sha)}
        if last_objective is not None and last_objective["seq"] > marked_seq:
            objective = (last_objective.get("payload") or {}).get("objective")
            if objective:
                new_objective = str(objective)
                meta["objective"] = new_objective
        meta["revision"] = {
            "seq": int(newest_relevant["seq"]),
            "hash": str(newest_relevant["hash"]),
        }
        self._write_metadata(meta)
        if new_objective is not None:
            self._rewrite_objective_line(new_objective)
        return meta

    # ---------- 校验 ----------

    def validate(self) -> list[str]:
        """布局完整性校验,返回问题清单(空 = 通过)。"""
        problems: list[str] = []
        for name, kind in LAYOUT.items():
            target = self.paths.root / name
            if kind == "d" and not target.is_dir():
                problems.append(f"缺失目录:{name}/")
            elif kind == "f" and not target.is_file():
                problems.append(f"缺失文件:{name}")
        meta_path = self.paths.metadata
        if meta_path.is_file():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                if meta.get("id") != self.paths.root.name:
                    problems.append(
                        f"engagement.json 的 id({meta.get('id')!r})与目录名不符"
                    )
                for field_name in ("objective", "created_at", "status"):
                    if field_name not in meta:
                        problems.append(f"engagement.json 缺字段:{field_name}")
            except json.JSONDecodeError as exc:
                problems.append(f"engagement.json 无法解析:{exc}")
        return problems

    def close(self) -> None:
        if self._index is not None:
            self._index.close()
            self._index = None

    def __enter__(self) -> Engagement:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
