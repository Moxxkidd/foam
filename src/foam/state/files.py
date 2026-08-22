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
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _slugify(text: str, max_len: int = 24) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return (slug[:max_len].strip("-") or "engagement")


def _default_engagement_id(objective: str) -> str:
    date = datetime.now(UTC).strftime("%Y%m%d")
    return f"{date}-{_slugify(objective)}"


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
    ) -> Engagement:
        """创建(或幂等复开)一个 engagement 目录。

        - 目录/id 不存在:按布局全新创建;
        - 已存在且 objective/scope 参数一致:幂等复开,不动任何已有内容;
        - 已存在但参数冲突:ValueError(防两个 engagement 混用同一目录)。
        """
        engagement_id = engagement_id or _default_engagement_id(objective)
        root = Path(base_dir) / engagement_id
        scope_meta = cls._scope_metadata(scope_path)

        if (root / "engagement.json").exists():
            meta = json.loads((root / "engagement.json").read_text(encoding="utf-8"))
            conflicts = []
            if objective and meta.get("objective") != objective:
                conflicts.append(
                    f"objective 不一致:已有 {meta.get('objective')!r} "
                    f"vs 传入 {objective!r}"
                )
            if scope_meta is not None and meta.get("scope") != scope_meta:
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
        (root / "engagement.json").write_text(
            json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
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
        self.paths.metadata.write_text(
            json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )

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
        lines += [
            "",
            "## 进展(loop 每轮更新)",
            "",
            "(loop 尚未写入进展;每轮结束由 loop 调 update_progress 维护本节)",
            "",
        ]
        return "\n".join(lines)

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
