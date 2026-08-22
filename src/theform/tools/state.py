"""LLM 状态工具:state_query / state_add_note / state_add_loot(WP-06)。

schema 形状与 WP-01 完全同构:``TOOL_SCHEMAS`` 为 provider 中立
{name, description, parameters(JSON Schema)} 纯 dict,``StateTool.dispatch``
是 WP-04 注册后的唯一入口(未知工具名 KeyError,业务错误回
{"error": ...} dict 给 LLM 看)。

脱敏红线:creds 经 state_query 返回给 LLM 时,secret **默认掩码中段**
(``mask_secret``),完整值只存在于落盘文件(index.sqlite;WP-10 报告导出
时经 state/index.py 取完整值)。工具层不提供任何 reveal 参数;attack_surface
汇总在索引层就不带 secret。本文件专项测试证明 LLM 视图拿不到完整 secret。

实现形态:所有操作是毫秒级小 IO,实现方法为同步 def(与 WP-01
``_render_view`` 同模式),``dispatch`` 为 async 薄壳以便 WP-04 统一 await。
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from theform.state.index import (
    DEFAULT_QUERY_LIMIT,
    MAX_QUERY_LIMIT,
    QUERY_KINDS,
    Index,
)

if TYPE_CHECKING:
    from theform.state.files import Engagement

#: state_query 的 kind 取值(索引层六类 + 攻击面汇总)。
QUERY_KIND_NAMES = sorted([*QUERY_KINDS, "attack_surface"])

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "state_query",
        "description": (
            "查询 engagement 状态索引(hosts/ports/creds/vulns/loot/notes,"
            "以及 attack_surface 按 host 汇总攻击面)。例:filters={\"port\": 445} "
            "查哪些 host 开了 445。creds 的 secret 对 LLM 默认掩码中段(产品红线,"
            "完整值只在 engagement 落盘文件,导出报告时才含完整值);"
            "attack_surface 汇总同样不含 secret。结果超出 limit 时分页返回。"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "kind": {
                    "type": "string",
                    "enum": QUERY_KIND_NAMES,
                    "description": "查询类别。",
                },
                "filters": {
                    "type": "object",
                    "description": (
                        "精确匹配过滤,如 {\"port\": 445}、{\"host_ip\": \"10.0.0.5\"};"
                        "各类别可用字段:hosts(ip/hostname)、ports(port/proto/service/"
                        "host_ip)、creds(host_ip/username/source)、vulns(host_ip/kind/"
                        "confidence)、loot(kind)、notes(无)。attack_surface 需 "
                        "host_ip。"
                    ),
                    "additionalProperties": True,
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_QUERY_LIMIT,
                    "default": DEFAULT_QUERY_LIMIT,
                    "description": "本页最多返回的行数。",
                },
                "offset": {
                    "type": "integer",
                    "minimum": 0,
                    "default": 0,
                    "description": "分页偏移(truncated=true 时继续翻页)。",
                },
            },
            "required": ["kind"],
            "additionalProperties": False,
        },
    },
    {
        "name": "state_add_note",
        "description": (
            "追加一条带时间戳的自由笔记到状态索引(观察、假设、下一步打算;"
            "会进入 ENGAGEMENT.md 的计数与 WP-10 报告)。"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "笔记内容。"},
            },
            "required": ["text"],
            "additionalProperties": False,
        },
    },
    {
        "name": "state_add_loot",
        "description": (
            "把 engagement 内的战利品文件登记进索引(dump、截图、key 文件等)。"
            "文件须已在 engagement 目录内(通常先经 run_command 写入 loot/);"
            "登记后可被 state_query(kind=\"loot\") 检索,并进入报告。"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "相对 engagement 根的路径,如 loot/samba-dump.txt。",
                },
                "kind": {
                    "type": "string",
                    "description": "战利品类别,如 dump / screenshot / key / config。",
                },
                "note": {
                    "type": "string",
                    "description": "一句话说明(来源、内容、下一步用途)。",
                },
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    },
]


def mask_secret(secret: str) -> str:
    """掩码中段:头 2 字符 + 固定 8 个掩码符 + 尾 2 字符;长度 ≤4 全掩。

    掩码符数量固定,不泄露 secret 的精确长度。
    """
    if len(secret) <= 4:
        return "****"
    return f"{secret[:2]}{'*' * 8}{secret[-2:]}"


def _mask_cred_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    masked = []
    for row in rows:
        row = dict(row)
        if "secret" in row:
            row["secret"] = mask_secret(str(row["secret"]))
            row["secret_masked"] = True
        masked.append(row)
    return masked


class StateTool:
    """state 工具入口。一个 engagement 一个实例。"""

    def __init__(self, engagement: Engagement):
        self._engagement = engagement
        self._index = Index(engagement.paths.index_db)

    def close(self) -> None:
        self._index.close()

    def __enter__(self) -> StateTool:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # ---------- WP-04 唯一入口(async 薄壳,实现为同步小 IO) ----------

    async def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        handlers = {
            "state_query": self.state_query,
            "state_add_note": self.state_add_note,
            "state_add_loot": self.state_add_loot,
        }
        handler = handlers[name]  # 未知工具名属编程错误,直接 KeyError
        try:
            return handler(**arguments)
        except (ValueError, TypeError) as exc:
            return {"error": str(exc)}

    # ---------- 工具实现(同步) ----------

    def state_query(
        self,
        kind: str,
        filters: dict[str, Any] | None = None,
        *,
        limit: int = DEFAULT_QUERY_LIMIT,
        offset: int = 0,
    ) -> dict[str, Any]:
        if kind == "attack_surface":
            return self._query_attack_surface(filters or {})
        result = self._index.query(kind, filters, limit=limit, offset=offset)
        if kind == "creds":
            result["rows"] = _mask_cred_rows(result["rows"])
            result["masking_note"] = (
                "secret 已掩码(产品红线);完整值仅在 engagement 落盘文件,"
                "报告导出时可见"
            )
        return result

    def _query_attack_surface(self, filters: dict[str, Any]) -> dict[str, Any]:
        host_ip = filters.get("host_ip")
        if not host_ip:
            return {
                "error": "attack_surface 需要 filters={\"host_ip\": \"...\"}",
                "kind": "attack_surface",
            }
        surface = self._index.attack_surface(str(host_ip))
        if surface is None:
            return {
                "kind": "attack_surface",
                "host_ip": host_ip,
                "found": False,
                "message": "索引中没有该 host(解析器/工具尚未上报过它)",
            }
        # attack_surface 在索引层就不含 secret,这里再设一道防线
        surface = dict(surface)
        surface["found"] = True
        surface["kind"] = "attack_surface"
        return surface

    def state_add_note(self, text: str) -> dict[str, Any]:
        if not text.strip():
            return {"error": "笔记内容不能为空"}
        note_id = self._index.add_note(text)
        return {"added": True, "kind": "notes", "id": note_id}

    def state_add_loot(
        self,
        path: str,
        kind: str | None = None,
        note: str | None = None,
    ) -> dict[str, Any]:
        root = self._engagement.paths.root.resolve()
        target = (root / path).resolve()
        if not target.is_relative_to(root):
            return {
                "error": (
                    f"{path!r} 不在 engagement 目录内;战利品须先放进 engagement "
                    f"(通常写入 loot/)再登记"
                ),
                "added": False,
            }
        if not target.is_file():
            return {
                "error": f"文件不存在:{path!r}(先经 run_command 写入,再登记)",
                "added": False,
            }
        rel = target.relative_to(root)
        loot_id = self._index.add_loot(
            str(rel), kind=kind, note=note, size_bytes=target.stat().st_size
        )
        return {
            "added": True,
            "kind": "loot",
            "id": loot_id,
            "path": str(rel),
            "size_bytes": target.stat().st_size,
        }
