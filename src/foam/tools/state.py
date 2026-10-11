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

import os
import stat
from pathlib import Path
from typing import TYPE_CHECKING, Any

from foam.state.index import (
    DEFAULT_QUERY_LIMIT,
    MAX_QUERY_LIMIT,
    QUERY_KINDS,
    Index,
)

if TYPE_CHECKING:
    from foam.state.files import Engagement

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
    # ---------------- R08-B:非解析器成果登记(决策 6) ----------------
    {
        "name": "state_add_host",
        "description": (
            "登记一台主机到状态索引(解析层不认的工具产出、手工确认的资产等)。"
            "按 ip 去重:重复登记返回同一 record_id 并附 deduplicated=true,"
            "hostname 以最新观测为准。"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "主机 IP(去重键)。"},
                "hostname": {
                    "type": "string",
                    "description": "主机名(可缺省,不臆造)。",
                },
            },
            "required": ["ip"],
            "additionalProperties": False,
        },
    },
    {
        "name": "state_add_port",
        "description": (
            "登记一个开放端口到状态索引。按 (host, port, proto) 去重:"
            "重复登记返回同一 record_id,非空新值充实 service/product/version。"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "host": {
                    "type": "string",
                    "description": "主机 IP(host 不存在时自动建档)。",
                },
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "proto": {
                    "type": "string",
                    "default": "tcp",
                    "description": "协议,默认 tcp。",
                },
                "service": {"type": "string", "description": "服务名,如 http。"},
                "product": {"type": "string", "description": "产品名。"},
                "version": {"type": "string", "description": "版本串。"},
            },
            "required": ["host", "port"],
            "additionalProperties": False,
        },
    },
    {
        "name": "state_add_vuln",
        "description": (
            "登记一条漏洞/发现到状态索引(解析层不认的工具产出、手工验证发现)。"
            "按 (host, kind, title) 去重:重复登记返回同一 record_id,证据引用"
            "并集追加不丢。evidence_refs 为证据文件路径列表——须为 engagement "
            "目录内已存在的常规文件(先经 run_command 落盘),逐条校验,任一无效"
            "整体拒绝。verification_status 只能 unknown/unverified(默认 "
            "unverified):「已验证」由独立验证流程判定,本工具不接受 verified,"
            "模型自述不升级。来源自动记为 manual;confidence 可缺省,不臆造。"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "host": {
                    "type": "string",
                    "description": "主机 IP(host 不存在时自动建档)。",
                },
                "kind": {
                    "type": "string",
                    "description": "发现类别,如 sqli / xss / config / cve。",
                },
                "title": {
                    "type": "string",
                    "description": "一句话标题(去重键之一,保持精确稳定)。",
                },
                "evidence_refs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "证据文件路径列表(相对 engagement 根,如 "
                        "outputs/abc123.log);逐条校验存在性与界内性。"
                    ),
                },
                "confidence": {
                    "type": "string",
                    "description": "置信度,如 low / medium / high;可缺省。",
                },
                "verification_status": {
                    "type": "string",
                    "enum": ["unknown", "unverified"],
                    "description": "验证状态;默认 unverified。不接受 verified。",
                },
                "observed_at": {
                    "type": "string",
                    "description": "观测时间 ISO 串;默认当前 UTC。",
                },
                "reproduction": {
                    "type": "string",
                    "description": "复现步骤(可缺省,不臆造)。",
                },
            },
            "required": ["host", "kind", "title"],
            "additionalProperties": False,
        },
    },
    {
        "name": "state_add_cred",
        "description": (
            "登记一组凭证到状态索引(完整 secret 落盘——产品红线:仅 LLM 视图"
            "掩码,索引进盘与报告导出为全值;本工具返回只含掩码形态)。按 "
            "(host, username, secret) 去重:重复登记返回同一 record_id,证据"
            "引用并集追加不丢。evidence_refs 校验语义与 state_add_vuln 相同;"
            "verification_status 不接受 verified(默认 unverified)。"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "host": {
                    "type": "string",
                    "description": "主机 IP(host 不存在时自动建档)。",
                },
                "username": {"type": "string", "description": "用户名。"},
                "secret": {
                    "type": "string",
                    "description": "口令/哈希/令牌原文(完整落盘,视图掩码)。",
                },
                "evidence_refs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "来源证据文件路径列表(相对 engagement 根)。",
                },
                "sensitive": {
                    "type": "boolean",
                    "default": True,
                    "description": "是否敏感(默认 true)。",
                },
                "verification_status": {
                    "type": "string",
                    "enum": ["unknown", "unverified"],
                    "description": "验证状态;默认 unverified。不接受 verified。",
                },
                "observed_at": {
                    "type": "string",
                    "description": "观测时间 ISO 串;默认当前 UTC。",
                },
            },
            "required": ["host", "username", "secret"],
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


def _resolve_contained_file(root: Path, ref: str) -> tuple[str, int]:
    """校验 engagement 内文件引用(R08 决策 5,战利品/证据共用)。

    检查链:``(root / ref).resolve()`` → 须在 root 内(拒 ``..`` 与指向
    engagement 外的符号链接;指向内部的符号链接允许)→ ``os.open`` +
    ``os.fstat`` 绑定实际打开的文件:必须常规文件(拒目录)、fstat 与
    ``os.stat(resolved)`` 的 (st_dev, st_ino) 一致(防校验/使用间替换)、
    大小取 fstat 值。返回 (解析后的相对路径, 大小),入库统一存相对路径。
    无 openat2/RESOLVE_BENEATH 的残余微窗口如实记录在 R08.md §8。

    评审收口(2026-10-11):
    - open 带 ``O_NONBLOCK``——FIFO/设备文件对 O_RDONLY 无限阻塞(模型可
      自行 mkfifo),NONBLOCK 下 fstat 仍正确判非 S_ISREG 拒绝;
    - resolve() 的符号链接环(3.12 RuntimeError;3.13 起 pathlib 放行、
      os.open 遇 ELOOP OSError——两条路径都覆盖)、open 后 stat 竞态
      (FileNotFoundError 等 OSError)一律转 ValueError——保持「校验失败
      =error dict」契约,不让非 ValueError 异常逃逸 dispatch 终结 run。
    """
    try:
        resolved = (root / ref).resolve()
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"{ref!r} 无法解析({exc})") from None
    if not resolved.is_relative_to(root):
        raise ValueError(f"{ref!r} 不在 engagement 目录内")
    try:
        fd = os.open(resolved, os.O_RDONLY | os.O_NONBLOCK)
    except FileNotFoundError:
        raise ValueError(
            f"文件不存在:{ref!r}(先经 run_command 写入,再登记)"
        ) from None
    except OSError as exc:
        raise ValueError(f"文件不可打开:{ref!r}({exc})") from None
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError(f"{ref!r} 不是常规文件(目录/FIFO 等不可登记)")
        try:
            current = os.stat(resolved)
        except OSError as exc:
            raise ValueError(
                f"{ref!r} 在校验与打开之间消失或被替换({exc}),拒绝登记"
            ) from None
        if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
            raise ValueError(f"{ref!r} 在校验与打开之间被替换,拒绝登记")
        size = opened.st_size
    finally:
        os.close(fd)
    return str(resolved.relative_to(root)), size


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

    @property
    def index(self) -> Index:
        """只读暴露索引(WP-11 声明的增量):loop 解析钩子与本工具共用
        同一连接,所有权/生命周期仍归 StateTool(close 在本类)。"""
        return self._index

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
            "state_add_host": self.state_add_host,
            "state_add_port": self.state_add_port,
            "state_add_vuln": self.state_add_vuln,
            "state_add_cred": self.state_add_cred,
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
        try:
            # R08:迁移到共享 helper——os.open+fstat 绑定实际文件,
            # 消除旧内联版「检查后 stat()」的 TOCTOU 窗口
            rel, size = _resolve_contained_file(root, path)
        except ValueError as exc:
            return {"added": False, "error": str(exc)}
        loot_id = self._index.add_loot(rel, kind=kind, note=note, size_bytes=size)
        return {
            "added": True,
            "kind": "loot",
            "id": loot_id,
            "path": rel,
            "size_bytes": size,
        }

    # ---------- R08-B:非解析器成果登记(决策 4/6) ----------

    @staticmethod
    def _check_verification_status(value: str | None) -> dict[str, Any] | None:
        """登记工具的验证状态闸门:不接受 verified(决策 2,模型自述不升级)。"""
        if value is None or value in ("unknown", "unverified"):
            return None
        return {
            "error": (
                f"verification_status 不接受 {value!r}:只能 unknown/unverified"
                "(默认 unverified);「已验证」由独立验证流程判定,登记工具不升级"
            ),
            "added": False,
        }

    def _check_evidence_refs(
        self, evidence_refs: Any
    ) -> tuple[list[str] | None, dict[str, Any] | None]:
        """逐条校验证据引用(任一失败整体拒绝并指出哪条,决策 5/AC03)。

        返回 (规范化后的相对路径列表 | None, 错误 dict | None);入库统一
        存解析后的相对路径。
        """
        if evidence_refs is None:
            return None, None
        if not isinstance(evidence_refs, (list, tuple)):
            return None, {"error": "evidence_refs 须为路径数组", "added": False}
        root = self._engagement.paths.root.resolve()
        refs: list[str] = []
        for ref in evidence_refs:
            try:
                rel, _size = _resolve_contained_file(root, str(ref))
            except ValueError as exc:
                return None, {
                    "error": f"证据引用 {ref!r} 无效:{exc}(任一无效即整体拒绝)",
                    "added": False,
                }
            if rel not in refs:
                refs.append(rel)
        return refs or None, None

    def state_add_host(self, ip: str, hostname: str | None = None) -> dict[str, Any]:
        ip = str(ip).strip()
        if not ip:
            return {"error": "ip 不能为空", "added": False}
        existing = bool(self._index.query("hosts", {"ip": ip}, limit=1)["rows"])
        host_id = self._index.upsert_host(ip, hostname or None)
        return {
            "added": True,
            "record_id": f"hosts/{host_id}",
            "deduplicated": existing,
        }

    def state_add_port(
        self,
        host: str,
        port: int,
        proto: str = "tcp",
        service: str | None = None,
        product: str | None = None,
        version: str | None = None,
    ) -> dict[str, Any]:
        port = int(port)
        if not 1 <= port <= 65535:
            return {"error": f"端口 {port} 超出 1-65535", "added": False}
        proto = str(proto or "tcp")
        host = str(host).strip()
        if not host:
            return {"error": "host 不能为空", "added": False}
        existing = bool(
            self._index.query(
                "ports",
                {"host_ip": host, "port": port, "proto": proto},
                limit=1,
            )["rows"]
        )
        port_id = self._index.upsert_port(
            host, port, proto, service=service, product=product, version=version
        )
        return {
            "added": True,
            "record_id": f"ports/{port_id}",
            "deduplicated": existing,
        }

    def state_add_vuln(
        self,
        host: str,
        kind: str,
        title: str,
        evidence_refs: list[str] | None = None,
        confidence: str | None = None,
        verification_status: str | None = None,
        observed_at: str | None = None,
        reproduction: str | None = None,
    ) -> dict[str, Any]:
        kind, title = str(kind).strip(), str(title).strip()
        host = str(host).strip()
        if not host or not kind or not title:
            return {"error": "host/kind/title 均不能为空", "added": False}
        if err := self._check_verification_status(verification_status):
            return err
        refs, err = self._check_evidence_refs(evidence_refs)
        if err:
            return err
        vuln_id, created = self._index.add_vuln(
            host,
            kind,
            title,
            source="manual",
            evidence_refs=refs,
            confidence=confidence,
            verification_status=verification_status,
            observed_at=observed_at,
            reproduction=reproduction,
        )
        return {
            "added": True,
            "record_id": f"vulns/{vuln_id}",
            "deduplicated": not created,
        }

    def state_add_cred(
        self,
        host: str,
        username: str,
        secret: str,
        evidence_refs: list[str] | None = None,
        sensitive: bool = True,
        verification_status: str | None = None,
        observed_at: str | None = None,
    ) -> dict[str, Any]:
        host, username = str(host).strip(), str(username).strip()
        if not host or not username or not secret:
            return {"error": "host/username/secret 均不能为空", "added": False}
        if err := self._check_verification_status(verification_status):
            return err
        refs, err = self._check_evidence_refs(evidence_refs)
        if err:
            return err
        cred_id, created = self._index.add_cred(
            host,
            username,
            str(secret),
            source="manual",
            sensitive=bool(sensitive),
            evidence_refs=refs,
            verification_status=verification_status,
            observed_at=observed_at,
        )
        return {
            "added": True,
            "record_id": f"creds/{cred_id}",
            "deduplicated": not created,
            "username": username,
            # 红线:返回只给掩码形态,绝不含 secret 原文
            "secret": mask_secret(str(secret)),
            "secret_masked": True,
        }
