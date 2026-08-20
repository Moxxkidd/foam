"""LLM 后端统一接口与共享基础设施。

归一化约定(模型/provider 差异不泄漏到上层):

- 事件流只有三种事件:`TextDelta`(文本增量)、`ToolCall`(完整工具调用帧,
  `arguments` 必为合法 JSON 对象)、`Usage`(token 用量,流末恰好一次)。
- 事件顺序:文本增量按到达顺序产出;工具调用在流结束时按 provider 顺序
  一次性产出;`Usage` 最后。provider 的常规行为是先文本后工具调用,两种
  后端在此常规路径上产出完全一致的事件序列。
- 消息模型与 OpenAI/Anthropic 两家 API 对齐:system/user/assistant/tool
  四种角色,assistant 可携带 `tool_calls`,tool 角色携带 `tool_call_id`。

错误模型:`BackendError` 树结构化区分「网络问题(可重试)」与
「provider 拒绝(不可重试)」,`retryable` 标记供上层(WP-04)决策。
任何错误消息都不得包含 API key 片段(红线:密钥只走环境变量)。
"""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from typing import Any, Literal

import httpx

Role = Literal["system", "user", "assistant", "tool"]


# ---------------------------------------------------------------------------
# 事件与消息模型
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TextDelta:
    """文本增量事件。"""

    text: str


@dataclass(frozen=True)
class ToolCall:
    """完整工具调用帧(流式片段已在后端内拼合、参数已解析为 dict)。

    同一个 dataclass 既作为流事件,也作为 assistant 历史消息里的
    `tool_calls` 元素,避免两套表示互相转换。
    """

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class Usage:
    """token 用量;provider 未上报的字段为 0。"""

    input_tokens: int = 0
    output_tokens: int = 0


BackendEvent = TextDelta | ToolCall | Usage


def event_to_dict(event: BackendEvent) -> dict[str, Any]:
    """事件的规范化可序列化形式(契约测试与将来 replay 的比对基准)。"""
    if isinstance(event, TextDelta):
        return {"type": "text_delta", "text": event.text}
    if isinstance(event, ToolCall):
        return {
            "type": "tool_call",
            "id": event.id,
            "name": event.name,
            "arguments": event.arguments,
        }
    if isinstance(event, Usage):
        return {
            "type": "usage",
            "input_tokens": event.input_tokens,
            "output_tokens": event.output_tokens,
        }
    raise TypeError(f"未知事件类型: {type(event)!r}")


def event_to_canonical_json(event: BackendEvent) -> str:
    """事件的字节级规范化形式(sort_keys),用于跨后端逐字节比对。"""
    return json.dumps(event_to_dict(event), ensure_ascii=False, sort_keys=True)


@dataclass(frozen=True)
class ToolSpec:
    """后端中立的工具描述;`parameters` 为 JSON Schema 对象。"""

    name: str
    description: str
    parameters: dict[str, Any]


@dataclass(frozen=True)
class Message:
    """后端中立的消息。

    - role == "assistant" 时可携带 `tool_calls`;
    - role == "tool"(工具结果)时 `tool_call_id` 必填,`content` 为结果文本。
    """

    role: Role
    content: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    tool_call_id: str | None = None

    @classmethod
    def system(cls, content: str) -> Message:
        return cls(role="system", content=content)

    @classmethod
    def user(cls, content: str) -> Message:
        return cls(role="user", content=content)

    @classmethod
    def assistant(
        cls, content: str = "", tool_calls: Sequence[ToolCall] = ()
    ) -> Message:
        return cls(role="assistant", content=content, tool_calls=tuple(tool_calls))

    @classmethod
    def tool_result(cls, tool_call_id: str, content: str) -> Message:
        return cls(role="tool", content=content, tool_call_id=tool_call_id)


# ---------------------------------------------------------------------------
# 结构化错误
# ---------------------------------------------------------------------------


class BackendError(Exception):
    """所有后端错误的基类。`retryable` 提示上层是否值得重试。"""

    retryable: bool = False

    def __init__(
        self,
        message: str,
        *,
        provider: str | None = None,
        status_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.provider = provider
        self.status_code = status_code


class ConfigError(BackendError):
    """配置缺失(如未设置 API key 环境变量)。错误消息不得含 key 片段。"""


class NetworkError(BackendError):
    """连接失败/DNS/TLS 等传输层问题。"""

    retryable = True


class RequestTimeoutError(NetworkError):
    """连接/读取/写入超时。"""


class RateLimitError(BackendError):
    """HTTP 429 限流;`retry_after` 来自 Retry-After 响应头(可能为 None)。"""

    retryable = True

    def __init__(
        self,
        message: str,
        *,
        provider: str | None = None,
        status_code: int | None = 429,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message, provider=provider, status_code=status_code)
        self.retry_after = retry_after


class ServerError(BackendError):
    """provider 5xx(含过载)。"""

    retryable = True


class AuthError(BackendError):
    """401/403 鉴权失败(key 缺失、错误或无权限);消息不得含 key 片段。"""


class ModerationError(BackendError):
    """provider 内容审核拦截(带特征文案的 4xx / content_filter / refusal)。

    属「provider 拒绝」,上层应如实呈现、不得改写 prompt 规避(红线)。
    """


class InvalidRequestError(BackendError):
    """其它 4xx(请求本身不合法:模型名错、参数错等)。"""


class StreamError(BackendError):
    """流式响应中断或数据块无法解析。"""

    retryable = True


class MalformedToolCallError(BackendError):
    """模型输出的工具参数不是合法 JSON 对象。

    携带 `raw_arguments` 原文,供上层回灌给模型纠正或记入实测日志
    (WP-03 实测的「参数合法 JSON 率」即以此统计)。
    """

    def __init__(
        self,
        message: str,
        *,
        provider: str | None = None,
        tool_name: str = "",
        call_id: str = "",
        raw_arguments: str = "",
    ) -> None:
        super().__init__(message, provider=provider)
        self.tool_name = tool_name
        self.call_id = call_id
        self.raw_arguments = raw_arguments


# ---------------------------------------------------------------------------
# 共享判定与转换辅助
# ---------------------------------------------------------------------------

# provider 审核拦截的特征文案(小写子串匹配,仅作用于 4xx 响应体与
# 流内 error 对象,不会误伤正常内容)。覆盖中英文常见表述。
MODERATION_MARKERS: tuple[str, ...] = (
    "content_filter",
    "content filter",
    "contentfilter",
    "moderation",
    "risk",
    "sensitive",
    "safety",
    "unsafe",
    "refusal",
    "refused",
    "违规",
    "违反",
    "敏感",
    "审核",
    "拦截",
)


def looks_like_moderation(payload_text: str) -> bool:
    """响应体/错误对象文本是否命中审核拦截特征。"""
    text = payload_text.lower()
    return any(marker in text for marker in MODERATION_MARKERS)


def map_http_error(
    status_code: int,
    body_text: str,
    *,
    provider: str,
    retry_after: float | None = None,
) -> BackendError:
    """把非 2xx 响应映射为结构化错误(返回而不抛出,便于单测)。

    映射规则:401 → Auth;403 → 命中审核特征则 Moderation 否则 Auth;
    429 → RateLimit;5xx → Server;其余 4xx 命中审核特征 → Moderation,
    否则 InvalidRequest。消息只带状态码与响应体摘录,绝不含请求头/key。
    """
    detail = body_text.strip()[:500]
    where = f"[{provider}] HTTP {status_code}"
    if status_code == 401:
        return AuthError(
            f"{where} 鉴权失败:请检查 API key 环境变量是否设置正确。{detail}",
            provider=provider,
            status_code=status_code,
        )
    if status_code == 403:
        if looks_like_moderation(body_text):
            return ModerationError(
                f"{where} provider 审核拦截: {detail}",
                provider=provider,
                status_code=status_code,
            )
        return AuthError(
            f"{where} 无权限: {detail}", provider=provider, status_code=status_code
        )
    if status_code == 429:
        return RateLimitError(
            f"{where} 限流: {detail}",
            provider=provider,
            retry_after=retry_after,
        )
    if status_code >= 500:
        return ServerError(
            f"{where} provider 服务端错误: {detail}",
            provider=provider,
            status_code=status_code,
        )
    if looks_like_moderation(body_text):
        return ModerationError(
            f"{where} provider 审核拦截: {detail}",
            provider=provider,
            status_code=status_code,
        )
    return InvalidRequestError(
        f"{where} 请求不合法: {detail}", provider=provider, status_code=status_code
    )


def map_transport_error(exc: httpx.TransportError, *, provider: str) -> BackendError:
    """httpx 传输层异常 → 结构化错误(超时是 NetworkError 的子类)。"""
    if isinstance(exc, httpx.TimeoutException):
        return RequestTimeoutError(f"[{provider}] 请求超时: {exc}", provider=provider)
    return NetworkError(f"[{provider}] 网络错误: {exc}", provider=provider)


def parse_tool_arguments(
    raw: str, *, name: str, call_id: str, provider: str
) -> dict[str, Any]:
    """把模型输出的工具参数原文解析为 dict;非法则抛 MalformedToolCallError。"""
    if not raw.strip():
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise MalformedToolCallError(
            f"[{provider}] 工具 {name!r} 的参数不是合法 JSON: {exc};"
            f"原文摘录: {raw[:300]!r}",
            provider=provider,
            tool_name=name,
            call_id=call_id,
            raw_arguments=raw,
        ) from exc
    if not isinstance(value, dict):
        raise MalformedToolCallError(
            f"[{provider}] 工具 {name!r} 的参数不是 JSON 对象: {raw[:300]!r}",
            provider=provider,
            tool_name=name,
            call_id=call_id,
            raw_arguments=raw,
        )
    return value


def require_env_key(env_var: str, *, provider: str) -> str:
    """只从环境变量读取 API key;缺失时报错且消息不含任何 key 片段。"""
    key = os.environ.get(env_var, "").strip()
    if not key:
        raise ConfigError(
            f"[{provider}] 缺少 API key:请设置环境变量 {env_var}"
            "(密钥只走环境变量,不写入任何文件)",
            provider=provider,
        )
    return key


def parse_retry_after(value: str | None) -> float | None:
    """解析 Retry-After 响应头(仅支持秒数形式;解析失败返回 None)。"""
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def redact_secret(text: str, secret: str) -> str:
    """抹除文本中出现的密钥原文。

    部分 provider 的错误响应体会回显请求 key(如 "Incorrect API key
    provided: sk-xxx"),直接进入异常消息就会污染日志——红线要求任何
    日志/错误不得出现真实 key,故所有引用 provider 原文的位置先过本函数。
    """
    if not secret:
        return text
    return text.replace(secret, "***")


async def iter_sse_data(response: httpx.Response) -> AsyncIterator[str]:
    """逐条产出 SSE 的 data 载荷。

    忽略 `event:`/`id:`/`retry:` 行与注释行(两个 provider 的事件类型都
    已在 data 的 JSON 里);同一事件的多行 data 按 SSE 规范以换行拼接。
    """
    buffer: list[str] = []
    async for line in response.aiter_lines():
        line = line.rstrip("\r")
        if line == "":
            if buffer:
                yield "\n".join(buffer)
                buffer.clear()
            continue
        if line.startswith(":"):
            continue
        if line.startswith("data:"):
            data = line[len("data:") :]
            if data.startswith(" "):
                data = data[1:]
            buffer.append(data)
    if buffer:
        yield "\n".join(buffer)


def default_timeout() -> httpx.Timeout:
    """默认超时:连接 10s,流式读取 300s(LLM 长停顿属正常),写 30s。"""
    return httpx.Timeout(connect=10.0, read=300.0, write=30.0, pool=10.0)


# ---------------------------------------------------------------------------
# 后端抽象基类
# ---------------------------------------------------------------------------


class LLMBackend(ABC):
    """统一后端接口。

    `chat()` 为异步生成器:逐事件产出,出错时抛 `BackendError` 子类。
    实现类在构造时即校验配置(缺 key 立即报 ConfigError,fail-fast)。
    """

    provider: str = "unknown"

    @abstractmethod
    def chat(
        self,
        messages: Sequence[Message],
        tools: Sequence[ToolSpec] | None = None,
    ) -> AsyncIterator[BackendEvent]:
        """发起一次流式对话,产出归一化事件流。"""

    @abstractmethod
    async def aclose(self) -> None:
        """释放底层连接资源(持有 HTTP 客户端的实现必须覆盖)。"""

    async def __aenter__(self) -> LLMBackend:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()
