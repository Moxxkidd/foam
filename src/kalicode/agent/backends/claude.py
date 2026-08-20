"""Anthropic Messages API 后端(httpx 直连,不引 SDK,控制依赖面)。

与 OpenAI 兼容层的差异全部收敛在本文件内,对上层只暴露 base.py 的
归一化事件流:

- system 消息抽取为顶层 `system` 参数(多条以空行拼接);
- tool 结果(role="tool")映射为 user 消息里的 tool_result 块,连续的
  tool 结果与相邻同 role 消息按 Anthropic「严格交替」要求合并;
- 工具 schema 映射为 {name, description, input_schema};
- `max_tokens` 是 Anthropic 必填项,此处给默认值 8192(可构造覆盖),
  属本后端内部细节,不泄漏到上层接口;
- stop_reason="refusal" 与流内 error 事件映射为结构化错误。

`base_url` 按 Anthropic 生态惯例为 API 根(不含 /v1),端点拼 /v1/messages。
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Sequence
from typing import Any

import httpx

from kalicode.agent.backends.base import (
    BackendEvent,
    LLMBackend,
    Message,
    ModerationError,
    ServerError,
    StreamError,
    TextDelta,
    ToolCall,
    ToolSpec,
    Usage,
    default_timeout,
    iter_sse_data,
    looks_like_moderation,
    map_http_error,
    map_transport_error,
    parse_retry_after,
    parse_tool_arguments,
    redact_secret,
    require_env_key,
)

ENV_API_KEY = "KALICODE_ANTHROPIC_API_KEY"
ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_BASE_URL = "https://api.anthropic.com"
DEFAULT_MAX_TOKENS = 8192


class _ToolUseBuilder:
    """把 content_block 流式片段(input_json_delta)拼成完整 tool_use。"""

    def __init__(self, call_id: str, name: str) -> None:
        self._call_id = call_id
        self._name = name
        self._json_parts: list[str] = []

    def feed(self, partial_json: str) -> None:
        if partial_json:
            self._json_parts.append(partial_json)

    def build(self, *, provider: str) -> ToolCall:
        raw = "".join(self._json_parts)
        return ToolCall(
            id=self._call_id,
            name=self._name,
            arguments=parse_tool_arguments(
                raw, name=self._name, call_id=self._call_id, provider=provider
            ),
        )


class ClaudeBackend(LLMBackend):
    """Anthropic Messages 流式后端。"""

    provider = "claude"

    def __init__(
        self,
        *,
        model: str,
        base_url: str = DEFAULT_BASE_URL,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        env_key: str = ENV_API_KEY,
        timeout: httpx.Timeout | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._max_tokens = max_tokens
        self._api_key = require_env_key(env_key, provider=self.provider)
        self._client = httpx.AsyncClient(
            timeout=timeout or default_timeout(), transport=transport
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    # ---- 请求构造 -----------------------------------------------------

    def _build_payload(
        self, messages: Sequence[Message], tools: Sequence[ToolSpec] | None
    ) -> dict[str, Any]:
        system, converted = self._convert_messages(messages)
        payload: dict[str, Any] = {
            "model": self._model,
            "max_tokens": self._max_tokens,
            "messages": converted,
            "stream": True,
        }
        if system:
            payload["system"] = system
        if tools:
            payload["tools"] = [
                {
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.parameters,
                }
                for t in tools
            ]
        return payload

    @classmethod
    def _convert_messages(
        cls, messages: Sequence[Message]
    ) -> tuple[str | None, list[dict[str, Any]]]:
        system = "\n\n".join(
            m.content for m in messages if m.role == "system" and m.content
        )
        converted: list[dict[str, Any]] = []
        for message in messages:
            if message.role == "system":
                continue
            if message.role == "user":
                cls._append_role(converted, "user", message.content)
            elif message.role == "assistant":
                blocks: list[dict[str, Any]] = []
                if message.content:
                    blocks.append({"type": "text", "text": message.content})
                blocks.extend(
                    {
                        "type": "tool_use",
                        "id": tc.id,
                        "name": tc.name,
                        "input": tc.arguments,
                    }
                    for tc in message.tool_calls
                )
                cls._append_role(converted, "assistant", blocks)
            else:  # role == "tool":映射为 user 消息内的 tool_result 块
                block = {
                    "type": "tool_result",
                    "tool_use_id": message.tool_call_id,
                    "content": message.content,
                }
                cls._append_role(converted, "user", [block])
        return system or None, converted

    @staticmethod
    def _append_role(converted: list[dict[str, Any]], role: str, content: Any) -> None:
        """追加消息并合并相邻同 role(Anthropic 要求 user/assistant 严格交替)。"""
        if converted and converted[-1]["role"] == role:
            converted[-1]["content"] = _merge_content(converted[-1]["content"], content)
        else:
            converted.append({"role": role, "content": content})

    # ---- 流式会话 -----------------------------------------------------

    async def chat(
        self,
        messages: Sequence[Message],
        tools: Sequence[ToolSpec] | None = None,
    ) -> AsyncIterator[BackendEvent]:
        payload = self._build_payload(messages, tools)
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": ANTHROPIC_VERSION,
        }
        url = f"{self._base_url}/v1/messages"
        try:
            async with self._client.stream(
                "POST", url, json=payload, headers=headers
            ) as response:
                if response.status_code != 200:
                    body = (await response.aread()).decode("utf-8", "replace")
                    raise map_http_error(
                        response.status_code,
                        redact_secret(body, self._api_key),
                        provider=self.provider,
                        retry_after=parse_retry_after(
                            response.headers.get("retry-after")
                        ),
                    )
                async for event in self._parse_stream(response):
                    yield event
        except httpx.TransportError as exc:
            raise map_transport_error(exc, provider=self.provider) from exc

    async def _parse_stream(
        self, response: httpx.Response
    ) -> AsyncIterator[BackendEvent]:
        builders: dict[int, _ToolUseBuilder] = {}
        input_tokens = 0
        output_tokens = 0
        async for data in iter_sse_data(response):
            try:
                event = json.loads(data)
            except json.JSONDecodeError as exc:
                raise StreamError(
                    f"[{self.provider}] 无法解析的流式数据块:"
                    f" {redact_secret(data[:200], self._api_key)!r}",
                    provider=self.provider,
                ) from exc

            event_type = event.get("type")
            if event_type == "message_start":
                start_usage = (event.get("message") or {}).get("usage") or {}
                input_tokens = int(start_usage.get("input_tokens") or 0)
                output_tokens = int(start_usage.get("output_tokens") or 0)
            elif event_type == "content_block_start":
                block = event.get("content_block") or {}
                if block.get("type") == "tool_use":
                    builders[self._block_index(event)] = _ToolUseBuilder(
                        call_id=str(block.get("id") or ""),
                        name=str(block.get("name") or ""),
                    )
            elif event_type == "content_block_delta":
                delta = event.get("delta") or {}
                delta_type = delta.get("type")
                if delta_type == "text_delta":
                    text = delta.get("text")
                    if text:
                        yield TextDelta(text=str(text))
                elif delta_type == "input_json_delta":
                    builder = builders.get(self._block_index(event))
                    if builder is not None:
                        builder.feed(str(delta.get("partial_json") or ""))
                # 其它 delta 类型(如 thinking)本版本不消费,忽略
            elif event_type == "content_block_stop":
                builder = builders.pop(self._block_index(event), None)
                if builder is not None:
                    yield builder.build(provider=self.provider)
            elif event_type == "message_delta":
                delta = event.get("delta") or {}
                if delta.get("stop_reason") == "refusal":
                    raise ModerationError(
                        f"[{self.provider}] provider 拒绝生成: stop_reason=refusal",
                        provider=self.provider,
                    )
                delta_usage = event.get("usage") or {}
                if delta_usage:
                    output_tokens = int(delta_usage.get("output_tokens") or 0)
            elif event_type == "error":
                self._raise_stream_error(event.get("error") or {})
            # ping / message_stop / 未知类型:忽略

        yield Usage(input_tokens=input_tokens, output_tokens=output_tokens)

    def _block_index(self, event: Any) -> int:
        """content_block_* 事件的 index;缺失/非法属 provider 数据坏。"""
        try:
            return int(event["index"])
        except (KeyError, TypeError, ValueError) as exc:
            raise StreamError(
                f"[{self.provider}] content_block 事件缺少合法 index:"
                f" {str(event)[:200]!r}",
                provider=self.provider,
            ) from exc

    def _raise_stream_error(self, error: Any) -> None:
        text = (
            error if isinstance(error, str) else json.dumps(error, ensure_ascii=False)
        )
        text = redact_secret(text, self._api_key)
        error_type = error.get("type") if isinstance(error, dict) else None
        if error_type == "overloaded_error":
            raise ServerError(
                f"[{self.provider}] provider 过载: {text[:500]}",
                provider=self.provider,
                status_code=529,
            )
        if looks_like_moderation(text):
            raise ModerationError(
                f"[{self.provider}] provider 审核拦截: {text[:500]}",
                provider=self.provider,
            )
        raise StreamError(
            f"[{self.provider}] 流内错误: {text[:500]}", provider=self.provider
        )


def _merge_content(old: Any, new: Any) -> list[dict[str, Any]]:
    """把两段 content(纯文本或块列表)合并为块列表,丢弃空文本块。"""

    def as_blocks(content: Any) -> list[dict[str, Any]]:
        if isinstance(content, str):
            return [{"type": "text", "text": content}] if content else []
        return [
            block
            for block in content
            if not (block.get("type") == "text" and not block.get("text"))
        ]

    return as_blocks(old) + as_blocks(new)
