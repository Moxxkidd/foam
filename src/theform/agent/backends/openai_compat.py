"""OpenAI 兼容端点万能适配(chat/completions SSE 流式)。

适配目标:Kimi K3(优先实测)、DeepSeek、GLM、OpenRouter 等一切实现了
OpenAI chat/completions 流式协议的端点。`base_url`/`model` 由调用方配置,
API key 只从环境变量读取(默认 `THEFORM_LLM_API_KEY`)。

要点:
- `stream_options.include_usage` 默认开启以取回流末 usage;个别端点不认
  该字段时可构造时传 `include_usage=False` 关闭(Usage 事件仍会产出,
  字段为 0)。
- assistant 历史消息的 `content` 在携带 tool_calls 时按 OpenAI 惯例置
  null;`extra_body` 可附加 provider 特有参数(如 temperature)。
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Mapping, Sequence
from typing import Any

import httpx

from theform.agent.backends.base import (
    BackendEvent,
    LLMBackend,
    Message,
    ModerationError,
    RateLimitError,
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

ENV_API_KEY = "THEFORM_LLM_API_KEY"


class _ToolCallBuilder:
    """把 OpenAI 流式 tool_calls 片段(index 定位)拼成完整帧。"""

    def __init__(self) -> None:
        self._id_parts: list[str] = []
        self._name_parts: list[str] = []
        self._arg_parts: list[str] = []

    def feed(self, fragment: Mapping[str, Any]) -> None:
        if fragment.get("id"):
            self._id_parts.append(str(fragment["id"]))
        function = fragment.get("function") or {}
        if function.get("name"):
            self._name_parts.append(str(function["name"]))
        if function.get("arguments"):
            self._arg_parts.append(str(function["arguments"]))

    def build(self, *, provider: str) -> ToolCall:
        call_id = "".join(self._id_parts)
        name = "".join(self._name_parts)
        raw = "".join(self._arg_parts)
        return ToolCall(
            id=call_id,
            name=name,
            arguments=parse_tool_arguments(
                raw, name=name, call_id=call_id, provider=provider
            ),
        )


class OpenAICompatBackend(LLMBackend):
    """OpenAI 兼容端点后端。"""

    provider = "openai_compat"

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        env_key: str = ENV_API_KEY,
        include_usage: bool = True,
        extra_body: Mapping[str, Any] | None = None,
        timeout: httpx.Timeout | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        # base_url 按 OpenAI 生态惯例包含版本路径,如
        # https://api.moonshot.cn/v1;此处只拼接端点相对路径。
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._include_usage = include_usage
        self._extra_body = dict(extra_body or {})
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
        payload: dict[str, Any] = {
            "model": self._model,
            "messages": [self._message_to_openai(m) for m in messages],
            "stream": True,
        }
        if self._include_usage:
            payload["stream_options"] = {"include_usage": True}
        if tools:
            payload["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters,
                    },
                }
                for t in tools
            ]
        payload.update(self._extra_body)
        return payload

    @staticmethod
    def _message_to_openai(message: Message) -> dict[str, Any]:
        if message.role in ("system", "user"):
            return {"role": message.role, "content": message.content}
        if message.role == "assistant":
            data: dict[str, Any] = {
                "role": "assistant",
                # 携带 tool_calls 时 OpenAI 惯例 content 为 null
                "content": message.content or None,
            }
            if message.tool_calls:
                data["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.name,
                            "arguments": json.dumps(tc.arguments, ensure_ascii=False),
                        },
                    }
                    for tc in message.tool_calls
                ]
            return data
        # role == "tool"
        return {
            "role": "tool",
            "tool_call_id": message.tool_call_id,
            "content": message.content,
        }

    # ---- 流式会话 -----------------------------------------------------

    async def chat(
        self,
        messages: Sequence[Message],
        tools: Sequence[ToolSpec] | None = None,
    ) -> AsyncIterator[BackendEvent]:
        payload = self._build_payload(messages, tools)
        headers = {"Authorization": f"Bearer {self._api_key}"}
        url = f"{self._base_url}/chat/completions"
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
        builders: dict[int, _ToolCallBuilder] = {}
        order: list[int] = []
        usage = Usage()
        async for data in iter_sse_data(response):
            if data == "[DONE]":
                break
            try:
                chunk = json.loads(data)
            except json.JSONDecodeError as exc:
                raise StreamError(
                    f"[{self.provider}] 无法解析的流式数据块:"
                    f" {redact_secret(data[:200], self._api_key)!r}",
                    provider=self.provider,
                ) from exc

            # 部分端点(如 OpenRouter)在 200 流内返回 error 对象
            stream_error = chunk.get("error")
            if stream_error:
                self._raise_stream_error(stream_error)

            for choice in chunk.get("choices") or []:
                delta = choice.get("delta") or {}
                content = delta.get("content")
                if content:
                    yield TextDelta(text=str(content))
                for fragment in delta.get("tool_calls") or []:
                    index = int(fragment.get("index", 0))
                    builder = builders.get(index)
                    if builder is None:
                        builder = builders[index] = _ToolCallBuilder()
                        order.append(index)
                    builder.feed(fragment)
                if choice.get("finish_reason") == "content_filter":
                    raise ModerationError(
                        f"[{self.provider}] provider 审核拦截:"
                        " finish_reason=content_filter",
                        provider=self.provider,
                    )

            chunk_usage = chunk.get("usage")
            if chunk_usage:
                usage = Usage(
                    input_tokens=int(chunk_usage.get("prompt_tokens") or 0),
                    output_tokens=int(chunk_usage.get("completion_tokens") or 0),
                )

        # 工具调用片段无单独完成信号,统一在流末按 index 顺序产出完整帧
        for index in order:
            yield builders[index].build(provider=self.provider)
        yield usage

    def _raise_stream_error(self, error: Any) -> None:
        text = (
            error if isinstance(error, str) else json.dumps(error, ensure_ascii=False)
        )
        text = redact_secret(text, self._api_key)
        if looks_like_moderation(text):
            raise ModerationError(
                f"[{self.provider}] provider 审核拦截: {text[:500]}",
                provider=self.provider,
            )
        code = error.get("code") if isinstance(error, Mapping) else None
        if code == 429:
            raise RateLimitError(
                f"[{self.provider}] 限流: {text[:500]}", provider=self.provider
            )
        raise StreamError(
            f"[{self.provider}] 流内错误: {text[:500]}", provider=self.provider
        )
