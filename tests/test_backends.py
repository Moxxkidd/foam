"""WP-03 后端层测试。

契约测试共用一个 fake HTTP server(`fake_llm_server`):同一个 handler
按请求路径分别以 OpenAI / Anthropic 两种格式应答,断言两个后端产出
**逐字节相同**的归一化事件序列。场景由请求体里的 `model` 字段切换,
便于在同一 server 上演示超时/5xx/限流/审核拦截/坏 JSON 等分支。

fixture 里的凭据全部是明显合成的(TESTONLY)。
"""

from __future__ import annotations

import json

import httpx
import pytest

from foam.agent.backends import claude, openai_compat
from foam.agent.backends.base import (
    AuthError,
    ConfigError,
    MalformedToolCallError,
    Message,
    ModerationError,
    NetworkError,
    RateLimitError,
    RequestTimeoutError,
    ServerError,
    StreamError,
    TextDelta,
    ToolCall,
    ToolSpec,
    Usage,
    event_to_canonical_json,
    redact_secret,
)

FAKE_OAI_KEY = "sk-TESTONLY-fake0000"
FAKE_CLAUDE_KEY = "sk-ant-TESTONLY-fake0000"

MESSAGES = [
    Message.system("你是授权渗透测试助手。"),
    Message.user("扫描 127.0.0.1 的开放端口。"),
]

TOOLS = [
    ToolSpec(
        name="run_command",
        description="在目标环境执行 shell 命令",
        parameters={
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "要执行的命令"},
            },
            "required": ["command"],
        },
    )
]

EXPECTED_HAPPY = [
    TextDelta(text="你好,"),
    TextDelta(text="世界"),
    ToolCall(
        id="tc-1", name="run_command", arguments={"command": "nmap -sV 127.0.0.1"}
    ),
    Usage(input_tokens=42, output_tokens=17),
]

REQUESTS: list[httpx.Request] = []


# ---------------------------------------------------------------------------
# fake server:流式载荷构造
# ---------------------------------------------------------------------------


def _oai_chunk(delta: dict, finish_reason: str | None = None) -> dict:
    return {
        "id": "chatcmpl-fake",
        "object": "chat.completion.chunk",
        "created": 0,
        "model": "fake-kimi-k3",
        "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}],
    }


def _oai_usage_chunk() -> dict:
    return {
        "id": "chatcmpl-fake",
        "object": "chat.completion.chunk",
        "created": 0,
        "model": "fake-kimi-k3",
        "choices": [],
        "usage": {"prompt_tokens": 42, "completion_tokens": 17, "total_tokens": 59},
    }


def _claude_message_start(with_usage: bool = True) -> dict:
    message = {
        "id": "msg_fake",
        "type": "message",
        "role": "assistant",
        "content": [],
        "model": "fake-claude",
        "stop_reason": None,
    }
    if with_usage:
        message["usage"] = {"input_tokens": 42, "output_tokens": 1}
    return {"type": "message_start", "message": message}


def _happy_openai_payloads() -> list:
    return [
        _oai_chunk({"role": "assistant", "content": ""}),
        _oai_chunk({"content": "你好,"}),
        _oai_chunk({"content": "世界"}),
        _oai_chunk(
            {
                "tool_calls": [
                    {
                        "index": 0,
                        "id": "tc-1",
                        "type": "function",
                        "function": {
                            "name": "run_command",
                            "arguments": '{"command": "nmap',
                        },
                    }
                ]
            }
        ),
        _oai_chunk(
            {
                "tool_calls": [
                    {"index": 0, "function": {"arguments": ' -sV 127.0.0.1"}'}}
                ]
            }
        ),
        _oai_chunk({}, "tool_calls"),
        _oai_usage_chunk(),
        "[DONE]",
    ]


def _happy_claude_payloads() -> list:
    return [
        _claude_message_start(),
        {
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "text", "text": ""},
        },
        {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": "你好,"},
        },
        {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": "世界"},
        },
        {"type": "content_block_stop", "index": 0},
        {
            "type": "content_block_start",
            "index": 1,
            "content_block": {
                "type": "tool_use",
                "id": "tc-1",
                "name": "run_command",
                "input": {},
            },
        },
        {
            "type": "content_block_delta",
            "index": 1,
            "delta": {"type": "input_json_delta", "partial_json": '{"command": "nmap'},
        },
        {
            "type": "content_block_delta",
            "index": 1,
            "delta": {"type": "input_json_delta", "partial_json": ' -sV 127.0.0.1"}'},
        },
        {"type": "content_block_stop", "index": 1},
        {
            "type": "message_delta",
            "delta": {"stop_reason": "tool_use", "stop_sequence": None},
            "usage": {"output_tokens": 17},
        },
        {"type": "message_stop"},
    ]


def _filter_finish_openai_payloads() -> list:
    return [
        _oai_chunk({"role": "assistant"}),
        _oai_chunk({"content": "检测到"}),
        _oai_chunk({}, "content_filter"),
        "[DONE]",
    ]


def _filter_finish_claude_payloads() -> list:
    return [
        _claude_message_start(),
        {
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "text", "text": ""},
        },
        {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": "检测到"},
        },
        {"type": "content_block_stop", "index": 0},
        {
            "type": "message_delta",
            "delta": {"stop_reason": "refusal", "stop_sequence": None},
            "usage": {"output_tokens": 3},
        },
        {"type": "message_stop"},
    ]


def _badjson_openai_payloads() -> list:
    return [
        _oai_chunk({"role": "assistant"}),
        _oai_chunk(
            {
                "tool_calls": [
                    {
                        "index": 0,
                        "id": "tc-1",
                        "type": "function",
                        "function": {
                            "name": "run_command",
                            "arguments": '{"command": "nmap',
                        },
                    }
                ]
            }
        ),
        _oai_chunk({"tool_calls": [{"index": 0, "function": {"arguments": " -sV"}}]}),
        _oai_chunk({}, "tool_calls"),
        "[DONE]",
    ]


def _badjson_claude_payloads() -> list:
    return [
        _claude_message_start(),
        {
            "type": "content_block_start",
            "index": 0,
            "content_block": {
                "type": "tool_use",
                "id": "tc-1",
                "name": "run_command",
                "input": {},
            },
        },
        {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "input_json_delta", "partial_json": '{"command": "nmap'},
        },
        {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "input_json_delta", "partial_json": " -sV"},
        },
        {"type": "content_block_stop", "index": 0},
        {
            "type": "message_delta",
            "delta": {"stop_reason": "tool_use", "stop_sequence": None},
            "usage": {"output_tokens": 17},
        },
        {"type": "message_stop"},
    ]


def _two_tools_openai_payloads() -> list:
    return [
        _oai_chunk({"role": "assistant"}),
        _oai_chunk(
            {
                "tool_calls": [
                    {
                        "index": 0,
                        "id": "tc-1",
                        "type": "function",
                        "function": {
                            "name": "run_command",
                            "arguments": '{"command": "id"}',
                        },
                    }
                ]
            }
        ),
        _oai_chunk(
            {
                "tool_calls": [
                    {
                        "index": 1,
                        "id": "tc-2",
                        "type": "function",
                        "function": {"name": "web_search", "arguments": '{"query":'},
                    }
                ]
            }
        ),
        _oai_chunk(
            {"tool_calls": [{"index": 1, "function": {"arguments": ' "cve"}'}}]}
        ),
        _oai_chunk({}, "tool_calls"),
        _oai_usage_chunk(),
        "[DONE]",
    ]


def _two_tools_claude_payloads() -> list:
    return [
        _claude_message_start(),
        {
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "text", "text": ""},
        },
        {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": "查一下"},
        },
        {"type": "content_block_stop", "index": 0},
        {
            "type": "content_block_start",
            "index": 1,
            "content_block": {
                "type": "tool_use",
                "id": "tc-1",
                "name": "run_command",
                "input": {},
            },
        },
        {
            "type": "content_block_delta",
            "index": 1,
            "delta": {"type": "input_json_delta", "partial_json": '{"command": "id"}'},
        },
        {"type": "content_block_stop", "index": 1},
        {
            "type": "content_block_start",
            "index": 2,
            "content_block": {
                "type": "tool_use",
                "id": "tc-2",
                "name": "web_search",
                "input": {},
            },
        },
        {
            "type": "content_block_delta",
            "index": 2,
            "delta": {"type": "input_json_delta", "partial_json": '{"query":'},
        },
        {
            "type": "content_block_delta",
            "index": 2,
            "delta": {"type": "input_json_delta", "partial_json": ' "cve"}'},
        },
        {"type": "content_block_stop", "index": 2},
        {
            "type": "message_delta",
            "delta": {"stop_reason": "tool_use", "stop_sequence": None},
            "usage": {"output_tokens": 17},
        },
        {"type": "message_stop"},
    ]


def _nousage_openai_payloads() -> list:
    return [
        _oai_chunk({"role": "assistant", "content": ""}),
        _oai_chunk({"content": "你好,"}),
        _oai_chunk({"content": "世界"}),
        _oai_chunk(
            {
                "tool_calls": [
                    {
                        "index": 0,
                        "id": "tc-1",
                        "type": "function",
                        "function": {
                            "name": "run_command",
                            "arguments": '{"command": "nmap -sV 127.0.0.1"}',
                        },
                    }
                ]
            }
        ),
        _oai_chunk({}, "tool_calls"),
        "[DONE]",
    ]


def _nousage_claude_payloads() -> list:
    return [
        _claude_message_start(with_usage=False),
        {
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "text", "text": ""},
        },
        {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": "你好,"},
        },
        {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": "世界"},
        },
        {"type": "content_block_stop", "index": 0},
        {
            "type": "content_block_start",
            "index": 1,
            "content_block": {
                "type": "tool_use",
                "id": "tc-1",
                "name": "run_command",
                "input": {},
            },
        },
        {
            "type": "content_block_delta",
            "index": 1,
            "delta": {
                "type": "input_json_delta",
                "partial_json": '{"command": "nmap -sV 127.0.0.1"}',
            },
        },
        {"type": "content_block_stop", "index": 1},
        {
            "type": "message_delta",
            "delta": {"stop_reason": "tool_use", "stop_sequence": None},
        },
        {"type": "message_stop"},
    ]


def _noargs_openai_payloads() -> list:
    return [
        _oai_chunk({"role": "assistant"}),
        _oai_chunk(
            {
                "tool_calls": [
                    {
                        "index": 0,
                        "id": "tc-1",
                        "type": "function",
                        "function": {"name": "ping_host"},
                    }
                ]
            }
        ),
        _oai_chunk({}, "tool_calls"),
        _oai_usage_chunk(),
        "[DONE]",
    ]


def _noargs_claude_payloads() -> list:
    return [
        _claude_message_start(),
        {
            "type": "content_block_start",
            "index": 0,
            "content_block": {
                "type": "tool_use",
                "id": "tc-1",
                "name": "ping_host",
                "input": {},
            },
        },
        {"type": "content_block_stop", "index": 0},
        {
            "type": "message_delta",
            "delta": {"stop_reason": "tool_use", "stop_sequence": None},
            "usage": {"output_tokens": 17},
        },
        {"type": "message_stop"},
    ]


_STREAM_SCENARIOS = {
    "happy": {"openai": _happy_openai_payloads, "claude": _happy_claude_payloads},
    "m-filter-finish": {
        "openai": _filter_finish_openai_payloads,
        "claude": _filter_finish_claude_payloads,
    },
    "m-badjson": {
        "openai": _badjson_openai_payloads,
        "claude": _badjson_claude_payloads,
    },
    "m-two-tools": {
        "openai": _two_tools_openai_payloads,
        "claude": _two_tools_claude_payloads,
    },
    "m-nousage": {
        "openai": _nousage_openai_payloads,
        "claude": _nousage_claude_payloads,
    },
    "m-noargs": {"openai": _noargs_openai_payloads, "claude": _noargs_claude_payloads},
    "m-garbage": {
        "openai": lambda: ["not-json{{{", "[DONE]"],
        "claude": lambda: ["not-json{{{"],
    },
}


def _sse(payloads: list) -> httpx.Response:
    lines = []
    for payload in payloads:
        data = (
            payload
            if isinstance(payload, str)
            else json.dumps(payload, ensure_ascii=False)
        )
        lines.append(f"data: {data}\n\n")
    return httpx.Response(
        200,
        headers={"content-type": "text/event-stream"},
        content="".join(lines).encode(),
    )


def _http_error_response(
    model: str, *, anthropic: bool, request: httpx.Request
) -> httpx.Response:
    if anthropic:
        key = request.headers.get("x-api-key", "")

        def wrap(err_type: str, message: str) -> dict:
            return {"type": "error", "error": {"type": err_type, "message": message}}
    else:
        key = request.headers.get("authorization", "").removeprefix("Bearer ")

        def wrap(err_type: str, message: str) -> dict:
            return {"error": {"type": err_type, "message": message}}

    if model == "m-500":
        return httpx.Response(500, json=wrap("api_error", "Internal server error"))
    if model == "m-429":
        return httpx.Response(
            429,
            json=wrap("rate_limit_error", "Rate limit exceeded"),
            headers={"retry-after": "7"},
        )
    if model == "m-401":
        # 真实 provider 的 401 文案有时会回显 key,借此验证后端脱敏
        return httpx.Response(
            401,
            json=wrap("authentication_error", f"Incorrect API key provided: {key}."),
        )
    # m-moderation:带特征文案的 4xx
    if anthropic:
        return httpx.Response(
            400,
            json=wrap(
                "invalid_request_error",
                "Request blocked by safety system: 违反内容政策",
            ),
        )
    return httpx.Response(
        400,
        json={
            "error": {
                "message": (
                    "The request was rejected by the content moderation system:"
                    " 检测到敏感内容"
                ),
                "type": "content_filter",
                "code": "content_filter",
            }
        },
    )


def fake_llm_server(request: httpx.Request) -> httpx.Response:
    """唯一 fake server:按路径区分协议,按 model 字段切换场景。"""
    REQUESTS.append(request)
    payload = json.loads(request.content)
    model = payload.get("model", "")
    anthropic = request.url.path.endswith("/messages")
    if model == "m-timeout":
        raise httpx.ConnectTimeout("simulated connect timeout", request=request)
    if model in ("m-500", "m-429", "m-401", "m-moderation"):
        return _http_error_response(model, anthropic=anthropic, request=request)
    scenario = _STREAM_SCENARIOS.get(model, _STREAM_SCENARIOS["happy"])
    return _sse(scenario["claude" if anthropic else "openai"]())


# ---------------------------------------------------------------------------
# 测试基座
# ---------------------------------------------------------------------------


class Harness:
    """构造指向 fake server 的后端实例(base_url 均可注入覆盖)。"""

    @staticmethod
    def make(kind: str, model: str | None = None, **overrides):
        if kind == "openai":
            kwargs = {
                "base_url": "http://fake.test/v1",
                "model": model or "fake-kimi-k3",
                "transport": httpx.MockTransport(fake_llm_server),
            }
            kwargs.update(overrides)
            return openai_compat.OpenAICompatBackend(**kwargs)
        if kind == "claude":
            kwargs = {
                "base_url": "http://fake.test",
                "model": model or "fake-claude",
                "transport": httpx.MockTransport(fake_llm_server),
            }
            kwargs.update(overrides)
            return claude.ClaudeBackend(**kwargs)
        raise ValueError(f"未知后端类型: {kind}")


@pytest.fixture
def harness() -> Harness:
    return Harness()


@pytest.fixture(autouse=True)
def _hermetic_env(monkeypatch: pytest.MonkeyPatch):
    """无论外部环境如何,测试都用合成 key;并清空请求记录。"""
    monkeypatch.setenv(openai_compat.ENV_API_KEY, FAKE_OAI_KEY)
    monkeypatch.setenv(claude.ENV_API_KEY, FAKE_CLAUDE_KEY)
    REQUESTS.clear()


async def collect(backend, messages=None, tools=None) -> list:
    async with backend:
        return [
            event
            async for event in backend.chat(
                MESSAGES if messages is None else messages,
                TOOLS if tools is None else tools,
            )
        ]


def canonical(events: list) -> list[str]:
    return [event_to_canonical_json(event) for event in events]


# ---------------------------------------------------------------------------
# 验收 1:契约测试——双格式应答 → 逐字节相同的归一化事件序列
# ---------------------------------------------------------------------------


async def test_contract_byte_identical_event_streams(harness: Harness):
    openai_events = await collect(harness.make("openai"))
    claude_events = await collect(harness.make("claude"))
    assert canonical(openai_events) == canonical(claude_events)
    assert openai_events == EXPECTED_HAPPY
    assert claude_events == EXPECTED_HAPPY


async def test_tool_call_without_arguments_normalizes_identically(harness: Harness):
    openai_events = await collect(harness.make("openai", model="m-noargs"))
    claude_events = await collect(harness.make("claude", model="m-noargs"))
    assert canonical(openai_events) == canonical(claude_events)
    tool_calls = [e for e in openai_events if isinstance(e, ToolCall)]
    assert tool_calls == [ToolCall(id="tc-1", name="ping_host", arguments={})]


async def test_usage_emitted_once_when_provider_omits_it(harness: Harness):
    openai_events = await collect(harness.make("openai", model="m-nousage"))
    claude_events = await collect(harness.make("claude", model="m-nousage"))
    assert canonical(openai_events) == canonical(claude_events)
    usages = [e for e in openai_events if isinstance(e, Usage)]
    assert usages == [Usage(input_tokens=0, output_tokens=0)]


EXPECTED_TWO_TOOLS = [
    ToolCall(id="tc-1", name="run_command", arguments={"command": "id"}),
    ToolCall(id="tc-2", name="web_search", arguments={"query": "cve"}),
    Usage(input_tokens=42, output_tokens=17),
]


@pytest.mark.parametrize(
    "kind,expected",
    [
        ("openai", EXPECTED_TWO_TOOLS),
        ("claude", [TextDelta(text="查一下"), *EXPECTED_TWO_TOOLS]),
    ],
)
async def test_multiple_parallel_tool_calls_in_order(
    harness: Harness, kind: str, expected: list
):
    events = await collect(harness.make(kind, model="m-two-tools"))
    assert events == expected


# ---------------------------------------------------------------------------
# 验收 2:错误分类——超时 / 5xx / 审核拦截 / 限流 / 鉴权 / 流内拒绝 / 坏 JSON
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["openai", "claude"])
async def test_timeout_maps_to_timeout_error(harness: Harness, kind: str):
    with pytest.raises(RequestTimeoutError) as excinfo:
        await collect(harness.make(kind, model="m-timeout"))
    assert excinfo.value.retryable is True
    assert isinstance(excinfo.value, NetworkError)


@pytest.mark.parametrize("kind", ["openai", "claude"])
async def test_5xx_maps_to_server_error(harness: Harness, kind: str):
    with pytest.raises(ServerError) as excinfo:
        await collect(harness.make(kind, model="m-500"))
    assert excinfo.value.status_code == 500
    assert excinfo.value.retryable is True


@pytest.mark.parametrize("kind", ["openai", "claude"])
async def test_moderation_4xx_maps_to_moderation_error(harness: Harness, kind: str):
    with pytest.raises(ModerationError) as excinfo:
        await collect(harness.make(kind, model="m-moderation"))
    assert excinfo.value.status_code == 400
    assert excinfo.value.retryable is False
    assert "审核拦截" in str(excinfo.value)


@pytest.mark.parametrize("kind", ["openai", "claude"])
async def test_429_maps_to_rate_limit_error(harness: Harness, kind: str):
    with pytest.raises(RateLimitError) as excinfo:
        await collect(harness.make(kind, model="m-429"))
    assert excinfo.value.retry_after == 7.0
    assert excinfo.value.retryable is True


@pytest.mark.parametrize("kind", ["openai", "claude"])
async def test_401_maps_to_auth_error(harness: Harness, kind: str):
    with pytest.raises(AuthError) as excinfo:
        await collect(harness.make(kind, model="m-401"))
    assert excinfo.value.status_code == 401
    assert excinfo.value.retryable is False


@pytest.mark.parametrize("kind", ["openai", "claude"])
async def test_stream_level_refusal_maps_to_moderation_error(
    harness: Harness, kind: str
):
    """OpenAI finish_reason=content_filter / Anthropic stop_reason=refusal。"""
    with pytest.raises(ModerationError):
        await collect(harness.make(kind, model="m-filter-finish"))


@pytest.mark.parametrize("kind", ["openai", "claude"])
async def test_malformed_tool_arguments_raise_structured_error(
    harness: Harness, kind: str
):
    with pytest.raises(MalformedToolCallError) as excinfo:
        await collect(harness.make(kind, model="m-badjson"))
    error = excinfo.value
    assert error.tool_name == "run_command"
    assert error.retryable is False
    assert '{"command": "nmap -sV' in error.raw_arguments
    assert error.provider == {"openai": "openai_compat", "claude": "claude"}[kind]


@pytest.mark.parametrize("kind", ["openai", "claude"])
async def test_unparseable_stream_chunk_maps_to_stream_error(
    harness: Harness, kind: str
):
    with pytest.raises(StreamError) as excinfo:
        await collect(harness.make(kind, model="m-garbage"))
    assert excinfo.value.retryable is True


# ---------------------------------------------------------------------------
# 验收 3:配置——env key 注入、缺 key 报错、报错永不泄漏 key 片段
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kind,env_var",
    [("openai", openai_compat.ENV_API_KEY), ("claude", claude.ENV_API_KEY)],
)
def test_missing_key_raises_config_error(
    monkeypatch: pytest.MonkeyPatch, kind: str, env_var: str
):
    monkeypatch.delenv(env_var, raising=False)
    with pytest.raises(ConfigError) as excinfo:
        Harness.make(kind)
    message = str(excinfo.value)
    assert env_var in message  # 指明该设哪个环境变量
    assert "环境变量" in message


@pytest.mark.parametrize("kind", ["openai", "claude"])
async def test_error_message_never_leaks_key(harness: Harness, kind: str):
    """fake server 的 401 文案故意回显 key;异常消息必须脱敏。"""
    with pytest.raises(AuthError) as excinfo:
        await collect(harness.make(kind, model="m-401"))
    message = str(excinfo.value)
    assert FAKE_OAI_KEY not in message
    assert FAKE_CLAUDE_KEY not in message
    assert "***" in message


def test_redact_secret_helper():
    assert redact_secret("prefix sk-abc suffix", "sk-abc") == "prefix *** suffix"
    assert redact_secret("no secret here", "") == "no secret here"


# ---------------------------------------------------------------------------
# 请求构造(base_url/model 注入 + 消息格式转换)
# ---------------------------------------------------------------------------

CONVERSATION = [
    Message.system("你是授权渗透测试助手。"),
    Message.user("执行 id 命令。"),
    Message.assistant(
        "并行查",
        tool_calls=[
            ToolCall(id="tc-1", name="run_command", arguments={"command": "id"}),
            ToolCall(id="tc-2", name="web_search", arguments={"query": "cve"}),
        ],
    ),
    Message.tool_result("tc-1", "uid=1000 tester"),
    Message.tool_result("tc-2", "no results"),
    Message.user("继续"),
]


async def test_openai_request_shape(harness: Harness):
    await collect(harness.make("openai"), messages=CONVERSATION)
    request = REQUESTS[-1]
    assert request.url.path == "/v1/chat/completions"
    assert request.headers["authorization"] == f"Bearer {FAKE_OAI_KEY}"
    body = json.loads(request.content)
    assert body["model"] == "fake-kimi-k3"
    assert body["stream"] is True
    assert body["stream_options"] == {"include_usage": True}
    messages = body["messages"]
    assert messages[0] == {"role": "system", "content": "你是授权渗透测试助手。"}
    # assistant:携带 tool_calls 时 arguments 必须是 JSON 字符串
    tool_calls = messages[2]["tool_calls"]
    assert tool_calls[0]["function"]["arguments"] == '{"command": "id"}'
    assert tool_calls[1]["function"]["name"] == "web_search"
    # tool 结果各自成条,带 tool_call_id
    assert messages[3] == {
        "role": "tool",
        "tool_call_id": "tc-1",
        "content": "uid=1000 tester",
    }
    assert messages[4]["tool_call_id"] == "tc-2"
    assert body["tools"][0]["function"]["parameters"]["required"] == ["command"]


async def test_claude_request_shape(harness: Harness):
    await collect(harness.make("claude"), messages=CONVERSATION)
    request = REQUESTS[-1]
    assert request.url.path == "/v1/messages"
    assert request.headers["x-api-key"] == FAKE_CLAUDE_KEY
    assert request.headers["anthropic-version"] == "2023-06-01"
    body = json.loads(request.content)
    assert body["model"] == "fake-claude"
    assert body["max_tokens"] == 8192
    # system 抽取为顶层参数,不混入 messages
    assert body["system"] == "你是授权渗透测试助手。"
    messages = body["messages"]
    assert all(m["role"] != "system" for m in messages)
    # assistant:text + tool_use 块,input 为 dict
    assistant_blocks = messages[1]["content"]
    assert assistant_blocks[0] == {"type": "text", "text": "并行查"}
    assert assistant_blocks[1] == {
        "type": "tool_use",
        "id": "tc-1",
        "name": "run_command",
        "input": {"command": "id"},
    }
    # 连续 tool 结果 + 后续 user 文本合并为一条 user 消息(严格交替)
    merged = messages[2]
    assert merged["role"] == "user"
    assert merged["content"] == [
        {"type": "tool_result", "tool_use_id": "tc-1", "content": "uid=1000 tester"},
        {"type": "tool_result", "tool_use_id": "tc-2", "content": "no results"},
        {"type": "text", "text": "继续"},
    ]
    assert body["tools"][0]["input_schema"]["required"] == ["command"]


async def test_openai_extra_body_and_usage_opt_out(harness: Harness):
    backend = harness.make(
        "openai", extra_body={"temperature": 0.6}, include_usage=False
    )
    await collect(backend)
    body = json.loads(REQUESTS[-1].content)
    assert body["temperature"] == 0.6
    assert "stream_options" not in body


async def test_openai_base_url_trailing_slash_tolerated(harness: Harness):
    await collect(harness.make("openai", base_url="http://fake.test/v1/"))
    assert REQUESTS[-1].url.path == "/v1/chat/completions"


async def test_claude_max_tokens_overridable(harness: Harness):
    await collect(harness.make("claude", max_tokens=1024))
    body = json.loads(REQUESTS[-1].content)
    assert body["max_tokens"] == 1024
