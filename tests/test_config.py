"""P1-1 配置持久化测试(2026-09-12 冻结契约):foam.config 全量 + CLI 集成。

- load_config 容错三态(缺失/坏 JSON/非 dict 一律 {});
- save_config:0600 + 合并保留 operator 等未知键;
- load_dotenv:全语法面 / 不覆盖已有键 / 畸形行中文警告(带行号)/ 文件
  不存在静默;
- put_profile 白名单剔除(红线:profile 里塞 api_key 值,落盘 JSON 全文
  grep 不得含该值);
- validate_profile_name(2026-09-12 对抗审查修复 Fix-1):字符白名单、长度、
  不得等于 key 环境变量当前值;put_profile 防御层抛 ValueError;
- sanitize_url(Fix-2;2026-09-12 第三轮起 fail-closed):userinfo 剥离、
  敏感 query 打码(参数名 unquote 后比对,堵 %6bey 编码绕过)、无 scheme
  凭证 URL 重解析剥离、正常 URL 逐字节不变、畸形且可能藏凭证的输入
  抛 ValueError 而非原样透传;put_profile 落盘前再过一层;
- get_profile / active_profile;
- CLI 集成(monkeypatch HOME 到 tmp_path):--save-profile 落盘、下次
  --profile 生效、active_profile 自动应用、flag>env>profile 逐项优先级、
  无 profile 时默认行为不变;
- CLI 红线集成:profile 名=key 值/非法字符被拒(退出码 2、config.json
  不留痕);带凭证 base_url 走 --save-profile——落盘 JSON 全文与 stdout
  不含凭证值,运行时(args 传 factory)保持原值;
- CLI fail-closed 集成(第三轮):--save-profile 遇不可解析 base_url
  退出码 2 且临时 HOME 零落盘;上屏 base_url 占位符;profile 名两条
  回显路径过可打印过滤。

CLI 集成组说明:cli.py 的 --profile/--save-profile 接线
(resolve_backend_args)已同批落地,本组为硬依赖(2026-09-12 移除
hasattr 守卫:接线已在,静默 skip 风险消除)。
"""

from __future__ import annotations

import json
import os
import stat
from collections import deque
from pathlib import Path

import pytest

from foam import cli
from foam.agent.backends.base import LLMBackend, TextDelta, Usage
from foam.config import (
    CONFIG_DIRNAME,
    CONFIG_FILENAME,
    active_profile,
    get_profile,
    load_config,
    load_dotenv,
    put_profile,
    sanitize_url,
    save_config,
    validate_profile_name,
)


def _config_path(home: Path) -> Path:
    return home / CONFIG_DIRNAME / CONFIG_FILENAME


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


# ---------------------------------------------------------------------------
# load_config:容错三态 + 正常读
# ---------------------------------------------------------------------------


def test_load_config_missing_returns_empty(tmp_path):
    assert load_config(tmp_path) == {}


def test_load_config_broken_json_returns_empty(tmp_path):
    _config_path(tmp_path).parent.mkdir(parents=True)
    _config_path(tmp_path).write_text("{not json", encoding="utf-8")
    assert load_config(tmp_path) == {}


def test_load_config_non_dict_returns_empty(tmp_path):
    _config_path(tmp_path).parent.mkdir(parents=True)
    _config_path(tmp_path).write_text('["a", "b"]', encoding="utf-8")
    assert load_config(tmp_path) == {}


def test_load_config_reads_existing(tmp_path):
    _config_path(tmp_path).parent.mkdir(parents=True)
    _config_path(tmp_path).write_text('{"operator": "夜枭"}', encoding="utf-8")
    assert load_config(tmp_path) == {"operator": "夜枭"}


# ---------------------------------------------------------------------------
# save_config:0600 + 合并保留 operator 等未知键 + 目录不存在则建
# ---------------------------------------------------------------------------


def test_save_config_merges_and_preserves_operator_and_0600(tmp_path):
    save_config(tmp_path, {"operator": "夜枭"})  # 模拟 TUI 呼号先落盘
    save_config(tmp_path, {"profiles": {"lab": {"model": "k3"}}})
    data = json.loads(_config_path(tmp_path).read_text(encoding="utf-8"))
    assert data["operator"] == "夜枭"  # 未知键保留
    assert data["profiles"]["lab"]["model"] == "k3"
    assert _mode(_config_path(tmp_path)) == 0o600


def test_save_config_overwrites_same_key_keeps_others(tmp_path):
    save_config(tmp_path, {"operator": "旧", "profiles": {"a": {"model": "k3"}}})
    save_config(tmp_path, {"operator": "新"})
    data = load_config(tmp_path)
    assert data["operator"] == "新"  # 同名键以本次为准
    assert data["profiles"] == {"a": {"model": "k3"}}  # 其余键原样保留


def test_save_config_creates_missing_dir(tmp_path):
    home = tmp_path / "deep" / "home"
    save_config(home, {"a": 1})
    assert _config_path(home).is_file()
    assert _mode(_config_path(home)) == 0o600


def test_save_config_tolerates_broken_existing_file(tmp_path):
    """既有文件是坏 JSON 时按 {} 合并覆盖(与 load_config 容错口径一致)。"""
    _config_path(tmp_path).parent.mkdir(parents=True)
    _config_path(tmp_path).write_text("{{{", encoding="utf-8")
    save_config(tmp_path, {"operator": "夜枭"})
    assert load_config(tmp_path) == {"operator": "夜枭"}


# ---------------------------------------------------------------------------
# load_dotenv:全语法面 / 不覆盖 / 畸形行警告 / 文件不存在
# ---------------------------------------------------------------------------


def test_dotenv_missing_file_silent(tmp_path):
    env: dict[str, str] = {}
    assert load_dotenv(tmp_path / ".env", env) == ([], [])
    assert env == {}


def test_dotenv_full_syntax_surface(tmp_path):
    env: dict[str, str] = {}
    dotenv = tmp_path / ".env"
    dotenv.write_text(
        "\n".join(
            [
                "# 顶部注释",
                "",
                "PLAIN=value",
                "export EXPORTED=ok",
                "SINGLE='单引号 # 不是注释'",
                'DOUBLE="双引号 # 不是注释"',
                "QUOTED_INLINE='引号值' # 引号后注释",
                "INLINE=value  # 行内注释",
                "TRAIL=value\t# Tab 注释",
                "EMPTY=",
                "SPACED = 带空白 ",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    injected, warnings = load_dotenv(dotenv, env)
    assert warnings == []
    assert injected == [
        "PLAIN",
        "EXPORTED",
        "SINGLE",
        "DOUBLE",
        "QUOTED_INLINE",
        "INLINE",
        "TRAIL",
        "EMPTY",
        "SPACED",
    ]
    assert env["PLAIN"] == "value"
    assert env["EXPORTED"] == "ok"
    assert env["SINGLE"] == "单引号 # 不是注释"  # 引号内 # 不算注释
    assert env["DOUBLE"] == "双引号 # 不是注释"
    assert env["QUOTED_INLINE"] == "引号值"
    assert env["INLINE"] == "value"  # 「 #」行内注释被截
    assert env["TRAIL"] == "value"  # Tab 空白同样截
    assert env["EMPTY"] == ""
    assert env["SPACED"] == "带空白"  # 「KEY = VALUE」两端空白宽容


def test_dotenv_hash_without_space_is_not_comment(tmp_path):
    env: dict[str, str] = {}
    dotenv = tmp_path / ".env"
    dotenv.write_text("A=v#x\nB=#y\n", encoding="utf-8")
    injected, warnings = load_dotenv(dotenv, env)
    assert warnings == []
    assert injected == ["A", "B"]
    assert env["A"] == "v#x"  # # 前无空白:不算注释(python-dotenv 同款语义)
    assert env["B"] == "#y"


def test_dotenv_does_not_overwrite_existing(tmp_path):
    env = {"EXISTING": "env-wins"}
    dotenv = tmp_path / ".env"
    dotenv.write_text("EXISTING=dotenv-loses\nNEW=yes\n", encoding="utf-8")
    injected, warnings = load_dotenv(dotenv, env)
    assert warnings == []
    assert env["EXISTING"] == "env-wins"  # 不覆盖:显式环境变量优先
    assert injected == ["NEW"]  # 未注入的键不计入


def test_dotenv_malformed_lines_warn_chinese_lineno(tmp_path):
    env: dict[str, str] = {}
    dotenv = tmp_path / ".env"
    dotenv.write_text(
        "\n".join(
            [
                "OK=1",
                "没有等号的行",
                "1BAD=键名数字开头",
                'UNCLOSED="引号未闭合',
                'TRAILING="闭合后"垃圾',
                "AFTER_OK=2",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    injected, warnings = load_dotenv(dotenv, env)
    assert injected == ["OK", "AFTER_OK"]  # 畸形行不注入,好行不受影响
    assert len(warnings) == 4
    for warning in warnings:
        assert warning.startswith("第 ") and "行" in warning  # 中文带行号
    assert "第 2 行" in warnings[0]
    assert "第 3 行" in warnings[1]
    assert "第 4 行" in warnings[2]
    assert "第 5 行" in warnings[3]


def test_dotenv_default_environ_is_os_environ(tmp_path, monkeypatch):
    """契约签名:environ 默认即 os.environ(进程环境)。"""
    monkeypatch.delenv("FOAM_TEST_DOTENV_INJECT", raising=False)
    dotenv = tmp_path / ".env"
    dotenv.write_text("FOAM_TEST_DOTENV_INJECT=1\n", encoding="utf-8")
    injected, warnings = load_dotenv(dotenv)  # 不传 environ:默认 os.environ
    assert warnings == []
    assert injected == ["FOAM_TEST_DOTENV_INJECT"]
    assert os.environ["FOAM_TEST_DOTENV_INJECT"] == "1"
    # monkeypatch 记录的 delenv 在 teardown 会把该键清掉,不污染后续测试


# ---------------------------------------------------------------------------
# put_profile:白名单剔除(红线)+ active_profile + 0600
# ---------------------------------------------------------------------------


def test_put_profile_whitelist_strips_secrets_redline(tmp_path):
    """红线测试:profile 里塞 api_key/token/secret,落盘 JSON 全文不得含其值。"""
    secret = "sk-TESTONLY-红线值-绝不落盘"
    put_profile(
        tmp_path,
        "lab",
        {
            "backend": "openai_compat",
            "model": "k3",
            "base_url": "http://127.0.0.1:8000/v1",
            "api_key": secret,
            "token": secret,
            "secret": secret,
            "extra_unknown": "剔除",
        },
    )
    raw = _config_path(tmp_path).read_text(encoding="utf-8")
    assert secret not in raw  # 红线:全文 grep 不含密钥值
    assert "api_key" not in raw
    assert "token" not in raw
    assert "secret" not in raw
    assert "extra_unknown" not in raw
    data = json.loads(raw)
    assert data["profiles"]["lab"] == {
        "backend": "openai_compat",
        "model": "k3",
        "base_url": "http://127.0.0.1:8000/v1",
    }
    assert data["active_profile"] == "lab"  # 记住上次选择


def test_put_profile_sets_active_and_keeps_0600(tmp_path):
    put_profile(tmp_path, "a", {"model": "k3"})
    put_profile(tmp_path, "b", {"model": "k4"})
    data = json.loads(_config_path(tmp_path).read_text(encoding="utf-8"))
    assert data["active_profile"] == "b"  # 后保存的激活
    assert set(data["profiles"]) == {"a", "b"}  # 旧 profile 保留
    assert _mode(_config_path(tmp_path)) == 0o600


def test_put_profile_preserves_operator_key(tmp_path):
    save_config(tmp_path, {"operator": "夜枭"})
    put_profile(tmp_path, "lab", {"model": "k3"})
    assert load_config(tmp_path)["operator"] == "夜枭"


def test_put_profile_all_junk_keys_stores_empty_profile(tmp_path):
    put_profile(tmp_path, "junk", {"api_key": "x", "password": "y"})
    config = load_config(tmp_path)
    assert config["profiles"]["junk"] == {}  # 全剔光:留空壳,不留密
    assert config["active_profile"] == "junk"
    assert get_profile(config, "junk") is None  # 读侧:空 profile 视为无


# ---------------------------------------------------------------------------
# validate_profile_name(Fix-1):字符白名单 / 长度 / 不等于 key env 当前值
# ---------------------------------------------------------------------------


def test_validate_profile_name_accepts_legal_names():
    for name in ("lab", "k3", "a" * 64, "Name.With_All-legal.chars0"):
        assert validate_profile_name(name) is None


def test_validate_profile_name_rejects_bad_charset_and_length():
    for name in ("", "a" * 65, "带中文", "has space", "a/b", "a;rm", "名"):
        assert validate_profile_name(name) is not None  # 非法返回中文原因


def test_validate_profile_name_rejects_env_key_value(monkeypatch):
    """红线:profile 名 = 密钥 env 当前值即非法;空串不参与比对。"""
    monkeypatch.setenv("FOAM_LLM_API_KEY", "sk-legal-charset-value")
    assert validate_profile_name("sk-legal-charset-value") is not None
    assert validate_profile_name("sk-legal-charset-value2") is None  # 仅精确命中
    monkeypatch.setenv("FOAM_ANTHROPIC_API_KEY", "sk-ant-value")
    assert validate_profile_name("sk-ant-value") is not None
    monkeypatch.setenv("FOAM_LLM_API_KEY", "")  # 空串不构成黑名单
    assert validate_profile_name("lab") is None


def test_validate_profile_name_reason_never_echoes_secret(monkeypatch):
    """返回的中文原因绝不回现 key 值本身(防二次泄漏)。"""
    secret = "sk-do-not-echo-me"
    monkeypatch.setenv("FOAM_LLM_API_KEY", secret)
    reason = validate_profile_name(secret)
    assert reason is not None
    assert secret not in reason


def test_put_profile_rejects_env_key_value_name_redline(tmp_path, monkeypatch):
    """红线(a)防御层:put_profile 对等于 key env 值的名字抛 ValueError,不落盘。"""
    secret = "sk-TESTONLY-redline-value"
    monkeypatch.setenv("FOAM_ANTHROPIC_API_KEY", secret)
    with pytest.raises(ValueError):
        put_profile(tmp_path, secret, {"model": "k3"})
    assert not _config_path(tmp_path).exists()


def test_put_profile_rejects_illegal_name(tmp_path):
    """红线(b)防御层:put_profile 对非法字符名抛 ValueError,不落盘。"""
    with pytest.raises(ValueError):
        put_profile(tmp_path, "坏/名字", {"model": "k3"})
    assert not _config_path(tmp_path).exists()


# ---------------------------------------------------------------------------
# sanitize_url(Fix-2,第三轮起 fail-closed):userinfo 剥离 / 敏感 query 打码
# (含编码绕过封堵)/ 无 scheme 凭证 URL / 正常 URL 逐字节不变 / 畸形即抛
# ---------------------------------------------------------------------------


def test_sanitize_url_strips_userinfo_keeps_host_port():
    assert (
        sanitize_url("http://user:pass@127.0.0.1:8000/v1")
        == "http://127.0.0.1:8000/v1"
    )
    assert sanitize_url("http://user@example.com:8080/v1") == (
        "http://example.com:8080/v1"
    )
    assert sanitize_url("https://u:p@host/v1") == "https://host/v1"
    assert sanitize_url("http://u:p@[::1]:8080/v1") == "http://[::1]:8080/v1"


def test_sanitize_url_masks_sensitive_query_values():
    assert sanitize_url("http://h/v1?key=abc") == "http://h/v1?key=***"
    assert (
        sanitize_url("http://h/v1?API_KEY=abc&foo=bar")
        == "http://h/v1?API_KEY=***&foo=bar"  # 大小写不敏感;非敏感段不动
    )
    assert sanitize_url(
        "http://h/v1?apikey=a&token=b&secret=c&password=d"
    ) == "http://h/v1?apikey=***&token=***&secret=***&password=***"
    assert (
        sanitize_url("http://u:p@h:8000/v1?key=abc&x=1")
        == "http://h:8000/v1?key=***&x=1"  # userinfo 与敏感 query 同时收敛
    )


def test_sanitize_url_masks_percent_encoded_sensitive_query_names():
    """编码绕过封堵(第三轮):参数名先 unquote 再 lower 比对——%6bey 即 key。"""
    assert sanitize_url("http://h/v1?%6bey=abc") == "http://h/v1?%6bey=***"
    assert (
        sanitize_url("http://h/v1?%41PI_%4bEY=abc&foo=bar")
        == "http://h/v1?%41PI_%4bEY=***&foo=bar"  # API_KEY 编码形态打码,非敏感段不动
    )
    assert (
        sanitize_url("http://u:p@h:8000/v1?%74OKEN=abc")
        == "http://h:8000/v1?%74OKEN=***"  # token 编码形态 + userinfo 同时收敛
    )


def test_sanitize_url_schemeless_userinfo_stripped():
    """P2 实锤修复(第三轮):无 scheme 的凭证 URL——urlsplit 把 user 误判为
    scheme、netloc 为空,旧版永不打码;现加「//」重解析后剥光。"""
    assert (
        sanitize_url("user:pass@127.0.0.1:8000/v1")
        == "//127.0.0.1:8000/v1"
    )
    assert (
        sanitize_url("user:pass@example.com/v1?key=a")
        == "//example.com/v1?key=***"
    )


def test_sanitize_url_normal_url_byte_identical():
    """无 userinfo、无敏感 query 的正常 URL:逐字节不变(不重排、不重编码)。"""
    for url in (
        "http://127.0.0.1:8000/v1",
        "https://api.moonshot.cn/v1",
        "http://Example.COM:8080/v1?foo=bar&page=2",
        "http://h/v1?foo=a%20b",  # 已编码值不重演
    ):
        assert sanitize_url(url) == url


def test_sanitize_url_benign_non_url_passthrough():
    """无凭证嫌疑的朴素输入(首个「/」前无「@」):原样返回,不炸。"""
    assert sanitize_url("") == ""
    assert sanitize_url("not a url") == "not a url"
    assert sanitize_url("/relative/path") == "/relative/path"


def test_sanitize_url_malformed_credential_url_raises_failclosed():
    """fail-closed(2026-09-12 第三轮反转,P1 实锤):畸形且可能藏凭证的输入
    一律抛 ValueError——原样返回等于把凭证串透传到落盘/上屏出口。"""
    for bad in (
        "http://u:p@h:bad/v1",  # 坏端口:userinfo 剥不干净
        "http://u:p@::1:8080/v1",  # 裸 IPv6:host/port 段非法
        "http://[::1",  # IPv6 括号不配对(urlsplit 直接抛)
        "http://u:p@/v1",  # 有 userinfo 无 host
        "user:pass@h:bad/v1",  # 无 scheme:重解析后端口仍非法
        "user:pass@/v1",  # 无 scheme:取不到干净 host
    ):
        with pytest.raises(ValueError):
            sanitize_url(bad)


def test_sanitize_url_error_message_never_echoes_url():
    """异常文案绝不回显原 URL 的任何片段(防二次泄漏)。"""
    secret = "s3cret-TESTONLY-不回落"
    for bad in (
        f"http://operator:{secret}@h:bad/v1",
        f"operator:{secret}@h:bad/v1",
    ):
        with pytest.raises(ValueError) as excinfo:
            sanitize_url(bad)
        assert secret not in str(excinfo.value)
        assert "operator" not in str(excinfo.value)


def test_put_profile_sanitizes_base_url_defense_layer(tmp_path):
    """防御层(第三轮):put_profile 自身对 base_url 过 sanitize_url——
    即使调用方漏脱敏,落盘副本也不含 userinfo,敏感 query 打码。"""
    put_profile(
        tmp_path,
        "lab",
        {"base_url": "http://u:p@127.0.0.1:8000/v1?key=abc"},
    )
    raw = _config_path(tmp_path).read_text(encoding="utf-8")
    assert "u:p" not in raw
    assert "abc" not in raw
    data = json.loads(raw)
    assert (
        data["profiles"]["lab"]["base_url"]
        == "http://127.0.0.1:8000/v1?key=***"
    )


def test_put_profile_unparseable_base_url_raises_failclosed(tmp_path):
    """fail-closed 防御层:畸形带凭证 base_url 抛 ValueError(中文)且零落盘。"""
    with pytest.raises(ValueError):
        put_profile(tmp_path, "bad", {"base_url": "http://u:p@h:bad/v1"})
    assert not _config_path(tmp_path).exists()  # 抛在任何写盘动作之前


# ---------------------------------------------------------------------------
# get_profile / active_profile
# ---------------------------------------------------------------------------


def test_get_profile_returns_whitelisted_copy():
    config = {
        "profiles": {
            "lab": {
                "backend": "claude",
                "model": "claude-sonnet-5",
                "base_url": "",  # 空 str 被剔
                "api_key": "x",  # 非白名单被剔(读侧防线:手编文件也漏不进)
            }
        }
    }
    profile = get_profile(config, "lab")
    assert profile == {"backend": "claude", "model": "claude-sonnet-5"}
    profile["model"] = "篡改"
    assert get_profile(config, "lab")["model"] == "claude-sonnet-5"  # 返回的是副本


def test_get_profile_missing_and_malformed():
    assert get_profile({}, "lab") is None
    assert get_profile({"profiles": "not-a-dict"}, "lab") is None
    assert get_profile({"profiles": {}}, "lab") is None
    assert get_profile({"profiles": {"lab": "not-a-dict"}}, "lab") is None
    assert get_profile({"profiles": {"lab": {"api_key": "x"}}}, "lab") is None
    assert get_profile({"profiles": {"lab": {"model": 123}}}, "lab") is None


def test_active_profile_roundtrip_and_absent(tmp_path):
    assert active_profile({}) is None
    assert active_profile({"active_profile": 123}) is None  # 类型非法按无处理
    assert active_profile({"active_profile": "不存在"}) is None
    put_profile(
        tmp_path, "lab", {"backend": "claude", "model": "claude-sonnet-5"}
    )
    config = load_config(tmp_path)
    assert active_profile(config) == {
        "backend": "claude",
        "model": "claude-sonnet-5",
    }


# ---------------------------------------------------------------------------
# CLI 集成(monkeypatch HOME 到 tmp_path)
#
# cli.py 的 --profile/--save-profile 接线(resolve_backend_args)已同批落地,
# 本组为硬依赖(2026-09-12 移除 hasattr 守卫:静默 skip 风险消除)。
# ---------------------------------------------------------------------------

SCOPE_TEXT = "127.0.0.0/8\nlocalhost\n"
FINISH = [TextDelta("侦察结束,无进一步动作。"), Usage(2, 2)]


class FakeBackend(LLMBackend):
    """脚本化后端(与 test_cli.py 同模式,本文件自带一份保持自包含)。"""

    provider = "fake"

    def __init__(self, script=()):
        self._script = deque(script)
        self.calls: list[list] = []

    async def aclose(self) -> None:
        pass

    def chat(self, messages, tools=None):
        self.calls.append(list(messages))
        return self._stream()

    async def _stream(self):
        events = self._script.popleft() if self._script else [Usage(1, 1)]
        for event in events:
            yield event


class _FactoryProbe:
    """backend_factory 探针:记录 resolve 回填后 args 上的装配三元组。"""

    def __init__(self) -> None:
        self.seen: dict[str, str | None] = {}

    def __call__(self, args) -> LLMBackend:
        self.seen = {
            "backend": args.backend,
            "model": args.model,
            "base_url": args.base_url,
        }
        return FakeBackend([FINISH])


@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    """CLI 集成公共隔离:HOME 指向 tmp_path、cwd 切 tmp_path、清非密钥 env。

    防开发机 FOAM_LLM_MODEL/FOAM_LLM_BASE_URL 泄漏进断言(与 test_cli.py
    的 monkeypatch.delenv 同款防御);.env 只在 tmp_path 内临时构造。
    密钥类 env 除红线测试以 TESTONLY 哨兵值经 monkeypatch 写入(名=key 值
    碰撞用例,teardown 自动还原)外,本文件从不触碰(红线:key 只走环境
    变量,测试也绝不写真 key)。
    """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("FOAM_LLM_MODEL", raising=False)
    monkeypatch.delenv("FOAM_LLM_BASE_URL", raising=False)
    return tmp_path


def _run_argv(home: Path, *extra: str) -> list[str]:
    """构造 run 参数:scope/workdir 全部落在 home(=tmp_path)内,不碰仓库。"""
    scope_file = home / "lab.scope"
    scope_file.write_text(SCOPE_TEXT, encoding="utf-8")
    return [
        "run",
        "--scope",
        str(scope_file),
        "--objective",
        "侦察本机",
        "--workdir",
        str(home / "eng"),
        *extra,
    ]


def test_cli_save_profile_persists_and_activates(isolated_home):
    """--save-profile:装配成功后落盘为 profile 并设为 active(0600)。"""
    probe = _FactoryProbe()
    rc = cli.main(
        _run_argv(
            isolated_home,
            "--base-url",
            "http://127.0.0.1:8000/v1",
            "--model",
            "k3",
            "--save-profile",
            "lab",
        ),
        backend_factory=probe,
    )
    assert rc == 0
    path = _config_path(isolated_home)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["profiles"]["lab"] == {
        "backend": "openai_compat",
        "model": "k3",
        "base_url": "http://127.0.0.1:8000/v1",
    }
    assert data["active_profile"] == "lab"  # 记住上次选择
    assert _mode(path) == 0o600


def test_cli_active_profile_auto_applies(isolated_home, capsys):
    """active_profile 自动应用:无 flag 无 env 时,上次保存的 profile 生效。"""
    put_profile(
        isolated_home,
        "lab",
        {
            "backend": "openai_compat",
            "model": "k-profiled",
            "base_url": "http://127.0.0.1:9000/v1",
        },
    )
    probe = _FactoryProbe()
    rc = cli.main(_run_argv(isolated_home), backend_factory=probe)
    assert rc == 0
    assert probe.seen == {
        "backend": "openai_compat",
        "model": "k-profiled",
        "base_url": "http://127.0.0.1:9000/v1",
    }
    out = capsys.readouterr().out
    assert "[config] profile 'lab'" in out  # 启动可见性
    assert "model=k-profiled" in out


def test_cli_explicit_profile_flag_selects_named(isolated_home, capsys):
    """--profile NAME:显式选择指定 profile(覆盖 active_profile)。"""
    put_profile(isolated_home, "a", {"model": "k-a", "base_url": "http://a.invalid/v1"})
    put_profile(isolated_home, "b", {"model": "k-b", "base_url": "http://b.invalid/v1"})
    # active 是 b(后存);--profile a 显式选择 a
    probe = _FactoryProbe()
    rc = cli.main(_run_argv(isolated_home, "--profile", "a"), backend_factory=probe)
    assert rc == 0
    assert probe.seen["model"] == "k-a"
    assert probe.seen["base_url"] == "http://a.invalid/v1"
    assert "[config] profile 'a'" in capsys.readouterr().out


def test_cli_priority_env_beats_profile(isolated_home, monkeypatch):
    """优先级逐项:env > profile;backend 无 env 通道(维持现状)取 profile。"""
    put_profile(
        isolated_home,
        "lab",
        {
            "backend": "claude",
            "model": "k-profile",
            "base_url": "http://profile.invalid/v1",
        },
    )
    monkeypatch.setenv("FOAM_LLM_MODEL", "k-env")
    monkeypatch.setenv("FOAM_LLM_BASE_URL", "http://env.invalid/v1")
    probe = _FactoryProbe()
    rc = cli.main(_run_argv(isolated_home), backend_factory=probe)
    assert rc == 0
    assert probe.seen == {
        "backend": "claude",  # backend 无 env 通道:无 flag 时仍取 profile
        "model": "k-env",  # env 胜 profile
        "base_url": "http://env.invalid/v1",
    }


def test_cli_priority_flag_beats_env_and_profile(isolated_home, monkeypatch):
    """优先级逐项:flag > env > profile(全压时 flag 全胜)。"""
    put_profile(
        isolated_home,
        "lab",
        {
            "backend": "claude",
            "model": "k-profile",
            "base_url": "http://profile.invalid/v1",
        },
    )
    monkeypatch.setenv("FOAM_LLM_MODEL", "k-env")
    monkeypatch.setenv("FOAM_LLM_BASE_URL", "http://env.invalid/v1")
    probe = _FactoryProbe()
    rc = cli.main(
        _run_argv(
            isolated_home,
            "--backend",
            "openai_compat",
            "--model",
            "k-flag",
            "--base-url",
            "http://flag.invalid/v1",
        ),
        backend_factory=probe,
    )
    assert rc == 0
    assert probe.seen == {
        "backend": "openai_compat",
        "model": "k-flag",
        "base_url": "http://flag.invalid/v1",
    }


def test_cli_priority_partial_flag_falls_through(isolated_home, monkeypatch):
    """优先级逐项:每键独立解析——model 取 flag、base_url 取 env、backend 取 profile。"""
    put_profile(
        isolated_home,
        "lab",
        {
            "backend": "claude",
            "model": "k-profile",
            "base_url": "http://profile.invalid/v1",
        },
    )
    monkeypatch.setenv("FOAM_LLM_BASE_URL", "http://env.invalid/v1")  # model 不设 env
    probe = _FactoryProbe()
    rc = cli.main(_run_argv(isolated_home, "--model", "k-flag"), backend_factory=probe)
    assert rc == 0
    assert probe.seen == {
        "backend": "claude",  # 无 flag 无 env 通道:取 profile
        "model": "k-flag",  # flag 胜 profile
        "base_url": "http://env.invalid/v1",  # env 胜 profile
    }


def test_cli_profile_invalid_backend_ignored_with_warning(isolated_home, capsys):
    """profile 中 backend 非法值:忽略并警告,其余键(model/base_url)仍生效。"""
    save_config(
        isolated_home,
        {
            "profiles": {
                "bad": {
                    "backend": "不存在的后端",
                    "model": "k3",
                    "base_url": "http://x.invalid/v1",
                }
            },
            "active_profile": "bad",
        },
    )
    probe = _FactoryProbe()
    rc = cli.main(_run_argv(isolated_home), backend_factory=probe)
    assert rc == 0
    assert probe.seen["backend"] == "openai_compat"  # 非法值退回内置默认
    assert probe.seen["model"] == "k3"  # 合法键不受影响
    assert "backend" in capsys.readouterr().err  # 有警告


def test_cli_dotenv_injected_keys_printed_values_never(isolated_home, capsys):
    """main() 入口加载 ./.env:键名上屏(值绝不上屏),畸形行警告走 stderr。"""
    (isolated_home / ".env").write_text(
        "FOAM_LLM_BASE_URL=http://127.0.0.1:7000/v1\n"
        "FOAM_LLM_MODEL=k-dotenv\n"
        "没有等号的畸形行\n",
        encoding="utf-8",
    )
    probe = _FactoryProbe()
    rc = cli.main(_run_argv(isolated_home), backend_factory=probe)
    assert rc == 0
    assert probe.seen["base_url"] == "http://127.0.0.1:7000/v1"  # .env 注入后进入解析链
    assert probe.seen["model"] == "k-dotenv"
    captured = capsys.readouterr()
    assert "[config] .env 注入 2 个变量" in captured.out
    assert "FOAM_LLM_BASE_URL" in captured.out  # 只打印键名
    assert "http://127.0.0.1:7000" not in captured.out  # 值绝不上屏
    assert "第 3 行" in captured.err  # 畸形行警告(带行号)走 stderr


def test_cli_save_profile_not_persisted_on_bad_config(isolated_home):
    """坏配置不落盘:装配失败(ConfigError)时 --save-profile 不产生任何文件。"""
    rc = cli.main(_run_argv(isolated_home, "--save-profile", "lab"))  # 缺 base_url
    assert rc == 2
    assert not _config_path(isolated_home).exists()


def test_cli_defaults_unchanged_without_profile(isolated_home, capsys):
    """回归底线:无 profile、无 .env、无 flag 时行为与现状逐字节一致。"""
    probe = _FactoryProbe()
    rc = cli.main(_run_argv(isolated_home), backend_factory=probe)
    assert rc == 0
    assert probe.seen == {
        "backend": "openai_compat",  # 内置默认后端(现状同款)
        "model": "k3",  # 内置默认模型(现状在 _build_backend 里兜底,解析链接管)
        "base_url": None,  # openai_compat 无内置默认
    }
    out = capsys.readouterr().out
    assert "backend=openai_compat" in out
    assert "[config]" not in out  # 无 profile 无 .env:零额外输出

    # 真装配(无 factory):openai_compat 缺 base url 的报错与现状一致
    rc = cli.main(_run_argv(isolated_home))
    assert rc == 2
    assert "FOAM_LLM_BASE_URL" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# CLI 红线集成(2026-09-12 对抗审查修复 Fix-1/Fix-2)
# ---------------------------------------------------------------------------


def test_cli_save_profile_name_equal_to_env_key_value_rejected(
    isolated_home, monkeypatch, capsys
):
    """红线(a):profile 名 = 密钥 env 当前值 → 退出码 2,config.json 不留痕。

    哨兵值只用合法字符集字符(精确命中 env 值规则,而非字符集规则);
    报错文案绝不回现该值(回显即二次泄漏)。
    """
    secret = "sk-TESTONLY-redline-sentinel"
    monkeypatch.setenv("FOAM_LLM_API_KEY", secret)
    probe = _FactoryProbe()
    rc = cli.main(
        _run_argv(
            isolated_home,
            "--base-url",
            "http://127.0.0.1:8000/v1",
            "--save-profile",
            secret,
        ),
        backend_factory=probe,
    )
    assert rc == 2
    assert not _config_path(isolated_home).exists()  # 坏名不落盘
    err = capsys.readouterr().err
    assert "profile 名" in err
    assert "FOAM_LLM_API_KEY" in err  # 指向变量名,可行动
    assert secret not in err  # 值绝不回显


def test_cli_save_profile_illegal_name_rejected(isolated_home, capsys):
    """红线(b):profile 名含非法字符 → 退出码 2,config.json 不留痕。"""
    probe = _FactoryProbe()
    rc = cli.main(
        _run_argv(
            isolated_home,
            "--base-url",
            "http://127.0.0.1:8000/v1",
            "--save-profile",
            "坏/名字",
        ),
        backend_factory=probe,
    )
    assert rc == 2
    assert "profile 名" in capsys.readouterr().err
    assert not _config_path(isolated_home).exists()


def test_cli_save_profile_sanitizes_base_url_redline(isolated_home, capsys):
    """红线(c):带凭证 base_url 走 --save-profile——落盘 JSON 全文与 stdout
    不含凭证值,但 factory 收到的 args.base_url 是原值(运行时不动)。"""
    password = "s3cret-TESTONLY-凭证"
    query_secret = "qk-TESTONLY-凭证"
    raw_url = f"http://operator:{password}@127.0.0.1:8000/v1?key={query_secret}"
    probe = _FactoryProbe()
    rc = cli.main(
        _run_argv(
            isolated_home,
            "--base-url",
            raw_url,
            "--model",
            "k3",
            "--save-profile",
            "lab",
        ),
        backend_factory=probe,
    )
    assert rc == 0
    # 运行时不动:装配链收到的是带凭证的原值(凭证 URL 功能可用)
    assert probe.seen["base_url"] == raw_url
    # 落盘副本:全文 grep 不含任何凭证段
    raw = _config_path(isolated_home).read_text(encoding="utf-8")
    assert password not in raw
    assert query_secret not in raw
    assert "operator" not in raw
    data = json.loads(raw)
    assert data["profiles"]["lab"]["base_url"] == (
        "http://127.0.0.1:8000/v1?key=***"  # userinfo 剥光、敏感 query 打码
    )
    # 上屏副本:stdout 同样不含凭证
    out = capsys.readouterr().out
    assert password not in out
    assert query_secret not in out


def test_cli_profile_display_sanitizes_handedited_base_url(isolated_home, capsys):
    """上屏副本脱敏(手编防线):config.json 被手工塞入带凭证 base_url 时,
    可见性行不原样上屏;解析进 args 的仍是原值(运行时不动)。

    (put_profile 自第三轮起自身消毒,手编场景用 save_config 直接写入模拟。)"""
    password = "s3cret-TESTONLY-手编"
    query_secret = "tok-TESTONLY-手编"
    raw_url = f"http://user:{password}@127.0.0.1:9000/v1?token={query_secret}"
    save_config(
        isolated_home,
        {
            "profiles": {"lab": {"model": "k3", "base_url": raw_url}},
            "active_profile": "lab",
        },
    )
    probe = _FactoryProbe()
    rc = cli.main(_run_argv(isolated_home), backend_factory=probe)
    assert rc == 0
    assert probe.seen["base_url"] == raw_url  # 运行时原值进入装配链
    out = capsys.readouterr().out
    assert "[config] profile 'lab'" in out
    assert password not in out
    assert query_secret not in out
    assert "base_url=http://127.0.0.1:9000/v1?token=***" in out


# ---------------------------------------------------------------------------
# CLI fail-closed 集成(2026-09-12 第三轮)
# ---------------------------------------------------------------------------


def test_cli_save_profile_unparseable_base_url_rejected_exit2(isolated_home, capsys):
    """fail-closed:--save-profile 遇不可解析 base_url → 退出码 2 + 临时 HOME
    零落盘;stderr 中文说明,原 URL(及其凭证)绝不回显;运行时 args 仍是原值。"""
    password = "s3cret-TESTONLY-拒存"
    raw_url = f"http://operator:{password}@h:bad/v1"  # 坏端口 → sanitize 抛
    probe = _FactoryProbe()
    rc = cli.main(
        _run_argv(
            isolated_home,
            "--base-url",
            raw_url,
            "--model",
            "k3",
            "--save-profile",
            "lab",
        ),
        backend_factory=probe,
    )
    assert rc == 2
    assert not (isolated_home / CONFIG_DIRNAME).exists()  # 零落盘(目录都没建)
    err = capsys.readouterr().err
    assert "base_url 无法解析" in err
    assert "已拒绝保存" in err
    assert raw_url not in err  # 原 URL 不回显
    assert password not in err  # 凭证绝不回显
    assert probe.seen["base_url"] == raw_url  # 运行时原值语义不动(装配在落盘前)


def test_cli_profile_display_placeholder_when_base_url_unparseable(
    isolated_home, capsys
):
    """上屏 fail-closed:手编进 config.json 的畸形带凭证 base_url,可见性行
    显示占位符 <无法解析,已脱敏>,绝不原样上屏;运行时 args 仍是原值。"""
    password = "s3cret-TESTONLY-占位"
    raw_url = f"http://user:{password}@h:bad/v1"  # 坏端口 → sanitize 抛
    save_config(  # put_profile 已 fail-closed,手编场景用 save_config 模拟
        isolated_home,
        {
            "profiles": {"lab": {"model": "k3", "base_url": raw_url}},
            "active_profile": "lab",
        },
    )
    probe = _FactoryProbe()
    rc = cli.main(_run_argv(isolated_home), backend_factory=probe)
    assert rc == 0
    assert probe.seen["base_url"] == raw_url  # 运行时原值进入装配链
    out = capsys.readouterr().out
    assert "base_url=<无法解析,已脱敏>" in out
    assert password not in out
    assert raw_url not in out


def test_cli_profile_display_active_name_printable_filtered(isolated_home, capsys):
    """active_profile 名(手编可含 ANSI/换行)上屏前过可打印过滤——
    防转义序列染色与换行伪造日志行。"""
    evil = "lab\x1b[31m\n[config] 伪造行"
    save_config(
        isolated_home,
        {
            "profiles": {
                evil: {"model": "k3", "base_url": "http://127.0.0.1:9000/v1"}
            },
            "active_profile": evil,
        },
    )
    probe = _FactoryProbe()
    rc = cli.main(_run_argv(isolated_home), backend_factory=probe)
    assert rc == 0
    assert probe.seen["model"] == "k3"  # profile 正常生效
    out = capsys.readouterr().out
    assert "\x1b" not in out  # 无裸转义字符
    assert "\\x1b" in out  # 以转义形态可见
    assert "[config] 伪造行" in out  # 名字内容仍可见(行内)
    assert "\n[config] 伪造行" not in out  # 但没有被伪造出独立日志行


def test_cli_profile_flag_missing_name_printable_filtered(isolated_home, capsys):
    """--profile 指定名(命令行直接可带控制字符)的回显同样过可打印过滤。"""
    evil = "nope\x1b[31m\n伪造"
    probe = _FactoryProbe()
    rc = cli.main(
        _run_argv(isolated_home, "--profile", evil), backend_factory=probe
    )
    assert rc == 0  # 警告后按解析链继续(默认装配)
    err = capsys.readouterr().err
    assert "不存在或为空" in err
    assert "\x1b" not in err  # 无裸转义字符
    assert "\\x1b" in err  # 以转义形态可见
    assert "\n伪造" not in err  # 换行未伪造出独立行
