"""配置持久化(P1-1,2026-09-12 冻结契约):~/.foam/config.json 读写 + .env 只读解析。

解决现状痛点:后端/模型/base-url 无持久化、每次启动重给;.gitignore 列了
.env 却无任何代码读它(用户陷阱);~/.foam/config.json 此前只存 operator
一个键(TUI 呼号,见 tui/app.py 的 load_operator/save_operator)。

红线(测试与文化双重锁定):
- API key 只走环境变量;本模块任何路径都不把 key 写入任何文件。
- .env 只是环境变量的载体:foam 读它(load_dotenv),永不写它。
- profile 白名单仅 backend/model/base_url 三键;其余任何键(尤其任何
  key/token/secret 字样)写时剔除、读时过滤,双保险——绝不落盘,也绝不
  进入装配链。
- profile 名先过 validate_profile_name(2026-09-12 对抗审查修复):字符
  白名单 + 不得等于 key 环境变量当前值——名会原样落盘,把 key 值当名
  等于把密钥写进文件。
- base_url 的「落盘副本」与「上屏副本」先过 sanitize_url(剥 userinfo、
  敏感 query 打码);fail-closed(2026-09-12 第三轮反转):凡解析不出
  「确定无凭证」的结果一律抛 ValueError,绝不原样透传——畸形串可能正是
  藏了凭证的串。运行时传给后端的原值不动(凭证 URL 功能可用)。

残余风险注记(2026-09-12 第三轮如实写明,best-effort 之外的已知残余面):
- fragment(# 后段)不打码——它不上网络,按 URL 语义不会出现在请求里;
- 极端编码形态(双重及以上编码的 query 名、非标分隔符变体等)在单次
  unquote + lower 的比对之外,不保证打码。

配置文件与 TUI 呼号同文件(home/.foam/config.json,0600):写时合并既有
内容,operator 等未知键一律保留;读时全容错——缺失/坏 JSON/非 dict 一律
按 {} 处理(口径与 app.py load_operator 对齐:配置是锦上添花的本地状态,
任何读取问题都不该阻断启动)。
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import MutableMapping
from pathlib import Path
from urllib.parse import unquote, urlsplit, urlunsplit

#: 配置目录名(home 下),与 TUI 呼号配置共用同一目录、同一文件。
CONFIG_DIRNAME = ".foam"
#: 配置文件名;完整路径 = home / CONFIG_DIRNAME / CONFIG_FILENAME。
CONFIG_FILENAME = "config.json"

#: profile 白名单键(红线防线):除此之外任何键——尤其任何 key/token/
#: secret 字样——写时剔除、读时过滤。
_PROFILE_KEYS = ("backend", "model", "base_url")

#: .env 键名合法形(与 shell 变量名一致);不符即畸形行,记警告并跳过。
_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

#: 非引号值的行内注释起点:空白(空格/Tab)后紧跟「#」——`A=v#x` 不算注释,
#: `A=v # x` 才算(与 python-dotenv 同款语义)。
_INLINE_COMMENT_RE = re.compile(r"[ \t]+#")

#: profile 名合法形:1–64 字符,仅 [A-Za-z0-9._-](2026-09-12 对抗审查修复
#: Fix-1)。名会原样落盘(profiles 键名与 active_profile),字符面收窄到
#: 无需转义、不携控制字符/路径分隔符的安全子集。
_PROFILE_NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")

#: profile 名比对用的密钥环境变量(与 backends/openai_compat.py、claude.py
#: 的 ENV_API_KEY 对齐;为避免 config → backends 反向依赖,字面量在此固化)。
#: 名等于其中任何一个的当前值即非法——把 key 值当 profile 名等于把密钥
#: 写进 config.json,红线不允许。
_SECRET_ENV_VARS = ("FOAM_LLM_API_KEY", "FOAM_ANTHROPIC_API_KEY")

#: URL query 中的敏感参数名:sanitize_url 把它们的值打码。比对前对参数名
#: 做 unquote 再 lower——堵「%6bey=」这类编码绕过(2026-09-12 第三轮)。
_SENSITIVE_QUERY_KEYS = frozenset(
    {"key", "api_key", "apikey", "token", "secret", "password"}
)


def _config_path(home: Path) -> Path:
    """配置文件的完整路径(本模块唯一定位点,改布局只动这里)。"""
    return home / CONFIG_DIRNAME / CONFIG_FILENAME


def load_config(home: Path) -> dict:
    """读 home/.foam/config.json;缺失/坏 JSON/非 dict 一律返回 {}。

    容错口径与 app.py load_operator 逐条对齐:配置文件是锦上添花的本地
    状态(预填呼号/记住上次选择),任何读取或解析问题都按「无配置」处理,
    绝不阻断启动。
    """
    try:
        data = json.loads(_config_path(home).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_config(home: Path, data: dict) -> None:
    """合并写入配置并置 0600;目录不存在则创建。

    「合并」语义与 app.py save_operator 一致:先读旧内容(读失败按 {}),
    再用 data 覆盖同名键——operator 等本模块不认识的键原样保留,未来新增
    的非 profile 键也不会被本模块的写路径擦掉。文件含本地偏好,0600 与
    TUI 呼号文件口径一致。
    """
    config_dir = home / CONFIG_DIRNAME
    config_dir.mkdir(parents=True, exist_ok=True)
    path = config_dir / CONFIG_FILENAME
    merged = load_config(home)
    merged.update(data)
    path.write_text(
        json.dumps(merged, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    os.chmod(path, 0o600)


def _parse_dotenv_value(raw_value: str) -> str | None:
    """解析 .env 右值;返回 None 表示畸形(调用方记中文警告并跳过)。

    - 单/双引号值:取引号内字面内容(不做转义展开,保持最小语法面);
      闭合引号后只允许空白或「#」注释,其余一律算畸形。
    - 非引号值:剥首尾空白,并截掉「空白 + #」起的行内注释。
    """
    value = raw_value.strip()
    if value[:1] in ("'", '"'):
        quote = value[0]
        end = value.find(quote, 1)
        if end == -1:
            return None
        rest = value[end + 1 :].strip()
        if rest and not rest.startswith("#"):
            return None
        return value[1:end]
    if match := _INLINE_COMMENT_RE.search(value):
        value = value[: match.start()]
    return value.strip()


def load_dotenv(
    path: Path, environ: MutableMapping[str, str] = os.environ
) -> tuple[list[str], list[str]]:
    """解析 .env 注入环境变量;返回 (injected_keys, warnings)。

    语法面(与主流 dotenv 实现对齐的最小子集):空行、# 注释行、export
    前缀、KEY=VALUE、单/双引号值、非引号内「 #」行内注释。

    两条铁律:
    - 只读不写(红线):.env 只是环境变量的载体,本函数绝不落盘;
    - 不覆盖:environ 中已存在的键一律跳过(显式环境变量优先于 .env,
      这是 dotenv 通行语义),未注入的键不计入 injected_keys。

    文件不存在静默返回 ([], [])——.env 是可选项,缺失不是错误;畸形行
    不注入、按「第 N 行:…」记中文警告(行号 1 起),由调用方上屏。
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return [], []
    injected: list[str] = []
    warnings: list[str] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue  # 空行 / 整行注释
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()  # 兼容 shell source 习惯
        if "=" not in line:
            warnings.append(f"第 {lineno} 行:缺少「=」,不是 KEY=VALUE 形式(已跳过)")
            continue
        key, _, raw_value = line.partition("=")
        key = key.strip()
        if not _KEY_RE.fullmatch(key):
            warnings.append(
                f"第 {lineno} 行:键名「{key}」非法(须为字母或下划线开头,已跳过)"
            )
            continue
        value = _parse_dotenv_value(raw_value)
        if value is None:
            warnings.append(f"第 {lineno} 行:值的引号未闭合或闭合后有多余内容(已跳过)")
            continue
        if key in environ:
            continue  # 不覆盖:显式环境变量优先于 .env
        environ[key] = value
        injected.append(key)
    return injected, warnings


def validate_profile_name(name: str) -> str | None:
    """校验 profile 名;合法返回 None,非法返回中文原因(Fix-1)。

    规则:1–64 字符、仅 [A-Za-z0-9._-];且不得等于 FOAM_LLM_API_KEY /
    FOAM_ANTHROPIC_API_KEY 的当前值(空串不参与比对——未设置的 key 不
    构成黑名单)。名会原样落盘:把 key 值当名等于把密钥写进 config.json,
    红线不允许。返回的原因文案绝不回现 key 值本身(防二次泄漏)。
    """
    if not _PROFILE_NAME_RE.fullmatch(name):
        return "profile 名须为 1–64 字符,仅含字母/数字/「.」「_」「-」"
    for env_var in _SECRET_ENV_VARS:
        secret = os.environ.get(env_var) or ""
        if secret and name == secret:
            return (
                f"profile 名不得等于环境变量 {env_var} 的当前值"
                "(密钥只走环境变量,绝不落盘)"
            )
    return None


def sanitize_url(url: str) -> str:
    """剥离 url 中的凭证痕迹,返回脱敏副本(Fix-2;2026-09-12 第三轮起 fail-closed)。

    只用于「落盘副本」与「上屏副本」:运行时传给后端的 base_url 一律
    原值不动(凭证 URL 功能可用),本函数只在 --save-profile 落盘与
    [config] 可见性行两个出口收敛。

    正常路径:
    - userinfo(user:pass@)整体剥掉,保留 host:port(IPv6 字面量补回方括号);
    - query 中敏感参数名(_SENSITIVE_QUERY_KEYS)的值替换为 ***(键名保留,
      便于核对是哪个参数;非敏感段逐字节不动);比对前对参数名 unquote 再
      lower,堵「%6bey=」编码绕过;
    - 无 scheme(或 scheme 被 userinfo 用户名抢占)的凭证 URL:urlsplit
      拿不到 netloc(P2 实锤:「user:pass@host」的 user 被误判为 scheme),
      首个「/」之前含「@」即加「//」前缀重解析,逼出 authority 段再剥。

    fail-closed 红线(2026-09-12 对抗复核实锤后反转):凡解析不出「确定
    无凭证」的结果,一律抛 ValueError(中文原因,文案绝不回显原 URL——
    防二次泄漏),绝不原样返回。覆盖三处:urlsplit 自身 ValueError
    (IPv6 括号不配对/非法字符)、host/port 段非法(坏端口、裸 IPv6)、
    含 userinfo 却取不到干净 host。已知残余面(fragment、极端编码形态)
    见模块 docstring 的残余风险注记。
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        # 原异常的 message 可能含 netloc 片段(NFKC 报错),绝不向上传播。
        raise ValueError(
            "base_url 结构非法(IPv6 括号不配对或含非法字符),无法安全解析"
        ) from None
    if not parts.netloc:
        # 无 scheme 场景:urlsplit 对「user:pass@host:port/v1」把 user
        # 误判为 scheme,netloc 为空、userinfo 永远剥不到。首个「/」之前
        # 含「@」即按凭证 URL 处理:加「//」重解析;仍无 authority 段则抛。
        head = url.split("/", 1)[0]
        if "@" in head:
            try:
                parts = urlsplit(f"//{url}")
            except ValueError:
                raise ValueError(
                    "base_url 含 userinfo 且结构非法,无法安全解析"
                ) from None
            if not parts.netloc:
                raise ValueError(
                    "base_url 含 userinfo 但取不到干净的 host,无法安全解析"
                )
    netloc = parts.netloc
    if "@" in netloc:
        # userinfo 整体剥掉,只留 host:port;hostname/port 属性访问对
        # 畸形输入(非法端口、裸 IPv6 等)抛 ValueError——fail-closed 上抛。
        try:
            host = parts.hostname
            port = parts.port
        except ValueError:
            raise ValueError(
                "base_url 的 host/port 段非法(坏端口或 IPv6 未加括号),"
                "无法安全剥离凭证"
            ) from None
        if not host:
            raise ValueError(
                "base_url 含 userinfo 但取不到干净的 host,无法安全解析"
            )
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"  # IPv6 字面量补回方括号
        netloc = f"{host}:{port}" if port is not None else host
    query = parts.query
    if query:
        query = "&".join(
            (
                f"{segment.partition('=')[0]}=***"
                if unquote(segment.partition("=")[0]).lower() in _SENSITIVE_QUERY_KEYS
                else segment
            )
            for segment in query.split("&")
        )
    return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))


def _whitelist(profile: dict) -> dict:
    """profile 白名单过滤(红线防线本体):只留非空 str 的 backend/model/base_url。

    写路径(put_profile)与读路径(get_profile)都过它:即使有人手工往
    config.json 塞了 api_key 之类的字段,也绝不进入装配链。
    """
    return {
        key: profile[key]
        for key in _PROFILE_KEYS
        if isinstance(profile.get(key), str) and profile[key].strip()
    }


def get_profile(config: dict, name: str) -> dict | None:
    """取 config["profiles"][name] 的白名单化副本;没有(或过滤后为空)则 None。

    配置文件是用户可手编的文本,读侧同样过白名单(写时剔除 + 读时过滤
    双保险);返回的是副本,调用方改动不会回流 config。
    """
    profiles = config.get("profiles")
    if not isinstance(profiles, dict):
        return None
    raw = profiles.get(name)
    if not isinstance(raw, dict):
        return None
    return _whitelist(raw) or None


def put_profile(home: Path, name: str, profile: dict) -> None:
    """白名单过滤后写入 profiles[name],并把 active_profile 设为 name(0600)。

    「记住上次选择」:保存即激活,下次启动 active_profile 自动生效。
    白名单剔除是红线:profile 里即使混入 api_key 之类的值也绝不落盘
    (有测试对落盘 JSON 全文 grep 锁定)。合并写,operator 等键保留。
    name 先过 validate_profile_name(Fix-1 防御层):非法抛 ValueError
    (中文原因)——调用方即使漏校验,坏名/密钥值也到不了盘上。
    base_url 在本层再过一次 sanitize_url(2026-09-12 第三轮 fail-closed
    防御层):畸形/含凭证却剥不出干净 host 时 ValueError 直接传播(中文),
    且抛在任何写盘动作之前——调用方即使漏脱敏,凭证也到不了盘上。
    """
    reason = validate_profile_name(name)
    if reason is not None:
        raise ValueError(reason)
    cleaned = _whitelist(profile)
    if "base_url" in cleaned:
        # fail-closed:解析不出「确定无凭证」的副本即抛,绝不原样落盘。
        cleaned["base_url"] = sanitize_url(cleaned["base_url"])
    config = load_config(home)
    profiles = config.get("profiles")
    if not isinstance(profiles, dict):
        profiles = {}
        config["profiles"] = profiles
    profiles[name] = cleaned
    config["active_profile"] = name
    save_config(home, config)


def active_profile(config: dict) -> dict | None:
    """取 config["active_profile"] 指向的 profile(白名单化);无则 None。

    active_profile 指向不存在的名字、或类型非法时同样按「无」处理——
    与全模块容错口径一致:本地状态坏了就当没有,绝不阻断启动。
    """
    name = config.get("active_profile")
    if not isinstance(name, str) or not name:
        return None
    return get_profile(config, name)
