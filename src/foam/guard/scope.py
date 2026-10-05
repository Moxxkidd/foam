"""scope 护栏 v0:授权范围解析 + 命令目标提取 + 参数级强制。

三种 scope 规则(见 ``scopes/lab.scope``):

- CIDR:``192.168.56.0/24``(单个 IP 视作 /32、/128)
- 主机名:``localhost`` / ``metasploitable.testlab.local``;``*.`` 前缀为通配域
  (``*.example.com`` 匹配任意深度子域,不匹配裸域 ``example.com``)
- URL 前缀:``http://127.0.0.1:3000/``(规范化 origin + 路径前缀语义)

判定顺序:URL 目标先按规范化 origin(scheme 小写 / host 小写去尾点、IP 字面量
经 ipaddress 归一 / 有效端口=显式端口或 scheme 缺省)匹配 URL 规则,origin
相同再比 path+query+fragment 前缀(规则无路径即授权整个 origin);URL 规则
不匹配再取其 host 按 IP/主机名规则匹配(「或」语义)。畸形 URL(空 host、
非法/越界端口、无法解析的 authority)一律拒绝,不抛异常、不回退 host 检查;
畸形 URL 规则在 ``parse_scope`` 加载期拒绝。
CIDR 目标要求整条网段是 scope 内某条 CIDR 的子网(防止用 /16 超网绕过);
nmap 八位组范围(``192.168.56.1-50``)的请求集合是四个八位组区间的笛卡尔积,
必须被 scope 的 IPv4 CIDR 并集**完整覆盖**(离散并集中的空洞也算越界;逐空隙
精确判定,O(#CIDR) 有界,不逐 IP 枚举)。

明示限制(必须同步进开发日志的绕过面清单):
- **参数级启发式**,不是网络层强制。shell 变量(``$T``)、命令替换
  (``$(...)`` / 反引号)、进制/转义混淆、``xargs`` 二次拼装等可绕过
  静态提取;网络出口级强制(nftables)在 v1 立项补齐。
- 工具从文件读目标(如 nmap ``-iL targets.txt``)、从 stdin 读目标时,
  护栏看不到文件/流内容。
- 不做 DNS 解析:主机名按字符串匹配。scope 只写了 CIDR 而命令用主机名,
  会被拒绝(偏严方向);反之 scope 写主机名、命令用其 IP 也会拒绝。
- 裸单段主机名(``ping metasploitable``)不提取——避免把普通单词误判为
  目标;单段名须经目标 flag(``-h`` 等)传入才校验。属已知漏判面。
- 无网络目标的命令(纯本地操作)不在本护栏管辖内,直接放行。
- 对含 ``$`` / 反引号的命令:不阻断,但在审计 payload 里记 ``warnings``
  留痕。
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple
from urllib.parse import urlsplit

from foam.guard import audit as _audit_mod

if TYPE_CHECKING:
    from foam.guard.audit import AuditLog

# 取目标值的 flag(值可以是 IP/主机名/URL,单段主机名也收)。
TARGET_FLAGS = frozenset(
    {
        "-h", "-t", "-u", "-d",
        "--target", "--url", "--host", "--hostname", "--domain", "--server",
    }
)

# 值为文件路径的 flag:其值不参与目标提取(避免 nmap -oN report.txt 之类
# 被误判为越界主机名)。注意:-iL 一类「从文件读目标」恰是绕过面,见 docstring。
FILE_VALUE_FLAGS = frozenset(
    {
        "-o", "-oN", "-oX", "-oG", "-oA", "-w", "-f", "-i", "-iL",
        "-P", "-L", "-C",  # hydra:密码/用户名/组合文件
        "--input-file", "--output-file", "--stylesheet",
    }
)

# 裸位置参数中,末段是这些扩展名的「含点词」视为文件名而非主机名
# (.zip/.mov 等真实存在的 gTLD 刻意不收,避免绕过面)。
FILE_EXTS = frozenset(
    {
        "txt", "lst", "xml", "json", "pcap", "pcapng", "log", "out",
        "nse", "yaml", "yml", "conf", "cfg", "html", "csv", "md", "gz", "tar",
    }
)

# KEY=VALUE 形式(msf 风格)中取目标值的键,大小写不敏感。
# 刻意不收 LHOST/LPORT/SRVHOST(回连/监听地址,通常是攻击机自身)。
TARGET_KEYS = frozenset(
    {
        "rhost", "rhosts", "target", "targets", "host", "hostname",
        "domain", "url", "uri", "vhost",
    }
)

_URL_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_HOST_PORT_RE = re.compile(
    r"^(?P<host>\[[0-9A-Fa-f:]+\]|[A-Za-z0-9_.-]+):(?P<port>\d{1,5})(?P<path>/\S*)?$"
)
_USER_HOST_RE = re.compile(r"^[^\s@/]+@(?P<host>\S+)$")
_KEY_VALUE_RE = re.compile(r"^(?P<key>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>\S+)$")
# nmap 八位组范围:192.168.56.1-50、192.168.56-57.10(每段可为 num 或 num-num)
_NMAP_RANGE_RE = re.compile(
    r"^(?:\d{1,3}(?:-\d{1,3})?\.){3}\d{1,3}(?:-\d{1,3})?$"
)


@dataclass(frozen=True)
class Scope:
    """解析后的授权范围。rules 保留原始有效行,用于拒绝时向 LLM 复述。"""

    cidrs: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    hosts: frozenset[str] = frozenset()
    wildcards: tuple[str, ...] = ()  # 去掉 "*." 后的后缀
    url_prefixes: tuple[str, ...] = ()
    rules: tuple[str, ...] = ()  # 原始有效行(去注释空行后)

    def summary(self) -> dict:
        """审计/提示用的结构化摘要。"""
        return {
            "cidrs": [str(n) for n in self.cidrs],
            "hosts": sorted(self.hosts),
            "wildcards": list(self.wildcards),
            "url_prefixes": list(self.url_prefixes),
        }


def parse_scope(text: str) -> Scope:
    """解析 scope 文本(``#`` 注释、空行忽略;行内 ``#`` 起也算注释)。

    URL 规则在加载期校验:空 host、非法/越界端口、无法解析的 authority、
    userinfo 一律 ``ValueError``(fail closed)——逐字收下 ``https://`` 这类
    规则会在旧字符串前缀语义下匹配所有 https URL;归一静默丢弃 userinfo
    会把规则放宽到整个 origin。
    """
    cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    hosts: set[str] = set()
    wildcards: list[str] = []
    url_prefixes: list[str] = []
    rules: list[str] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        rules.append(line)
        if _URL_SCHEME_RE.match(line):
            if _parse_url_parts(line, for_rule=True) is None:
                raise ValueError(f"scope 第 {lineno} 行:非法 URL 规则 {line!r}")
            url_prefixes.append(line)
            continue
        if line.startswith("*."):
            suffix = line[2:].lower().rstrip(".")
            if not suffix or not is_hostname(suffix):
                raise ValueError(f"scope 第 {lineno} 行:非法通配域 {line!r}")
            wildcards.append(suffix)
            continue
        try:
            cidrs.append(ipaddress.ip_network(line, strict=False))
            continue
        except ValueError:
            pass
        host = line.lower().rstrip(".")
        if is_hostname(host):
            hosts.add(host)
            continue
        raise ValueError(f"scope 第 {lineno} 行:无法识别的规则 {line!r}")
    return Scope(
        cidrs=tuple(cidrs),
        hosts=frozenset(hosts),
        wildcards=tuple(wildcards),
        url_prefixes=tuple(url_prefixes),
        rules=tuple(rules),
    )


def load_scope(path: str | Path) -> Scope:
    """从文件加载 scope。"""
    return parse_scope(Path(path).read_text(encoding="utf-8"))


def is_hostname(token: str) -> bool:
    """是否合法主机名形态(RFC 1034 label;纯数字点分如 1.2.3 不算——那是
    版本号或坏 IP,避免误判)。"""
    if not token or len(token) > 253:
        return False
    if all(c.isdigit() or c == "." for c in token):
        return False
    for label in token.split("."):
        if not 1 <= len(label) <= 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not re.fullmatch(r"[A-Za-z0-9-]+", label):
            return False
    return True


#: 常见 scheme 的缺省端口(URL origin 归一化用;未知 scheme 无缺省,记 None)。
_SCHEME_DEFAULT_PORTS = {"http": 80, "https": 443}


class _UrlParts(NamedTuple):
    """规范化后的 URL 部件(origin 比较 + 路径前缀比较的依据)。

    - ``scheme`` 小写;
    - ``host`` 小写、去尾点;IP 字面量(v4/v6)经 ``ipaddress`` 归一化
      (``::1`` 与 ``0:0:0:0:0:0:0:1`` 视为同一 host);
    - ``port`` 为有效端口:显式端口,否则 ``_SCHEME_DEFAULT_PORTS`` 里的
      scheme 缺省,否则 None;
    - ``suffix`` 为 path+query+fragment,即 origin 之后的字符串——路径前缀
      语义维持旧字符串前缀在同一 origin 内的行为(规则 suffix 为空串时
      授权整个 origin)。
    """

    scheme: str
    host: str
    port: int | None
    suffix: str


def _parse_url_parts(url: str, *, for_rule: bool = False) -> _UrlParts | None:
    """解析并规范化 URL;畸形返回 None(调用方按 fail closed 处理)。

    畸形 = scheme 缺失、host 为空、端口非数字或越界、authority 无法解析。
    注意 ``SplitResult.port`` 是惰性校验:非法端口在**访问**时才抛
    ``ValueError``;``urlsplit`` 自身也可能因不配对 IPv6 括号等抛出——
    全部归为畸形,绝不上抛。

    ``for_rule=True``(scope 规则)另拒 userinfo:规则里的 ``user@`` 在旧
    字符串前缀语义下只匹配字面开头,origin 归一静默丢弃会把规则放宽到整个
    origin(§1 规范化不得扩大规则);空 userinfo(``https://@h/``)同样拒绝。
    **目标** URL 的 userinfo 不受影响——按真实 host 判定(``a@b`` 的 host
    是 ``b``)。
    """
    try:
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port  # 访问即校验:非法端口在此抛 ValueError
        if for_rule and (parts.username is not None or parts.password is not None):
            return None
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if not scheme or not host:
        return None
    host = host.lower().rstrip(".")
    if not host:
        return None
    try:  # IP 字面量归一化;非 IP(主机名)保持字符串形态
        host = str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if port is None:
        port = _SCHEME_DEFAULT_PORTS.get(scheme)
    suffix = parts.path
    if parts.query:
        suffix += "?" + parts.query
    if parts.fragment:
        suffix += "#" + parts.fragment
    return _UrlParts(scheme=scheme, host=host, port=port, suffix=suffix)


def _url_rules_match(target: _UrlParts, scope: Scope) -> bool:
    """URL 目标是否命中某条 URL 规则:规范化 origin 相同,且目标 suffix
    以规则 suffix 为前缀。"""
    for rule in scope.url_prefixes:
        rule_parts = _parse_url_parts(rule, for_rule=True)
        if rule_parts is None:
            continue  # 畸形规则已在 parse_scope 拒绝;此处防御性跳过
        if (
            (rule_parts.scheme, rule_parts.host, rule_parts.port)
            == (target.scheme, target.host, target.port)
            and target.suffix.startswith(rule_parts.suffix)
        ):
            return True
    return False


def _parse_nmap_range(value: str) -> tuple[tuple[int, int], ...] | None:
    """解析 nmap 八位组范围(``192.168.56.1-50``),返回四个八位组的
    ``(下界, 上界)`` 区间;不是范围语法或区间非法(越出 0-255、下界 >
    上界)返回 None。

    请求地址集合是四个区间的**笛卡尔积**(nmap 实际会触碰的地址),不是
    一条连续数值区间——``192.0.2-3.1`` = {192.0.2.1, 192.0.3.1}。
    """
    if "-" not in value or not _NMAP_RANGE_RE.match(value):
        return None
    octets: list[tuple[int, int]] = []
    for segment in value.split("."):
        lo_s, _, hi_s = segment.partition("-")
        if (len(lo_s) > 1 and lo_s.startswith("0")) or (
            len(hi_s) > 1 and hi_s.startswith("0")
        ):
            return None  # 前导零(056):inet_aton 八进制歧义,拒绝而非猜测
        lo = int(lo_s)
        hi = int(hi_s) if hi_s else lo
        if lo > 255 or hi > 255 or lo > hi:
            return None
        octets.append((lo, hi))
    return tuple(octets)


def _v4_scope_intervals(scope: Scope) -> list[tuple[int, int]]:
    """scope 的 IPv4 CIDR 合并为排序、不相交的整数区间。

    v6 CIDR 不可能覆盖 v4 地址,直接排除(混合 v4/v6 scope 照常工作)。
    """
    ivs = sorted(
        (int(net.network_address), int(net.broadcast_address))
        for net in scope.cidrs
        if isinstance(net, ipaddress.IPv4Network)
    )
    merged: list[list[int]] = []
    for lo, hi in ivs:
        if merged and lo <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])
    return [(lo, hi) for lo, hi in merged]


def _octets_to_int(digits: Iterable[int]) -> int:
    value = 0
    for digit in digits:
        value = (value << 8) | digit
    return value


def _product_min_at_least(
    octets: tuple[tuple[int, int], ...], floor: int
) -> int | None:
    """笛卡尔积 S 中 ≥ ``floor`` 的最小元素;没有则 None。

    32 位数值序 = 八位组字典序。不枚举元素:``floor`` 自身在 S 内即答案;
    否则从右往左找第一个能在保持前缀等于 ``floor`` 的前提下提升的八位组,
    提升位取区间内最小合法值、后缀取各区间下界,O(1)。
    """
    want = [(floor >> shift) & 0xFF for shift in (24, 16, 8, 0)]
    if all(lo <= digit <= hi for (lo, hi), digit in zip(octets, want, strict=True)):
        return floor
    for pos in range(3, -1, -1):
        if not all(lo <= want[i] <= hi for i, (lo, hi) in enumerate(octets[:pos])):
            continue
        bumped = max(octets[pos][0], want[pos] + 1)
        if bumped <= octets[pos][1]:
            digits = want[:pos] + [bumped] + [lo for lo, _ in octets[pos + 1:]]
            return _octets_to_int(digits)
    return None


def _product_hits_gap(
    octets: tuple[tuple[int, int], ...], gap_lo: int, gap_hi: int
) -> bool:
    """S 是否含有空隙 [gap_lo, gap_hi] 内的元素(命中 = 未被授权覆盖)。"""
    smallest = _product_min_at_least(octets, gap_lo)
    return smallest is not None and smallest <= gap_hi


def _nmap_range_in_scope(octets: tuple[tuple[int, int], ...], scope: Scope) -> bool:
    """请求集合(四区间笛卡尔积)被 scope 的 IPv4 CIDR 并集完整覆盖才放行。

    精确(能检出离散并集的空洞)且有界:合并 scope 区间 O(#CIDR),随后对
    [S_min, S_max] 内每个覆盖空隙做一次 O(1) 命中判定,总工作量 O(#CIDR),
    与请求集合大小无关(``0-255.0-255.0-255.0-255`` 立即返回)。
    """
    s_min = _octets_to_int(lo for lo, _ in octets)
    s_max = _octets_to_int(hi for _, hi in octets)
    cursor = s_min  # 已覆盖到 cursor-1;[cursor, s_max] 待覆盖
    for iv_lo, iv_hi in _v4_scope_intervals(scope):
        if iv_hi < cursor:
            continue  # 整段在 S 下界之下
        if iv_lo > s_max:
            break  # 之后的区间都在 S 上界之上
        if iv_lo > cursor and _product_hits_gap(octets, cursor, iv_lo - 1):
            return False  # 区间之间的空洞被 S 命中
        cursor = max(cursor, iv_hi + 1)
        if cursor > s_max:
            return True  # 已覆盖到 S 上界
    return not _product_hits_gap(octets, cursor, s_max)  # 尾部空隙


def _ip_in_scope(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address, scope: Scope
) -> bool:
    return any(addr in net for net in scope.cidrs)


def _cidr_in_scope(
    net: ipaddress.IPv4Network | ipaddress.IPv6Network, scope: Scope
) -> bool:
    for allowed in scope.cidrs:
        try:
            if net.subnet_of(allowed):
                return True
        except TypeError:  # v4/v6 混合
            continue
    return False


def _host_in_scope(host: str, scope: Scope) -> bool:
    host = host.lower().rstrip(".")
    if host in scope.hosts:
        return True
    try:
        return _ip_in_scope(ipaddress.ip_address(host), scope)
    except ValueError:
        pass
    return any(host.endswith("." + suffix) for suffix in scope.wildcards)


def target_in_scope(target: str, scope: Scope) -> bool:
    """单个目标(URL/IP/CIDR/主机名)是否被 scope 覆盖。"""
    if _URL_SCHEME_RE.match(target):
        parts = _parse_url_parts(target)
        if parts is None:
            return False  # 畸形 URL:fail closed,不回退 host 检查
        if _url_rules_match(parts, scope):
            return True
        return _host_in_scope(parts.host, scope)
    try:
        return _cidr_in_scope(ipaddress.ip_network(target, strict=False), scope)
    except ValueError:
        pass
    try:
        return _ip_in_scope(ipaddress.ip_address(target), scope)
    except ValueError:
        pass
    nmap_range = _parse_nmap_range(target)
    if nmap_range is not None:
        # 请求集合是四区间笛卡尔积:必须被 scope v4 CIDR 并集完整覆盖。
        # 旧「端点凸集」假设只对单一连续区间成立,对离散 CIDR 并集是洞。
        return _nmap_range_in_scope(nmap_range, scope)
    return _host_in_scope(target, scope)


def _classify_value(value: str, *, loose_hostname: bool) -> str | None:
    """把单个值归类为目标串;不像目标则返回 None。

    loose_hostname=True(flag 显式声明是目标)时收单段主机名;
    否则只收含点主机名(裸单段词不提取,见模块 docstring)。
    """
    if _URL_SCHEME_RE.match(value):
        return value
    if value.startswith("[") and value.endswith("]"):  # [v6] 字面量
        return _classify_value(value[1:-1], loose_hostname=loose_hostname)
    try:  # CIDR 目标(nmap 192.168.56.0/24、RHOSTS=10.0.0.0/24)
        ipaddress.ip_network(value, strict=False)
        if "/" in value:
            return value
    except ValueError:
        pass
    try:  # IP 字面量
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if _parse_nmap_range(value) is not None:  # nmap 八位组范围
        return value
    match = _USER_HOST_RE.match(value)  # ssh user@host
    if match:
        return _classify_value(match.group("host"), loose_hostname=loose_hostname)
    match = _HOST_PORT_RE.match(value)  # host:port[/path]
    if match:
        host = match.group("host").strip("[]")
        return _classify_value(host, loose_hostname=loose_hostname)
    match = _KEY_VALUE_RE.match(value)  # msf 风格 KEY=VALUE
    if match and match.group("key").lower() in TARGET_KEYS:
        return _classify_value(match.group("value"), loose_hostname=True)
    host = value.lower().rstrip(".")
    if is_hostname(host) and (loose_hostname or "." in host):
        if not loose_hostname and host.rsplit(".", 1)[1] in FILE_EXTS:
            return None  # 裸位置的常见文件名(report.txt / rockyou.txt …)
        return host
    return None


def extract_targets(command: str) -> list[str]:
    """从 shell 命令行启发式提取网络目标(IP/主机名/URL/CIDR),保持出现顺序去重。

    规则:
    - 首个 token 是命令名,跳过;
    - TARGET_FLAGS(``-h/-t/--target/--url/-u`` 等)的值,含 ``--flag=value`` 形式;
    - FILE_VALUE_FLAGS(``-oN`` 等)的值跳过,不参与提取;
    - 任意位置的 IP 字面量、CIDR、带 scheme 的 URL、``user@host``、
      ``host:port[/path]``、TARGET_KEYS 的 ``KEY=VALUE``;
    - 裸位置参数中的含点主机名(``example.com``);裸单段词不提取。

    ``shlex`` 分词失败(引号未闭合等)抛 ``ValueError``——无法静态解析的
    命令不得进入放行判定(fail closed)。
    """
    tokens = shlex.split(command, posix=True)
    targets: list[str] = []
    seen: set[str] = set()

    def _add(value: str, *, loose: bool) -> None:
        target = _classify_value(value, loose_hostname=loose)
        if target is not None and target not in seen:
            seen.add(target)
            targets.append(target)

    skip_next = False
    for i, token in enumerate(tokens):
        if i == 0:
            continue
        if skip_next:
            skip_next = False
            continue
        # token 指命令行词元,非口令(S105 误报)
        if token.startswith("-") and token != "-":  # noqa: S105
            flag, eq, inline = token.partition("=")
            if flag in TARGET_FLAGS:
                if eq:
                    _add(inline, loose=True)
                elif i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
                    _add(tokens[i + 1], loose=True)
                    skip_next = True
            elif flag in FILE_VALUE_FLAGS and not eq:
                skip_next = True
            continue
        _add(token, loose=False)
    return targets


@dataclass(frozen=True)
class GuardDecision:
    """护栏判定结果。reason 面向 LLM:拒绝时给出可行动的纠正说明。"""

    allowed: bool
    command: str
    targets: tuple[str, ...]
    violations: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    reason: str = ""


def _detect_warnings(command: str) -> list[str]:
    warnings: list[str] = []
    if "$" in command or "`" in command:
        warnings.append(
            "命令含 shell 变量/命令替换,参数级护栏无法校验展开后的实际目标"
        )
    return warnings


def _format_scope_for_llm(scope: Scope) -> str:
    lines: list[str] = []
    if scope.cidrs:
        lines.append("  CIDR: " + ", ".join(str(n) for n in scope.cidrs))
    if scope.hosts:
        lines.append("  主机名: " + ", ".join(sorted(scope.hosts)))
    if scope.wildcards:
        lines.append("  通配域: " + ", ".join(f"*.{w}" for w in scope.wildcards))
    if scope.url_prefixes:
        lines.append("  URL 前缀: " + ", ".join(scope.url_prefixes))
    return "\n".join(lines) if lines else "  (scope 为空——任何网络目标都会被拒)"


def _denial_reason(violations: list[str], scope: Scope) -> str:
    return (
        f"命令被 scope 护栏拒绝:目标 {violations} 不在授权范围内。\n"
        f"当前授权范围(scope):\n{_format_scope_for_llm(scope)}\n"
        "可采取的纠正动作:\n"
        "  1. 把命令中的目标改为上述范围内的地址/域名/URL 后重试;\n"
        "  2. 若该目标确已获授权,请操作员将其追加到 scope 文件并重新加载;\n"
        "  3. 若 scope 写的是 CIDR 而你想用主机名,"
        "改用其 IP,或请操作员把该主机名写入 scope。\n"
        "注意:护栏是参数级校验,所有执行请求与拒绝都已记入哈希链审计。"
    )


def check_command(
    command: str, scope: Scope, audit: AuditLog | None = None
) -> GuardDecision:
    """判定命令是否放行:所有识别出的目标都在 scope 内才放行。

    - 无法静态解析(shlex 失败)→ 拒绝(fail closed);
    - 任一识别目标越界 → 拒绝 + 记 ``exec_denied`` + 给 LLM 的纠正说明;
    - 全部在界内(或没有识别到目标)→ 放行 + 记 ``exec_request``;
    - 传入 ``audit`` 时无论放行与否都会落审计记录。
    """
    warnings = _detect_warnings(command)
    try:
        targets = extract_targets(command)
    except ValueError as exc:
        decision = GuardDecision(
            allowed=False,
            command=command,
            targets=(),
            violations=(),
            warnings=tuple(warnings),
            reason=(
                f"命令被 scope 护栏拒绝:无法静态解析({exc})。\n"
                "请改用不带未闭合引号的直白写法;"
                "不要用需要 shell 展开才能确定目标的写法。"
            ),
        )
        if audit is not None:
            audit.append(
                _audit_mod.KIND_EXEC_DENIED,
                {
                    "command": command,
                    "reason": "unparseable",
                    "detail": str(exc),
                    "warnings": warnings,
                },
            )
        return decision

    violations = [t for t in targets if not target_in_scope(t, scope)]
    if violations:
        decision = GuardDecision(
            allowed=False,
            command=command,
            targets=tuple(targets),
            violations=tuple(violations),
            warnings=tuple(warnings),
            reason=_denial_reason(violations, scope),
        )
        if audit is not None:
            audit.append(
                _audit_mod.KIND_EXEC_DENIED,
                {
                    "command": command,
                    "targets": targets,
                    "violations": violations,
                    "warnings": warnings,
                },
            )
        return decision

    reason = (
        f"放行:识别目标 {targets} 均在 scope 内。"
        if targets
        else "放行:未识别到网络目标(参数级护栏不覆盖无目标命令)。"
    )
    decision = GuardDecision(
        allowed=True,
        command=command,
        targets=tuple(targets),
        warnings=tuple(warnings),
        reason=reason,
    )
    if audit is not None:
        audit.append(
            _audit_mod.KIND_EXEC_REQUEST,
            {
                "command": command,
                "targets": targets,
                "decision": "allowed",
                "warnings": warnings,
            },
        )
    return decision


def render_canonical_rules(rules: Iterable[str]) -> str:
    """规则列表 → canonical 文本(WP-14a,Q2/D1 落盘与 round-trip 形态)。

    每行一条、保持顺序、无注释空行、尾部单换行;空列表 → 空串(空规则集
    合法,语义=拒绝一切网络目标)。纯文本函数,不做语法校验——合法性永远
    由 ``parse_scope`` 裁决。输入应为已归一化的规则行(去注释/去空白)。
    """
    lines = [rule.strip() for rule in rules if rule.strip()]
    if not lines:
        return ""
    return "\n".join(lines) + "\n"


def scope_payload(scope: Scope, source: str) -> dict:
    """构造 ``scope_loaded`` 事件的 payload(供加载方写审计)。"""
    return {"source": source, **scope.summary()}
