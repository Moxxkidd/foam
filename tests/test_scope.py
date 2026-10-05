"""scope 护栏表驱动单测(WP-02 验收 1/2/3;R01 回归见末节)。"""

import ipaddress
import itertools

import pytest

from foam.guard import audit
from foam.guard.scope import (
    check_command,
    extract_targets,
    load_scope,
    parse_scope,
    target_in_scope,
)

LAB_SCOPE_TEXT = """\
# 注释行
127.0.0.0/8
localhost
http://127.0.0.1:3000/

192.168.56.0/24   # 行内注释
*.testlab.local
"""

LAB_SCOPE = parse_scope(LAB_SCOPE_TEXT)


# ---------------------------------------------------------------- 解析

PARSE_CASES = [
    # (scope 文本, 期望 CIDR 数, 主机数, 通配数, URL 前缀数)
    ("192.168.56.0/24", 1, 0, 0, 0),
    ("10.0.0.1", 1, 0, 0, 0),  # 单 IP 归一化为 /32
    ("::1/128", 1, 0, 0, 0),
    ("localhost", 0, 1, 0, 0),
    ("Metasploitable.TestLab.LOCAL", 0, 1, 0, 0),  # 大小写归一
    ("*.example.com", 0, 0, 1, 0),
    ("http://127.0.0.1:3000/", 0, 0, 0, 1),
    ("# 只有注释\n\n   \n", 0, 0, 0, 0),
    (LAB_SCOPE_TEXT, 2, 1, 1, 1),
]


@pytest.mark.parametrize(
    ("text", "n_cidr", "n_host", "n_wild", "n_url"), PARSE_CASES
)
def test_parse_scope(text, n_cidr, n_host, n_wild, n_url):
    scope = parse_scope(text)
    assert len(scope.cidrs) == n_cidr
    assert len(scope.hosts) == n_host
    assert len(scope.wildcards) == n_wild
    assert len(scope.url_prefixes) == n_url


def test_parse_scope_normalizes_single_ip_to_cidr():
    scope = parse_scope("10.0.0.1")
    assert str(scope.cidrs[0]) == "10.0.0.1/32"


def test_parse_scope_lowercases_hostname():
    scope = parse_scope("Metasploitable.TestLab.LOCAL")
    assert "metasploitable.testlab.local" in scope.hosts


def test_parse_scope_rejects_garbage_line():
    with pytest.raises(ValueError, match="无法识别"):
        parse_scope("这不是一个合法规则!!!")


def test_parse_scope_rejects_bad_wildcard():
    with pytest.raises(ValueError, match="通配域"):
        parse_scope("*.-bad-.com")


def test_load_scope_from_file(tmp_path):
    path = tmp_path / "t.scope"
    path.write_text(LAB_SCOPE_TEXT, encoding="utf-8")
    scope = load_scope(path)
    assert len(scope.rules) == 5


def test_repo_lab_scope_parses():
    """仓库自带 scopes/lab.scope 必须能解析(冒烟)。"""
    from pathlib import Path

    repo_root = Path(__file__).resolve().parent.parent
    scope = load_scope(repo_root / "scopes" / "lab.scope")
    assert scope.cidrs and "localhost" in scope.hosts


# ---------------------------------------------------------------- 匹配

MATCH_CASES = [
    # (目标, 是否在 LAB_SCOPE 内)
    ("192.168.56.10", True),  # CIDR 包含
    ("192.168.56.255", True),  # 边界地址
    ("192.168.57.10", False),  # CIDR 不包含
    ("8.8.8.8", False),
    ("127.0.0.1", True),
    ("10.0.0.1", False),
    ("192.168.56.0/25", True),  # scope 子网
    ("192.168.56.0/24", True),  # 等于 scope 网段
    ("192.168.0.0/16", False),  # 超网:不得用更大网段绕过
    ("192.168.56.1-50", True),  # nmap 八位组范围,整段在界内
    ("192.168.56-57.10", False),  # 范围上界越界(凸集端点法)
    ("localhost", True),
    ("LOCALHOST", True),  # 大小写
    ("localhost.", True),  # 尾点归一
    ("foo.localhost", False),  # 精确主机名不含子域
    ("web.testlab.local", True),  # 通配域
    ("a.b.testlab.local", True),  # 通配域任意深度
    ("testlab.local", False),  # 通配域不匹配裸域
    ("eviltwin.testlab.local.evil.com", False),
    ("http://127.0.0.1:3000/", True),  # URL 前缀精确
    ("http://127.0.0.1:3000/admin?x=1", True),  # URL 前缀前缀
    # 端口不同但 127/8 已覆盖:URL 规则与 CIDR 是「或」
    ("http://127.0.0.1:4000/", True),
    ("https://127.0.0.1:3000/", True),  # scheme 不同,但 host 落 127/8
    ("http://192.168.56.10:8080/login", True),  # URL 的 host 回退到 CIDR
    ("http://web.testlab.local/", True),  # URL 的 host 回退到通配域
    ("http://evil.example.com/", False),
    ("::1", False),  # scope 里没有 v6 段
]


@pytest.mark.parametrize(("target", "expected"), MATCH_CASES)
def test_target_in_scope(target, expected):
    assert target_in_scope(target, LAB_SCOPE) is expected


def test_url_prefix_does_not_leak_to_sibling_host():
    scope = parse_scope("http://127.0.0.1:3000/")
    assert not target_in_scope("http://127.0.0.1:3000.evil.com/", scope)


def test_url_prefix_scope_is_port_specific():
    """scope 只写 URL 前缀(不含 CIDR)时,端口必须匹配——细粒度授权。"""
    scope = parse_scope("http://127.0.0.1:3000/")
    assert target_in_scope("http://127.0.0.1:3000/app", scope)
    assert not target_in_scope("http://127.0.0.1:4000/", scope)


# ---------------------------------------------------------------- 提取

EXTRACT_CASES = [
    # (命令, 期望提取出的目标列表)
    ("nmap -sV 192.168.56.10", ["192.168.56.10"]),
    ("nmap -sV -p 80,443 192.168.56.10", ["192.168.56.10"]),
    ("nmap -oN report.txt 192.168.56.10", ["192.168.56.10"]),  # 输出文件不算目标
    ("nmap -oA scan 10.0.0.1 10.0.0.2", ["10.0.0.1", "10.0.0.2"]),
    ("nmap 192.168.56.0/24", ["192.168.56.0/24"]),
    ("nmap 192.168.56.1-50", ["192.168.56.1-50"]),  # nmap 八位组范围
    ("ping -c 4 8.8.8.8", ["8.8.8.8"]),
    ("curl http://127.0.0.1:3000/login", ["http://127.0.0.1:3000/login"]),
    ("curl -s http://a.example.com/ http://b.example.com/",
     ["http://a.example.com/", "http://b.example.com/"]),
    ("nikto -h http://target.example.com/", ["http://target.example.com/"]),
    ("nikto -h target.example.com", ["target.example.com"]),
    ("nikto -h metasploitable", ["metasploitable"]),  # flag 值收单段主机名
    ("sqlmap -u http://127.0.0.1:3000/?id=1", ["http://127.0.0.1:3000/?id=1"]),
    ("sqlmap -u=http://127.0.0.1:3000/?id=1", ["http://127.0.0.1:3000/?id=1"]),
    ("nmap --target=10.0.0.5", ["10.0.0.5"]),
    ("nmap --target 10.0.0.5", ["10.0.0.5"]),
    ("ssh user@192.168.56.10", ["192.168.56.10"]),
    ("ssh admin@web.testlab.local", ["web.testlab.local"]),
    ("nc 192.168.56.10 4444", ["192.168.56.10"]),
    ("ncat example.com:80", ["example.com"]),
    ("curl example.com:8080/admin", ["example.com"]),
    ("ssh user@[2001:db8::1]", ["2001:db8::1"]),
    ("gobuster dir -u http://10.0.0.9/ -w /usr/share/wordlists/dir.txt",
     ["http://10.0.0.9/"]),  # -w 词表文件不算目标
    ("msfvenom -p x LHOST=192.168.56.1 LPORT=4444 -f elf", []),  # LHOST 不收
    ("echo hello", []),  # 单段裸词不提取
    ("cat /etc/passwd", []),  # 路径不提取
    ("grep -rn 3.14 .", []),  # 数字点分(版本号)不提取
    ("ls -la /tmp", []),
    ("ping metasploitable", []),  # 已知漏判:裸单段主机名(记入开发日志)
    ("ping $TARGET", []),  # 已知绕过:shell 变量(记入开发日志)
    ("nmap -- 192.168.56.10", ["192.168.56.10"]),  # -- 分隔后仍抓 IP
    ("hydra -l admin -P pass.txt 192.168.56.10 ssh", ["192.168.56.10"]),
    # -P 是文件 flag,其值(即使无扩展名)不参与提取
    ("hydra -l admin -P passwords 192.168.56.10 ssh", ["192.168.56.10"]),
    ("hashcat hashes.txt rockyou.txt", []),  # 裸位置常见扩展名视为文件名
    ("nmap -sV 192.168.56.10 192.168.56.10", ["192.168.56.10"]),  # 去重
]


@pytest.mark.parametrize(("command", "expected"), EXTRACT_CASES)
def test_extract_targets(command, expected):
    assert extract_targets(command) == expected


def test_extract_targets_msf_key_value():
    assert extract_targets("msfconsole -x 'set RHOSTS 10.0.0.5'") == []
    # 注意:msf 内部 set 命令在 msfconsole 里执行,不经 shell 命令行护栏
    targets = extract_targets("msfvenom -p y RHOSTS=10.0.0.5")
    assert targets == ["10.0.0.5"]


def test_extract_targets_unparseable_raises():
    with pytest.raises(ValueError):
        extract_targets('nmap "192.168.56.10')


# ---------------------------------------------------------------- 判定

def test_check_command_allows_in_scope(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    with audit.AuditLog(log_path) as log:
        decision = check_command("nmap -sV 192.168.56.10", LAB_SCOPE, audit=log)
    assert decision.allowed
    assert decision.targets == ("192.168.56.10",)
    assert audit.verify(log_path)
    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    assert '"kind": "exec_request"' in lines[0]


def test_check_command_denies_out_of_scope(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    with audit.AuditLog(log_path) as log:
        decision = check_command("nmap -sV 8.8.8.8", LAB_SCOPE, audit=log)
    assert not decision.allowed
    assert decision.violations == ("8.8.8.8",)
    # 拒绝说明必须可行动:指出越界目标、列出当前 scope、给出纠正动作
    assert "8.8.8.8" in decision.reason
    assert "192.168.56.0/24" in decision.reason
    assert "scope" in decision.reason
    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    assert '"kind": "exec_denied"' in lines[0]
    assert audit.verify(log_path)


def test_check_command_denies_when_any_target_out():
    decision = check_command("nmap 192.168.56.10 8.8.8.8", LAB_SCOPE)
    assert not decision.allowed
    assert decision.violations == ("8.8.8.8",)


def test_check_command_allows_targetless():
    decision = check_command("ls -la /tmp", LAB_SCOPE)
    assert decision.allowed
    assert decision.targets == ()


def test_check_command_denies_supernet_sweep():
    decision = check_command("nmap 192.168.0.0/16", LAB_SCOPE)
    assert not decision.allowed


def test_check_command_denies_range_reaching_out():
    decision = check_command("nmap 192.168.56.250-192.168.57.5", LAB_SCOPE)
    # 跨段写法其实是逐段范围:上界 192.168.57.5 越界
    assert not decision.allowed


def test_check_command_denies_unparseable_fail_closed(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    with audit.AuditLog(log_path) as log:
        decision = check_command('nmap "192.168.56.10', LAB_SCOPE, audit=log)
    assert not decision.allowed
    assert "无法静态解析" in decision.reason
    assert '"kind": "exec_denied"' in log_path.read_text(encoding="utf-8")


def test_check_command_warns_on_shell_expansion(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    with audit.AuditLog(log_path) as log:
        decision = check_command("ping $TARGET", LAB_SCOPE, audit=log)
    assert decision.allowed  # 无识别目标:放行但留痕
    assert decision.warnings
    assert '"warnings"' in log_path.read_text(encoding="utf-8")


def test_check_command_url_prefix_scope():
    decision = check_command("curl http://127.0.0.1:3000/admin", LAB_SCOPE)
    assert decision.allowed


def test_denial_audit_contains_violations(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    with audit.AuditLog(log_path) as log:
        check_command("curl http://evil.example.com/", LAB_SCOPE, audit=log)
    content = log_path.read_text(encoding="utf-8")
    assert "evil.example.com" in content
    assert "exec_denied" in content


# ============================================================ R01 回归
# R01-A · URL origin 判定(E01);R01-B · nmap 地址集合覆盖(E02);
# R01-C · 混合/畸形/命令级回归。fixture 全部合成(TEST-NET-1 /
# example.com / *.testonly.invalid),不发网络请求。

URL_ORIGIN_CASES = [
    # (目标, 是否在界内)——scope 仅一条 https://example.com
    ("https://example.com", True),  # 规则无路径:授权整个 origin
    ("https://example.com/", True),
    ("https://example.com/admin/login?x=1", True),
    ("HTTPS://EXAMPLE.COM/admin", True),  # scheme/host 大小写不敏感
    ("https://example.com./x", True),  # 尾点归一=同一 DNS 名
    ("https://example.com:443/x", True),  # 显式缺省端口=同一 origin
    ("https://example.com.testonly.invalid", False),  # E01:相邻域名
    ("https://example.com@other.testonly.invalid/", False),  # E01:userinfo
    ("https://example.com:444/", False),  # 非缺省端口=不同 origin
    ("http://example.com/", False),  # 不同 scheme=不同 origin
    ("https://example.com:99999/", False),  # 端口越界:拒绝而非抛异常
    ("https://example.com:abc/", False),  # 非数字端口:拒绝而非抛异常
    ("https://example.com:443evil/", False),  # 端口带垃圾字符
    ("https://", False),  # 空 host
    ("http://[::1", False),  # authority 无法解析(旧实现对调用方抛 ValueError)
]


@pytest.mark.parametrize(("target", "expected"), URL_ORIGIN_CASES)
def test_url_origin_boundary(target, expected):
    """R01-A:仅授权 https://example.com 时的 origin 边界。"""
    scope = parse_scope("https://example.com")
    assert target_in_scope(target, scope) is expected


def test_url_origin_default_port_normalization():
    """缺省端口按 scheme 归一化(双向):规则写 :443 与目标省略 :443 同 origin。"""
    scope = parse_scope("https://example.com:443/app")
    assert target_in_scope("https://example.com/app", scope)
    assert target_in_scope("https://example.com:443/app/x", scope)
    assert not target_in_scope("https://example.com:444/app", scope)
    # 非缺省端口不被归一化放宽
    scope = parse_scope("http://192.0.2.1:8080")
    assert target_in_scope("http://192.0.2.1:8080/x", scope)
    assert not target_in_scope("http://192.0.2.1/x", scope)
    assert not target_in_scope("http://192.0.2.2:8080/x", scope)


def test_url_path_prefix_semantics():
    """origin 相同后按路径前缀判定;前缀语义照旧(不改成目录边界匹配)。"""
    scope = parse_scope("https://example.com/app")
    assert target_in_scope("https://example.com/app", scope)
    assert target_in_scope("https://example.com/app/x?y=1", scope)
    assert target_in_scope("https://example.com/app2", scope)  # 前缀非目录边界
    assert not target_in_scope("https://example.com/other", scope)
    assert not target_in_scope("https://other.testonly.invalid/app", scope)


def test_url_origin_ipv6_normalization():
    """IPv6 字面量经 ipaddress 归一:::1 与 0:0:0:0:0:0:0:1 同 origin。"""
    scope = parse_scope("http://[2001:db8::1]:8080/")
    assert target_in_scope("http://[2001:db8:0:0:0:0:0:1]:8080/x", scope)
    assert not target_in_scope("http://[2001:db8::2]:8080/", scope)
    assert not target_in_scope("http://[2001:db8::1]:8081/", scope)
    assert not target_in_scope("http://[2001:db8::1]/", scope)  # 缺省 80 ≠ 8080


def test_url_falls_back_to_host_rules():
    """URL 规则不匹配时回退 host/IP/通配域判定(「或」语义保留)。"""
    scope = parse_scope("https://example.com\n192.0.2.0/24\n*.testonly.invalid")
    assert target_in_scope("http://192.0.2.9:8080/x", scope)  # host 落 CIDR
    assert target_in_scope("http://a.testonly.invalid/", scope)  # host 落通配域
    assert not target_in_scope("http://192.0.3.9/", scope)
    assert not target_in_scope("http://other.invalid/", scope)
    # 主机名规则覆盖任意端口/scheme;细粒度授权须用 URL 规则表达
    scope = parse_scope("https://example.com\nexample.com")
    assert target_in_scope("http://example.com:9000/x", scope)


BAD_URL_RULES = [
    "https://",  # 空 host(旧实现逐字收下,会字符串匹配所有 https URL)
    "http://:8080/",  # 空 host 带端口
    "https://example.com:99999/",  # 端口越界
    "https://example.com:abc/",  # 非数字端口
]


@pytest.mark.parametrize("line", BAD_URL_RULES)
def test_parse_scope_rejects_bad_url_rule(line):
    """R01-A:畸形 URL 规则在加载期拒绝(fail closed),不逐字收下。"""
    with pytest.raises(ValueError, match="非法 URL"):
        parse_scope(line)


@pytest.mark.parametrize(
    "line",
    ["https://example.com", "http://127.0.0.1:3000/", "https://example.com/api/v1"],
)
def test_parse_scope_accepts_legal_url_rule(line):
    assert parse_scope(line).url_prefixes == (line,)


# ---------------------------------------------------------------- R01-B

def test_nmap_range_union_hole():
    """R01-B/E02:离散 /32 端点都在界内 ≠ 整段被授权覆盖。"""
    scope = parse_scope("192.0.2.1/32\n192.0.2.254/32")
    assert target_in_scope("192.0.2.1", scope)
    assert target_in_scope("192.0.2.254", scope)
    assert not target_in_scope("192.0.2.2", scope)
    assert not target_in_scope("192.0.2.1-254", scope)  # 旧端点法误放行
    assert not target_in_scope("192.0.2.1-253", scope)  # 空洞同样拒绝
    # 相邻 CIDR 并集完整覆盖 → 允许
    scope = parse_scope("192.0.2.0/25\n192.0.2.128/25")
    assert target_in_scope("192.0.2.0-255", scope)
    # 并集带空洞(.128–.191 未授权)→ 拒绝
    scope = parse_scope("192.0.2.0/25\n192.0.2.192/26")
    assert not target_in_scope("192.0.2.0-255", scope)
    assert target_in_scope("192.0.2.0-127", scope)  # 被完整覆盖的子段仍允许
    assert target_in_scope("192.0.2.192-255", scope)


def test_nmap_range_multi_octet():
    """多八位组范围按笛卡尔积判定,可由不同 CIDR 分别覆盖。"""
    scope = parse_scope("192.0.2.0/24")
    assert target_in_scope("192.0.2.10-20", scope)  # 全集在 /24 内
    assert not target_in_scope("192.0.2-3.10", scope)  # 192.0.3.10 越界
    # 两个八位组同时取区间:笛卡尔积全集在 /16 内
    scope = parse_scope("192.0.0.0/16")
    assert target_in_scope("192.0.2-3.10-20", scope)
    assert not target_in_scope("192.0-1.2.10", scope)  # 192.1.2.10 越界
    scope = parse_scope("192.0.2.0/24\n192.0.3.0/25")
    assert target_in_scope("192.0.2-3.0-2", scope)  # 两个分量各有 CIDR 覆盖
    scope = parse_scope("192.0.2.0/24\n192.0.3.128/25")
    assert not target_in_scope("192.0.2-3.0-2", scope)  # 192.0.3.0-2 无覆盖
    # 笛卡尔积中间分量落在并集空洞(192.0.3.0):旧端点法误放行
    scope = parse_scope("192.0.2.0/24\n192.0.4.0/24")
    assert not target_in_scope("192.0.2-4.0", scope)
    scope = parse_scope("192.0.2.0/24\n192.0.3.0/24\n192.0.4.0/24")
    assert target_in_scope("192.0.2-4.0-1", scope)  # 无空洞时全集允许


def test_nmap_range_mixed_ip_versions():
    """v6 CIDR 不能覆盖 v4 范围;IPv4/IPv6 混合 scope 不得崩溃。"""
    scope = parse_scope("2001:db8::/32")
    assert not target_in_scope("192.0.2.1-50", scope)
    scope = parse_scope("2001:db8::/32\n192.0.2.0/24")
    assert target_in_scope("192.0.2.1-50", scope)


def test_nmap_range_inverted_octet_invalid():
    """倒置八位组区间(50-1)不是合法范围;按主机名处理 → 不在界内。"""
    scope = parse_scope("192.0.2.0/24")
    assert not target_in_scope("192.0.2.50-1", scope)


def test_nmap_range_leading_zero_octet_rejected():
    """前导零八位组(056)有 inet_aton 八进制歧义:不当范围解析,拒绝。"""
    scope = parse_scope("192.0.0.0/16")
    assert not target_in_scope("192.0.056.1-50", scope)


def test_nmap_range_huge_bounded_computation():
    """R01-B:大范围不得逐 IP 枚举——全网笛卡尔积上的空洞须立即判定。"""
    # 并集在 64/8–127/8 有空洞;hull 两端(0.0.0.0 与 255.255.255.255)都被覆盖
    scope = parse_scope("0.0.0.0/2\n128.0.0.0/1")
    assert not target_in_scope("0-255.0-255.0-255.0-255", scope)
    # 无空洞时同一全网集合允许
    scope = parse_scope("0.0.0.0/0")
    assert target_in_scope("0-255.0-255.0-255.0-255", scope)
    # 小 scope + 全网请求:立即拒绝
    scope = parse_scope("10.0.0.0/8")
    assert not target_in_scope("0-255.0-255.0-255.0-255", scope)


def _brute_force_range_covered(octets, scope) -> bool:
    """oracle:逐地址枚举笛卡尔积,每个地址都必须落在 scope 的 CIDR 内。"""
    for combo in itertools.product(*(range(lo, hi + 1) for lo, hi in octets)):
        addr = ipaddress.IPv4Address(bytes(combo))
        if not any(addr in net for net in scope.cidrs):
            return False
    return True


NMAP_ORACLE_CASES = [
    # (scope 文本, 四个八位组的 (lo, hi) 区间)——地址域刻意保持小,便于枚举
    ("192.0.2.0/24", ((192, 192), (0, 0), (2, 2), (0, 3))),
    ("192.0.2.0/25", ((192, 192), (0, 0), (2, 2), (0, 3))),
    ("192.0.2.0/25", ((192, 192), (0, 0), (2, 2), (124, 131))),  # 跨界溢出
    ("192.0.2.0/25\n192.0.2.128/25", ((192, 192), (0, 0), (2, 2), (0, 7))),
    ("192.0.2.0/25\n192.0.2.192/26", ((192, 192), (0, 0), (2, 2), (0, 3))),
    # hull 端点在界内、中间有空洞(旧端点法误放行,oracle 必须一致拒绝)
    ("192.0.2.0/25\n192.0.2.192/26", ((192, 192), (0, 0), (2, 2), (126, 193))),
    ("192.0.2.0/24\n192.0.3.0/25", ((192, 192), (0, 0), (2, 3), (0, 2))),
    ("192.0.2.0/24\n192.0.3.128/25", ((192, 192), (0, 0), (2, 3), (0, 2))),
    ("2001:db8::/32\n192.0.2.0/29", ((192, 192), (0, 0), (2, 2), (0, 3))),
    ("2001:db8::/32", ((192, 192), (0, 0), (2, 2), (0, 3))),  # 纯 v6 不覆盖 v4
    ("192.0.2.1/32\n192.0.2.2/32", ((192, 192), (0, 0), (2, 2), (1, 2))),  # 相邻
    ("192.0.2.1/32\n192.0.2.3/32", ((192, 192), (0, 0), (2, 2), (1, 2))),  # 空洞
    # 多八位组笛卡尔积中间分量落在并集空洞
    ("192.0.2.0/24\n192.0.4.0/24", ((192, 192), (0, 0), (2, 4), (0, 0))),
]


@pytest.mark.parametrize(("scope_text", "octets"), NMAP_ORACLE_CASES)
def test_nmap_range_matches_brute_force_oracle(scope_text, octets):
    """R01-B:小地址域枚举 oracle 与区间算法逐案一致。"""
    scope = parse_scope(scope_text)
    range_str = ".".join(
        str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in octets
    )
    expected = _brute_force_range_covered(octets, scope)
    assert target_in_scope(range_str, scope) is expected


# ---------------------------------------------------------------- R01-C

def test_check_command_denies_url_userinfo_bypass(tmp_path):
    """E01 命令级:curl https://example.com@other.testonly.invalid/ 拒绝并留痕。"""
    log_path = tmp_path / "audit.jsonl"
    scope = parse_scope("https://example.com")
    with audit.AuditLog(log_path) as log:
        decision = check_command(
            "curl https://example.com@other.testonly.invalid/", scope, audit=log
        )
    assert not decision.allowed
    assert decision.violations == ("https://example.com@other.testonly.invalid/",)
    assert '"kind": "exec_denied"' in log_path.read_text(encoding="utf-8")


def test_check_command_allows_same_origin_url():
    scope = parse_scope("https://example.com")
    decision = check_command("curl https://example.com/admin/login", scope)
    assert decision.allowed


def test_check_command_denies_nmap_range_with_hole():
    """E02 命令级:nmap 192.0.2.1-254 在离散 /32 scope 下拒绝。"""
    scope = parse_scope("192.0.2.1/32\n192.0.2.254/32")
    decision = check_command("nmap 192.0.2.1-254", scope)
    assert not decision.allowed
    assert decision.violations == ("192.0.2.1-254",)


def test_check_command_denies_malformed_url_not_raise():
    """畸形 URL 目标:拒绝(fail closed),不向调用方抛解析异常。"""
    scope = parse_scope("https://example.com")
    decision = check_command("curl http://[::1", scope)
    assert not decision.allowed
    decision = check_command("curl https://example.com:99999/", scope)
    assert not decision.allowed
