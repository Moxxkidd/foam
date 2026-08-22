"""scope 护栏表驱动单测(WP-02 验收 1/2/3)。"""

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
