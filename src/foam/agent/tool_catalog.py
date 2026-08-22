"""静态工具目录(WP-08):覆盖 Kali 主要 metapackage 的常用工具,按渗透阶段分组。

本文件只放**数据**,逻辑在 toolmap.py:

- ``ToolEntry.name`` 即 which/路径/dpkg 的探测键——探测键与工具名是同一字段,
  从结构上消灭「目录名与探测键不一致」的死链(验收 1);
- ``package`` 仅当 apt 包名与命令名不同时才写(如 searchsploit → exploitdb),
  盘点与「未安装可 apt install」提示都以此为准;
- summary 一句话用途、usage 常用 flag 提示——按规格「一句话为止」,深度
  用法由 LLM 自行 man/--help(这正是 bash 全开的意义);
- 品牌纪律:目录文本不出现任何品牌名。
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolEntry:
    """一条工具目录项。name 是命令名(探测键);package 为 None 时与 name 同名。"""

    name: str
    summary: str  # 一句话用途
    usage: str  # 常用 flag 提示(一句话为止)
    package: str | None = None  # apt 包名;None 表示与命令名相同


@dataclass(frozen=True)
class ToolGroup:
    """一个渗透阶段分组。key 供「当前阶段优先」裁剪选用。"""

    key: str
    title: str
    tools: tuple[ToolEntry, ...]


TOOL_CATALOG: tuple[ToolGroup, ...] = (
    ToolGroup(
        key="recon",
        title="信息收集",
        tools=(
            ToolEntry("nmap", "端口、服务、版本与 OS 探测", "-sV -O;-p- 全端口"),
            ToolEntry("masscan", "海量 SYN 快速扫全端口", "--rate=10000 -p1-65535"),
            ToolEntry("rustscan", "快速端口扫并把结果交 nmap", "-a <IP> -- -sV"),
            ToolEntry("naabu", "轻量端口扫描", "-host <IP> -p -"),
            ToolEntry("arp-scan", "二层 ARP 主机发现", "--localnet"),
            ToolEntry("netdiscover", "ARP 主动/被动主机发现", "-r <网段>"),
            ToolEntry("fping", "批量 ICMP 存活探测", "-g <网段>"),
            ToolEntry("hping3", "手工构造包探测/防火墙测试", "-S -p 80 <IP>"),
            ToolEntry("theharvester", "OSINT 收集邮箱与子域", "-d <域> -b all"),
            ToolEntry("sublist3r", "子域枚举", "-d <域>"),
            ToolEntry("amass", "深度资产与子域枚举", "enum -d <域>"),
            ToolEntry("subfinder", "快速子域发现", "-d <域>"),
            ToolEntry("assetfinder", "子域抓取", "--subs-only <域>"),
            ToolEntry("dnsrecon", "DNS 记录与区域传送尝试", "-d <域> -t axfr"),
            ToolEntry("dnsenum", "DNS 枚举", "<域>"),
            ToolEntry("fierce", "DNS 爆破枚举", "--domain <域>"),
            ToolEntry("whois", "域名注册信息查询", "<域>"),
            ToolEntry("dig", "DNS 查询", "@<DNS> <域> ANY", package="dnsutils"),
            ToolEntry("host", "简易 DNS 查询", "<域>", package="bind9-host"),
            ToolEntry("nslookup", "交互式 DNS 查询", "<域>", package="dnsutils"),
            ToolEntry("recon-ng", "OSINT 聚合框架", "marketplace install …"),
            ToolEntry("traceroute", "路由路径追踪", "<IP>"),
            ToolEntry("mtr", "实时链路诊断", "-rw <IP>"),
            ToolEntry(
                "snmpwalk", "SNMP OID 遍历", "-v2c -c public <IP>", package="snmp"
            ),
            ToolEntry("onesixtyone", "SNMP 团体串爆破", "-c <字典> <IP>"),
            ToolEntry("snmp-check", "SNMP 信息汇总", "<IP>", package="snmpcheck"),
            ToolEntry("enum4linux", "SMB/NetBIOS 全项枚举", "-a <IP>"),
            ToolEntry("enum4linux-ng", "enum4linux 现代重写", "-A <IP>"),
            ToolEntry("smbmap", "SMB 共享与权限枚举", "-H <IP>"),
            ToolEntry("rpcclient", "RPC 空会话枚举", '-U "" -N <IP>'),
            ToolEntry("nbtscan", "NetBIOS 名称扫描", "<网段>"),
            ToolEntry(
                "ldapsearch", "LDAP 目录查询", "-x -H ldap://<IP> -b dc=…",
                package="ldap-utils",
            ),
            ToolEntry("smtp-user-enum", "SMTP 用户枚举", "-M VRFY -U <字典> -t <IP>"),
        ),
    ),
    ToolGroup(
        key="vuln",
        title="漏洞分析",
        tools=(
            ToolEntry("nikto", "Web 服务器漏洞扫描", "-h <URL>"),
            ToolEntry("nuclei", "模板化漏洞扫描", "-u <URL> -t <模板>"),
            ToolEntry("wpscan", "WordPress 漏洞扫描", "--url <URL> -e vp,u"),
            ToolEntry("joomscan", "Joomla 漏洞扫描", "-u <URL>"),
            ToolEntry("droopescan", "Drupal 漏洞扫描", "scan drupal -u <URL>"),
            ToolEntry("lynis", "本机安全基线审计", "audit system"),
            ToolEntry(
                "searchsploit", "本地 Exploit-DB 检索", "<关键词>",
                package="exploitdb",
            ),
            ToolEntry("msfconsole", "渗透框架主控台(交互走 PTY 会话)", "-q 静默启动"),
            ToolEntry("msfvenom", "载荷生成器", "-p <载荷> LHOST=… LPORT=…"),
            ToolEntry("msfdb", "框架数据库管理", "init"),
            ToolEntry("commix", "命令注入自动化", "-u <URL>"),
            ToolEntry("tplmap", "服务端模板注入利用", "-u <URL>"),
            ToolEntry("wafw00f", "WAF 识别", "<URL>"),
            ToolEntry("whatweb", "Web 技术栈指纹识别", "<URL>"),
            ToolEntry("wig", "Web 服务器信息收集", "<URL>"),
            ToolEntry("skipfish", "Web 主动安全扫描", "-o <目录> <URL>"),
            ToolEntry("wapiti", "Web 漏洞扫描", "-u <URL>"),
        ),
    ),
    ToolGroup(
        key="web",
        title="Web 测试",
        tools=(
            ToolEntry("gobuster", "目录/DNS/存储桶爆破", "dir -u <URL> -w <字典>"),
            ToolEntry("feroxbuster", "递归目录爆破", "-u <URL> -w <字典>"),
            ToolEntry("ffuf", "Web 参数与路径 fuzz", "-u <URL>/FUZZ -w <字典>"),
            ToolEntry("dirb", "经典目录爆破", "<URL> <字典>"),
            ToolEntry("wfuzz", "Web 模糊测试", "-w <字典> <URL>/FUZZ"),
            ToolEntry("katana", "深度爬虫", "-u <URL>"),
            ToolEntry("hakrawler", "轻量爬虫", "echo <URL> | hakrawler"),
            ToolEntry("gau", "历史 URL 收集", "<域>"),
            ToolEntry("waybackurls", "Wayback 历史 URL 收集", "<域>"),
            ToolEntry("httpx", "HTTP 探活与指纹", "-u <URL> -title -tech-detect"),
            ToolEntry("curl", "HTTP 请求瑞士刀", "-skv <URL>"),
            ToolEntry("wget", "下载与站点镜像", "-r -np <URL>"),
            ToolEntry("sqlmap", "SQL 注入自动化", "-u '<URL>?id=1' --batch"),
            ToolEntry("xsstrike", "XSS 检测与利用", "-u <URL>"),
            ToolEntry("dalfox", "XSS 扫描", "url <URL>"),
            ToolEntry("arjun", "隐藏参数发现", "-u <URL>"),
            ToolEntry("jwt_tool", "JWT 安全审计", "<token>", package="jwt-tool"),
            ToolEntry("burpsuite", "Web 代理测试平台(GUI)", "后台启动,代理 :8080"),
        ),
    ),
    ToolGroup(
        key="password",
        title="密码攻击",
        tools=(
            ToolEntry("hydra", "在线服务口令爆破", "-l <用户> -P <字典> <IP> ssh"),
            ToolEntry("medusa", "并行在线爆破", "-u <用户> -P <字典> -M ssh -h <IP>"),
            ToolEntry("ncrack", "网络认证爆破", "-U <用户表> -P <字典> ssh://<IP>"),
            ToolEntry("patator", "模块化爆破框架", "ssh_login host=<IP> …"),
            ToolEntry("crowbar", "RDP/SSH 密钥爆破", "-b rdp -s <IP>/32"),
            ToolEntry("john", "离线哈希破解", "--wordlist=<字典> <哈希文件>"),
            ToolEntry("hashcat", "GPU 哈希破解", "-m <类型> -a 0 <哈希> <字典>"),
            ToolEntry("hashid", "哈希类型识别", "<哈希>"),
            ToolEntry("hash-identifier", "哈希类型识别(交互)", "直接运行粘贴哈希"),
            ToolEntry("name-that-hash", "哈希类型识别", "-t <哈希>"),
            ToolEntry("crunch", "按规则生成字典", "<最小> <最大> <字符集>"),
            ToolEntry("cewl", "爬网站生成定向字典", "-w out.txt <URL>"),
            ToolEntry("cupp", "社工画像字典生成", "-i 交互输入画像"),
            ToolEntry("fcrackzip", "ZIP 口令破解", "-D -p <字典> <文件>"),
            ToolEntry("pdfcrack", "PDF 口令破解", "-w <字典> <文件>"),
        ),
    ),
    ToolGroup(
        key="sniff",
        title="嗅探与逆向",
        tools=(
            ToolEntry("tshark", "命令行抓包分析", "-i <网卡> -Y <过滤器>"),
            ToolEntry("tcpdump", "经典抓包", "-i any -nn port 80"),
            ToolEntry("wireshark", "GUI 抓包分析", "后台启动"),
            ToolEntry("ettercap", "MITM 嗅探框架", "-T -q -i <网卡>"),
            ToolEntry("bettercap", "现代 MITM 框架", "-iface <网卡>"),
            ToolEntry("mitmproxy", "HTTP 交互式 MITM 代理", "--listen-port 8080"),
            ToolEntry("responder", "LLMNR/NBT-NS 毒化收哈希", "-I <网卡>"),
            ToolEntry(
                "arpspoof", "ARP 欺骗", "-i <网卡> -t <目标> <网关>", package="dsniff"
            ),
            ToolEntry("dnsspoof", "DNS 应答伪造", "-i <网卡>", package="dsniff"),
            ToolEntry("urlsnarf", "HTTP URL 嗅探", "-i <网卡>", package="dsniff"),
            ToolEntry("tcpreplay", "pcap 流量重放", "-i <网卡> <pcap>"),
            ToolEntry("ngrep", "网络层 grep", "-i <网卡> <模式>"),
            ToolEntry(
                "aircrack-ng", "无线握手包破解", "<抓包文件>", package="aircrack-ng"
            ),
            ToolEntry(
                "airodump-ng", "无线抓包", "<监听网卡>", package="aircrack-ng"
            ),
            ToolEntry(
                "aireplay-ng", "无线帧注入", "--deauth 0 -a <BSSID>",
                package="aircrack-ng",
            ),
            ToolEntry("kismet", "无线侦测与告警", "直接运行"),
            ToolEntry("reaver", "WPS PIN 爆破", "-i <监听网卡> -b <BSSID>"),
            ToolEntry("mdk4", "无线压力/干扰测试", "<监听网卡> d"),
            ToolEntry("r2", "radare2 逆向框架", "-A <二进制>", package="radare2"),
            ToolEntry("ghidra", "逆向分析平台(GUI)", "后台启动"),
            ToolEntry("gdb", "调试器(常配 gef/pwndbg 插件)", "-q <二进制>"),
            ToolEntry("objdump", "反汇编", "-d <二进制>", package="binutils"),
            ToolEntry("readelf", "ELF 结构查看", "-h -S <文件>", package="binutils"),
            ToolEntry("strings", "可打印字符串提取", "-a <文件>", package="binutils"),
            ToolEntry("binwalk", "固件分析与解包", "-Me <固件>"),
            ToolEntry("foremost", "文件雕刻恢复", "-i <镜像>"),
            ToolEntry("steghide", "图片隐写提取", "extract -sf <图片>"),
            ToolEntry(
                "exiftool", "文件元数据读取", "<文件>",
                package="libimage-exiftool-perl",
            ),
            ToolEntry("volatility3", "内存取证", "-f <镜像> windows.info"),
        ),
    ),
    ToolGroup(
        key="post",
        title="后利用",
        tools=(
            ToolEntry(
                "nc", "网络瑞士刀与监听", "-lvnp <端口>", package="netcat-openbsd"
            ),
            ToolEntry("ncat", "nc 增强版(支持 TLS)", "--ssl -lvnp <端口>"),
            ToolEntry("socat", "任意双向通道", "TCP-L:<端口> …"),
            ToolEntry("rlwrap", "给哑 shell 补行编辑", "rlwrap nc …"),
            ToolEntry("chisel", "HTTP/SSH 隧道", "server -p 8080 --reverse"),
            ToolEntry("sshuttle", "基于 SSH 的透明代理", "-r <用户>@<IP> <网段>"),
            ToolEntry("proxychains4", "强制程序走代理链", "proxychains4 <命令>"),
            ToolEntry("evil-winrm", "WinRM 交互会话", "-i <IP> -u <用户> -p <口令>"),
            ToolEntry(
                "crackmapexec", "内网批量验证与执行", "smb <网段> -u <用户> -p <口令>"
            ),
            ToolEntry("nxc", "crackmapexec 的后继", "用法同左", package="netexec"),
            ToolEntry(
                "psexec.py", "impacket 远程执行", "<用户>:<口令>@<IP>",
                package="impacket-scripts",
            ),
            ToolEntry(
                "wmiexec.py", "impacket WMI 半交互执行", "<用户>:<口令>@<IP>",
                package="impacket-scripts",
            ),
            ToolEntry(
                "secretsdump.py", "远程导出凭据", "<用户>:<口令>@<IP>",
                package="impacket-scripts",
            ),
            ToolEntry(
                "GetUserSPNs.py", "Kerberoasting 取票",
                "<域>/<用户>:<口令> -request", package="impacket-scripts",
            ),
            ToolEntry(
                "getNPUsers.py", "AS-REP Roasting", "<域>/<用户>:<口令>",
                package="impacket-scripts",
            ),
            ToolEntry("bloodhound", "AD 攻击路径图谱(GUI)", "后台启动,配 SharpHound"),
            ToolEntry("mimikatz", "Windows 凭据提取", "上传目标侧执行"),
        ),
    ),
    ToolGroup(
        key="report",
        title="报告与证据",
        tools=(
            ToolEntry("eyewitness", "批量 Web 截图取证", "--web -f <URL 列表>"),
            ToolEntry("gowitness", "快速批量截图", "file -f <URL 列表>"),
            ToolEntry("cutycapt", "单页截图", "--url=<URL> --out=<png>"),
            ToolEntry("pipal", "口令分布统计分析", "<字典文件>"),
            ToolEntry("dradis", "报告协作平台", "后台启动"),
            ToolEntry("faraday", "漏洞管理与协作平台", "后台启动"),
            ToolEntry("cherrytree", "结构化富文本笔记", "后台启动"),
            ToolEntry("keepassxc", "密码库管理(GUI)", "后台启动"),
        ),
    ),
)
