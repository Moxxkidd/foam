#!/bin/sh
# WP-12 场景二环境探针:Metasploitable2 容器 + msfconsole + LLM env 自检
# (只读,不改动任何状态)。照 tests/e2e/probe_scenario1.sh 模式。
# 用法: tests/e2e/probe_scenario2.sh [scope 文件,默认 scopes/ms2.scope]
# 退出码: 0 = 靶场可打; 1 = 环境不具备(输出缺什么)。
set -u

SCOPE_FILE="${1:-scopes/ms2.scope}"
CONTAINER="ms2"
fail=0

say() { printf '%s\n' "$*"; }

# docker CLI 对无响应 daemon 可能无限阻塞(开发机实测),一律给上界;
# macOS 无 timeout(1),probe 目标平台是 Kali(coreutils 自带),裸跑兜底。
if command -v timeout >/dev/null 2>&1; then
    DOCKER="timeout 15 docker"
else
    DOCKER="docker"
fi

# 0. 运行目录(探针假设在仓库根下跑;.venv 是 foam 的运行底座)
if [ -x .venv/bin/python ]; then
    say "[ok] .venv 在($(.venv/bin/python -c 'import sys; print(sys.version.split()[0])' 2>/dev/null || echo '?'))"
else
    say "[缺] .venv 未建或不在仓库根下运行(见 docs/e2e/scenario2-setup.md)"
    fail=1
fi

# 1. 容器在跑
if command -v docker >/dev/null 2>&1 \
    && $DOCKER ps --format '{{.Names}}' 2>/dev/null | grep -qx "$CONTAINER"; then
    say "[ok] docker 容器 $CONTAINER 在跑"
else
    say "[缺] docker 容器 $CONTAINER 未运行(起法见 docs/e2e/scenario2-setup.md)"
    fail=1
fi

# 2. 容器 IP(docker0 网段,通常 172.17.0.x)
IP=$($DOCKER inspect -f '{{.NetworkSettings.IPAddress}}' "$CONTAINER" 2>/dev/null || true)
case "$IP" in
    ""|*[!0-9.]*)
        say "[缺] 取不到 $CONTAINER 的 IP"
        fail=1
        ;;
    *)
        say "[ok] 容器 IP = $IP"
        ;;
esac

# 3. 靶场探活(两个招牌服务:21 vsftpd / 80 http;x86 容器经 qemu 翻译,
#    服务比原生慢,首次失败可隔 10s 重试再下结论)
if [ -n "${IP:-}" ]; then
    for port in 21 80; do
        if nc -z -w 10 "$IP" "$port" 2>/dev/null; then
            say "[ok] $IP:$port TCP 可达"
        else
            say "[缺] $IP:$port 不可达(qemu 翻译慢,隔 10s 重试一次再判)"
            fail=1
        fi
    done
fi

# 4. scope 覆盖(规格:写死目标 IP 的 /32;探针要求与活容器逐行一致——
#    容器重建换 IP 会被这里挡下,防止拿旧 scope 打新地址)
if [ -n "${IP:-}" ] && [ -f "$SCOPE_FILE" ] \
    && grep -qxF "${IP}/32" "$SCOPE_FILE"; then
    say "[ok] $SCOPE_FILE 精确覆盖 $IP/32"
else
    say "[缺] $SCOPE_FILE 未有 ${IP:-?}/32 独立行(生成法见 setup 文档)"
    fail=1
fi

# 5. 工具面:nmap/msfconsole 是本场景主角,缺席即不可跑
for t in nmap msfconsole; do
    if command -v "$t" >/dev/null 2>&1; then
        say "[ok] 工具 $t 在($(command -v "$t"))"
    else
        say "[缺] 工具 $t 不在 PATH(场景硬依赖)"
        fail=1
    fi
done
line=""
for t in nc curl git; do
    if command -v "$t" >/dev/null 2>&1; then
        line="${line} ${t}[ok]"
    else
        line="${line} ${t}[--]"
    fi
done
say "[工具·参考]$line(缺失不阻断)"

# 6. LLM 环境变量(只查存在性,绝不打印值)
for v in FOAM_LLM_API_KEY FOAM_LLM_BASE_URL FOAM_LLM_MODEL; do
    eval "val=\${$v:-}"
    if [ -n "$val" ]; then
        say "[ok] env $v 已设置"
    else
        say "[缺] env $v 未设置(一次性导出,任何文件/日志不得落 key)"
        fail=1
    fi
done

if [ "$fail" -eq 0 ]; then
    say "[结论] 环境就绪,可开跑(objective 与命令见 docs/e2e/scenario2-setup.md)"
else
    say "[结论] 环境不具备,先补齐上面的 [缺] 项"
fi
exit "$fail"
