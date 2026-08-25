#!/bin/sh
# WP-11 场景一环境探针:跑 e2e 前/补测前的自检(只读,不改动任何状态)。
# 用法: tests/e2e/probe_scenario1.sh [scope 文件,默认 scopes/lab.scope]
# 退出码: 0 = 靶场可打; 1 = 环境不具备(输出缺什么)。
set -u

SCOPE_FILE="${1:-scopes/lab.scope}"
TARGET_URL="http://127.0.0.1:3000/"
fail=0

say() { printf '%s\n' "$*"; }

# 1. 容器在跑
if command -v docker >/dev/null 2>&1 \
    && docker ps --format '{{.Names}}' 2>/dev/null | grep -qx juice-shop; then
    say "[ok] docker 容器 juice-shop 在跑"
else
    say "[缺] docker 容器 juice-shop 未运行(起法见 docs/e2e/scenario1-setup.md)"
    fail=1
fi

# 2. 靶场探活(绕开本机代理:死代理曾把 curl 导走,见 setup 文档「代理坑」)
code=$(curl -sS --noproxy 127.0.0.1 -o /dev/null -w '%{http_code}' \
    --max-time 8 "$TARGET_URL" 2>/dev/null || echo 000)
if [ "$code" = "200" ]; then
    say "[ok] $TARGET_URL 探活 HTTP 200"
else
    say "[缺] $TARGET_URL 探活 HTTP $code(预期 200)"
    fail=1
fi

# 3. scope 覆盖(回环段 + URL 前缀;护栏「或」语义见 WP-02 日志)
if [ -f "$SCOPE_FILE" ] \
    && grep -q '^127\.0\.0\.0/8' "$SCOPE_FILE" \
    && grep -q '^http://127\.0\.0\.1:3000/' "$SCOPE_FILE"; then
    say "[ok] $SCOPE_FILE 覆盖 127.0.0.0/8 与 $TARGET_URL"
else
    say "[缺] $SCOPE_FILE 未同时覆盖 127.0.0.0/8 与 $TARGET_URL"
    fail=1
fi

# 4. 工具面(如实报告;缺失不是失败——工具地图本就标注缺失)
tools="nmap sqlmap ffuf gobuster whatweb nikto hydra curl python3"
line=""
for t in $tools; do
    if command -v "$t" >/dev/null 2>&1; then
        line="${line} ${t}[ok]"
    else
        line="${line} ${t}[--]"
    fi
done
say "[工具]$line"

# 5. LLM 环境变量(只查存在性,绝不打印值)
for v in FOAM_LLM_API_KEY FOAM_LLM_BASE_URL FOAM_LLM_MODEL; do
    eval "val=\${$v:-}"
    if [ -n "$val" ]; then
        say "[ok] env $v 已设置"
    else
        say "[缺] env $v 未设置(会话内桥接提供,见 setup 文档)"
        fail=1
    fi
done

if [ "$fail" -eq 0 ]; then
    say "探针通过:场景一环境可打。"
else
    say "探针未过:按上面 [缺] 项补齐。"
fi
exit "$fail"
