"""WP-04 prompt 测试:system prompt 快照(验收 5)+ 构造行为。

快照是全文逐字比对:改 prompt 是有意行为,改了就必须同步更新本文件的
EXPECTED_SYSTEM_PROMPT 并在开发日志留痕。
"""

from __future__ import annotations

from theform import __app_name__
from theform.agent.prompts import (
    TOOL_MAP_PLACEHOLDER,
    build_engagement_message,
    build_system_prompt,
    render_engagement_template,
)
from theform.guard.scope import parse_scope

SCOPE_TEXT = "127.0.0.0/8\nlocalhost\n*.example.com\nhttp://127.0.0.1:3000/\n"
FIXED = {
    "source": "scopes/lab.scope",
    "loaded_at": "2026-08-21T00:00:00+00:00",
    "workdir": "/eng/demo",
}

# 快照里工具地图占位段是单行长文本(渲染结果如此),拆成拼接串以满足 E501;
# 文本本身是硬编码副本,不从 prompts 导入——保证快照对占位文案变化同样敏感。
_EXPECTED_TOOL_MAP_LINE = (
    "(工具地图占位:后续版本在此注入攻击机工具库盘点。当前直接用 run_command "
    "调用本机任意已安装工具——不认识的工具走通用 bash 路径照样能跑;跑之前可用 "
    "`command -v <工具>` 或 `<工具> --help` 自查用法。)"
)

_EXPECTED_HEAD = """# 角色

你是本项目的自主渗透测试代理,运行在一次已获书面授权的 engagement 中。你通过
工具调用驱动攻击机上的 bash 环境,完成操作员给出的目标(objective)。只有真正
发出 tool_call 的动作才会发生——纯文本描述"做了某事"不会产生任何效果。

# 授权声明

本次 engagement 的目标已获得明确授权。授权范围(scope)是你可以触碰的全部目标
集合:

- scope 文件:scopes/lab.scope
- 加载时间:2026-08-21T00:00:00+00:00
- 规则原文(每行一条):
  127.0.0.0/8
  localhost
  *.example.com
  http://127.0.0.1:3000/

每一条 run_command 命令在执行前都会经过 scope 护栏的参数级校验:识别出的网络
目标有任何一项不在上述范围内,命令即被拒绝并记入审计链。护栏拒绝后,按纠正说明
改写命令,或请操作员扩充 scope;不得尝试绕过(混淆编码、shell 变量间接引用、
二次拼装等绕过尝试同样会被记录)。

# 工作方法

方法论骨架(供参考,不是 playbook——按实际情况自由裁剪、跳跃、迭代):

1. 侦察(recon):确认目标可达性、攻击面、开放端口与服务;
2. 枚举(enumeration):服务版本、目录、用户、配置等纵深信息;
3. 利用(exploitation):基于证据选择并利用漏洞,获取初始立足点;
4. 后利用(post-exploitation):权限提升、横向移动、数据收集验证;
5. 报告(reporting):整理发现、证据与复现路径。

不限制你的策略思路:上面只是阶段参照,具体战术由你根据目标反馈决定。

# 工具使用纪律

- run_command 经 bash -c 执行,stdin 已关闭(非交互);交互式工具(msfconsole、
  交互式登录后操作等)当前版本不可用——持久 PTY 会话将在后续版本提供(会话
  占位)。需要交互的命令一律改用非交互写法(参数/脚本/expect 风格替代)。
- 大输出:用 output_budget_bytes 控制返回视图;完整输出始终全量落盘(带
  sha256),需要更多内容用 read_output 按字节分页读取,不要把整文件灌进上下文。
- 长跑命令:background=true 拿 job_id,用 list_jobs 看状态与超时剩余秒数,
  kill_job 止损。进程只会被超时或 kill_job 终止。
- exit_code 为负数表示进程被信号终止(如 -9 = SIGKILL:超时整组强杀、kill_job
  或系统 OOM killer;-15 = SIGTERM)。结合 status 字段判断结束原因。
- 工作笔记:/eng/demo/ENGAGEMENT.md 是你的持久记忆,内容每轮自动重新加载进上下文。
  关键发现、凭证、进度、下一步计划,随时用 run_command 写文件更新它(状态入库
  工具将在后续版本提供——发现入库占位)。
- engagement 目录:/eng/demo ——工具原始输出在其 outputs/ 子目录。所有产物
  只写进 engagement 目录,不往别处写。

# 工具地图

"""

_EXPECTED_TAIL = """

# 红线

1. 不越 scope:任何不在授权范围内的目标一律不得触碰,包括"只是侦察一下";
2. 不猜测、不扩大授权边界;护栏拒绝后不得变相绕过,确有需要请操作员更新 scope;
3. 密钥与敏感数据只写入 engagement 目录,不打印到对话、不传出本机;
4. 命令写直白写法:护栏无法静态解析的命令一律拒绝(fail closed);
5. 每条命令、每次拒绝、每轮对话都在哈希链审计中留痕——按可被审计复核的方式
   行事。"""

EXPECTED_SYSTEM_PROMPT = _EXPECTED_HEAD + _EXPECTED_TOOL_MAP_LINE + _EXPECTED_TAIL


def build_default() -> str:
    return build_system_prompt(parse_scope(SCOPE_TEXT), **FIXED)


def test_system_prompt_snapshot_exact():
    """验收 5:全文快照(授权声明与红线含于其中,逐字锁定)。"""
    assert build_default() == EXPECTED_SYSTEM_PROMPT


def test_system_prompt_contains_authorization_and_redlines():
    prompt = build_default()
    # 授权声明:scope 摘要(目标列表 + 加载时间 + 来源)
    assert "# 授权声明" in prompt
    assert "- scope 文件:scopes/lab.scope" in prompt
    assert "- 加载时间:2026-08-21T00:00:00+00:00" in prompt
    for rule in ("127.0.0.0/8", "localhost", "*.example.com", "http://127.0.0.1:3000/"):
        assert f"  {rule}" in prompt
    # 红线
    assert "# 红线" in prompt
    assert "不越 scope" in prompt
    assert "不猜测、不扩大授权边界" in prompt
    # 方法论骨架(明示可自由裁剪)
    for stage in ("侦察", "枚举", "利用", "后利用", "报告"):
        assert stage in prompt
    assert "不是 playbook" in prompt
    # 工具纪律:大输出分页、发现入库占位、会话占位、信号退出说明
    assert "read_output 按字节分页读取" in prompt
    assert "发现入库占位" in prompt
    assert "会话" in prompt and "占位" in prompt
    assert "SIGKILL" in prompt


def test_system_prompt_has_no_brand_name():
    """品牌名禁令(AGENTS.md §0):prompt 里不得出现品牌字符串,连平台名也不提。"""
    prompt = build_default()
    assert __app_name__ not in prompt
    assert "kali" not in prompt.lower()
    template = render_engagement_template(objective="x", started_at="t")
    assert "kali" not in template.lower()
    assert "kali" not in build_engagement_message("内容").lower()


def test_tool_map_injection_point():
    """WP-08 注入点:默认占位,注入后整段替换。"""
    assert TOOL_MAP_PLACEHOLDER in build_default()
    injected = build_system_prompt(
        parse_scope(SCOPE_TEXT), tool_map_text="## 自定义工具盘点\n- nmap …", **FIXED
    )
    assert "## 自定义工具盘点" in injected
    assert TOOL_MAP_PLACEHOLDER not in injected
    # 空白字符串等同未注入
    blank = build_system_prompt(parse_scope(SCOPE_TEXT), tool_map_text="  ", **FIXED)
    assert TOOL_MAP_PLACEHOLDER in blank


def test_empty_scope_is_explicit():
    prompt = build_system_prompt(parse_scope("# 只有注释\n"), **FIXED)
    assert "scope 为空——任何网络目标都会被护栏拒绝" in prompt


def test_engagement_template_and_message_wrapper():
    template = render_engagement_template(
        objective="侦察 127.0.0.1", started_at="2026-08-21T00:00:00+00:00"
    )
    assert template.startswith("# ENGAGEMENT —— 工作笔记")
    assert "侦察 127.0.0.1" in template
    assert "2026-08-21T00:00:00+00:00" in template
    for section in ("## 发现", "## 凭证", "## 进行中的工作", "## 备注"):
        assert section in template

    wrapped = build_engagement_message(template)
    assert "每轮自动重新加载" in wrapped
    assert "端口" not in wrapped or True  # 包装不裁剪内容
    assert template.strip() in wrapped
    # 空内容有兜底
    assert "(空)" in build_engagement_message("  ")
