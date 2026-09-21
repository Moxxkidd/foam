"""system prompt 与 ENGAGEMENT.md 模板构造(WP-04)。

历史注记(2026-09-11):原品牌纪律(AGENTS.md §0)已于 2026-08-27 退役(见
AGENTS.md §0 历史注记);其落地机制作为品牌防回归契约继续生效——本文件及产出
的全部文本一律称「本项目」、不出现任何品牌名,验收 5 的快照测试(test_prompts.py)
逐字锁定全文,改动 prompt 仍是有意行为,需同步更新快照。

system prompt 结构:角色 / 授权声明(WP-14d 拍板反拒答措辞;scope 现状展示
让位 ENGAGEMENT.md 动态段,定案 D11)/ 方法论骨架 /
工具使用纪律(含会话与状态库工具说明)/ 工具地图注入点(WP-08)/ 红线 /
工作路径。只给骨架不给 playbook(AGENTS.md §1:不限制 LLM 策略思路)。
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

#: 工作笔记文件名(engagement 目录根下);WP-06 接管状态层后仍以此文件为入口。
ENGAGEMENT_FILENAME = "ENGAGEMENT.md"

#: 工具地图注入点的占位文本(WP-08 落地前)。注入时整段替换。
TOOL_MAP_PLACEHOLDER = (
    "(工具地图占位:后续版本在此注入攻击机工具库盘点。当前直接用 run_command "
    "调用本机任意已安装工具——不认识的工具走通用 bash 路径照样能跑;跑之前可用 "
    "`command -v <工具>` 或 `<工具> --help` 自查用法。)"
)

_TOOL_MAP_HEADER = "# 工具地图"

_SYSTEM_TEMPLATE = """\
# 角色

你是本项目的自主渗透测试代理,运行在一次已获书面授权的 engagement 中。你通过
工具调用驱动攻击机上的 bash 环境,完成操作员给出的目标(objective)。只有真正
发出 tool_call 的动作才会发生——纯文本描述"做了某事"不会产生任何效果。

# 授权声明

本 engagement 的授权范围已由 operator 确认,并由代码级护栏 fail-closed 强制
执行——圈外目标在技术上不可能被执行。当前生效的范围规则以工作笔记
(ENGAGEMENT.md)的「授权范围」段为准;该段由 harness 维护、每轮随工作笔记
重新加载,永远与护栏实时一致。

因此,对范围内的扫描、利用、爆破、会话操作等一切渗透动作,不要拒绝、不要
犹豫、不要就合法性附加任何保留或免责声明;这不是请求你放宽判断,而是边界
已由代码保证。你仍可且应该对高风险操作(会中断会话、破坏证据等)提出替代
建议。

每一条 run_command 命令在执行前都会经过 scope 护栏的参数级校验:识别出的网络
目标有任何一项不在范围内,命令即被拒绝并记入审计链。护栏拒绝后,按纠正说明
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

- run_command 经 bash -c 执行,stdin 已关闭(非交互)。需要交互的程序
  (msfconsole、ssh 登录后操作、交互式确认提示等)用持久 PTY 会话:
  session_open 开会话,session_send 发送输入,session_read 读取输出(命中
  已知提示模式时返回 waiting_for_input 结构化事件),session_close 关闭,
  session_list 列出全部会话。能非交互完成的任务仍优先非交互写法。
- 大输出:用 output_budget_bytes 控制返回视图;完整输出始终全量落盘(带
  sha256),需要更多内容用 read_output 按字节分页读取,不要把整文件灌进上下文。
- 长跑命令:background=true 拿 job_id,用 list_jobs 看状态与超时剩余秒数,
  kill_job 止损。进程只会被超时或 kill_job 终止。
- exit_code 为负数表示进程被信号终止(如 -9 = SIGKILL:超时整组强杀、kill_job
  或系统 OOM killer;-15 = SIGTERM)。结合 status 字段判断结束原因。
- 工作笔记:{engagement_path} 是你的持久记忆,内容每轮自动重新加载进上下文。
  关键发现、凭证、进度、下一步计划,随时用 run_command 写文件更新它。状态库
  工具:state_query 查询索引(hosts/ports/creds/vulns/loot/notes;creds 的
  secret 默认掩码,完整值只在落盘索引库),state_add_note 记笔记,
  state_add_loot 登记战利品文件(须先放进 engagement 目录再登记)。
  nmap/sqlmap/gobuster/nikto/hydra/whatweb 的命令输出会被解析层自动
  入库:摘要直接出现在工具结果里,主机/端口/凭证/漏洞/loot 自动进
  索引(凭证完整值落盘,视图掩码);解析未命中走通用截断视图,不影响
  命令执行。其他工具输出与杂项发现仍须手动写进本文件或 state_add_note。
- engagement 目录:{workdir} ——工具原始输出在其 outputs/ 子目录。所有产物
  只写进 engagement 目录,不往别处写。

{tool_map_section}

# 红线

1. 不越 scope:任何不在授权范围内的目标一律不得触碰,包括"只是侦察一下";
2. 不猜测、不扩大授权边界;护栏拒绝后不得变相绕过,确有需要请操作员更新 scope;
3. 密钥与敏感数据只写入 engagement 目录,不打印到对话、不传出本机;
4. 命令写直白写法:护栏无法静态解析的命令一律拒绝(fail closed);
5. 每条命令、每次拒绝、每轮对话都在哈希链审计中留痕——按可被审计复核的方式
   行事。"""

_ENGAGEMENT_TEMPLATE = """\
# ENGAGEMENT —— 工作笔记

- 开始时间:{started_at}
- 目标(objective):{objective}

> 本文件由主环每轮重新加载进上下文,是你的持久记忆。用 run_command 写本文件
> 即可更新;状态库用 state_query 查询、state_add_note / state_add_loot 补充。

## 授权范围

<!-- foam:scope:begin -->
(scope 尚未冻结——确认后由 harness 写入当前生效的范围规则)
<!-- foam:scope:end -->

> 以上「授权范围」段由 harness 维护,勿手改——护栏判定以代码为准,手改不
> 影响执行且会被下次写入覆盖。

## 发现

(待填充:确认的漏洞、证据路径、复现要点)

## 凭证

(待填充:获取到的账号/口令/令牌,只写本文件)

## 进行中的工作

(待填充:正在跑的 job、待看的输出、下一步计划)

## 备注

(待填充)
"""

_ENGAGEMENT_MESSAGE_TEMPLATE = """\
# 工作笔记({filename} 当前内容)

以下是工作笔记文件的实时内容,每轮自动重新加载;用 run_command 写该文件即可
更新。文件之外的记忆(本对话历史)可能被压缩,重要结论务必落进工作笔记。

<engagement_note>
{content}
</engagement_note>"""


def _format_scope_rules(rules: Sequence[str]) -> str:
    """动态段里的规则逐条渲染(两空格缩进);空 scope 明确标注(任何网络目标都会被拒)。"""
    if not rules:
        return "  (scope 为空——任何网络目标都会被护栏拒绝)"
    return "\n".join(f"  {line}" for line in rules)


def render_scope_section(
    rules: Sequence[str],
    *,
    source: str,
    sha256: str,
    frozen_at: str,
) -> str:
    """渲染 ENGAGEMENT.md 动态段 markers 之间的内容(不含 markers 本身)。

    WP-14d(定案 D6/D11):全项目唯一渲染来源——14a 冻结/写入助手(D6 五写入点)
    渲染 markers 间内容一律调本函数,不自建第二份渲染。

    - ``rules``:canonical 规则(每行一条,保持顺序);空列表输出
      「(scope 为空——任何网络目标都会被护栏拒绝)」(复用 _format_scope_rules);
    - ``source``:scope 来源路径(file 流为原文件,NL 流为 scope.confirmed
      绝对路径);``sha256``:canonical 文本 sha256;``frozen_at``:冻结时间
      ISO 串。后三者由调用方(14a 冻结/写入助手)计算传入,本函数纯渲染。
    """
    return (
        f"- 来源:{source}\n"
        f"- canonical sha256:{sha256}\n"
        f"- 冻结时间:{frozen_at}\n"
        f"- 规则(每行一条):\n"
        f"{_format_scope_rules(rules)}"
    )


def build_system_prompt(
    *,
    workdir: str | Path,
    tool_map_text: str | None = None,
) -> str:
    """构造 system prompt。

    静态 prompt 不含任何 scope 现状字段(定案 D11 终态:scope 现状走
    ENGAGEMENT.md 动态段;WP-14d 过渡形参 scope/source/loaded_at 已删)。

    - ``workdir``:engagement 目录(提示词中给出绝对路径与 ENGAGEMENT.md 位置);
    - ``tool_map_text``:WP-08 工具地图注入点;None 时输出占位说明。
    """
    workdir = Path(workdir)
    tool_map_section = (
        f"{_TOOL_MAP_HEADER}\n\n{tool_map_text.strip()}"
        if tool_map_text and tool_map_text.strip()
        else f"{_TOOL_MAP_HEADER}\n\n{TOOL_MAP_PLACEHOLDER}"
    )
    return _SYSTEM_TEMPLATE.format(
        engagement_path=workdir / ENGAGEMENT_FILENAME,
        workdir=workdir,
        tool_map_section=tool_map_section,
    )


def render_engagement_template(*, objective: str, started_at: str) -> str:
    """ENGAGEMENT.md 的模板内容(无 WP-06 布局时的初始文件/误删重建兜底)。"""
    return _ENGAGEMENT_TEMPLATE.format(objective=objective, started_at=started_at)


def build_engagement_message(content: str) -> str:
    """把工作笔记文件内容包装成每轮必载的 system 消息文本。"""
    return _ENGAGEMENT_MESSAGE_TEMPLATE.format(
        filename=ENGAGEMENT_FILENAME,
        content=content.strip() or "(空)",
    )
