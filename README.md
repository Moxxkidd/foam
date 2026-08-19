# Kali Code(暂用代号)

> **命名纪律**:本项目名称为暂用代号,任何阶段都可能整体改名。代码与文档中
> 不得把品牌名写死——品牌字符串只允许出现在 `pyproject.toml` 与
> `src/kalicode/__init__.py` 的单一常量中;文档一律称「本项目」。

一个 **Kali 原生的 LLM 渗透 harness**:让大模型与 Kali 整个工具生态有机
结合——不是把几个工具包成僵硬的模板,而是给 LLM 一个为重型安全工具专门
设计的运行环境:自由 bash + 智能输出层、持久 PTY 交互会话(msfconsole
这类)、工具输出解析与状态索引、scope 硬护栏、全程哈希链审计可回放。

类比:Claude Code 之于软件工程,本项目之于**明确授权**的安全测试。

## 状态

Pre-alpha,WP 制开发中。当前进度见 `docs/HANDOVER.md`,工作包台账见
`docs/wp-ledger.md`。

## 法律与边界

本项目仅服务于**你对目标拥有明确书面授权**的安全测试、教学与靶场演练。
scope 护栏是产品底线而非可选项。使用者对目标选择与合规负全责。

## 运行环境

Kali Linux(裸机/VM),Python ≥ 3.12。

## 安装(开发期)

```bash
git clone <repo> && cd kali-code
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
```

## License

GPL-3.0-only,见 `LICENSE`。
