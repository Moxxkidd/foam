# e2e 场景二:环境准备(Metasploitable 容器 + msfconsole 交互拿 shell)

> WP-12 产物。记录口径:如实记录,能复现;不含任何密钥值。
> 与 WP-11 共享 docs/e2e/ 与 tests/e2e/ 目录(规格声明),本文只覆盖场景二。

## 靶场

- **目标**:Metasploitable(镜像 `tleemcjr/metasploitable2`,linux/amd64)。
  在 arm64 Kali 上经 qemu 用户态翻译运行,**服务响应比原生慢**——探活与
  利用的超时都放宽,首次失败隔 10s 重试再下结论。
- **起法**(镜像已预拉;**必须 `-dit`,不能只有 `-d`**):

  ```
  docker run -dit --name ms2 --platform linux/amd64 tleemcjr/metasploitable2
  docker inspect -f '{{.NetworkSettings.IPAddress}}' ms2
  ```

  实测坑(2026-08-26):镜像 CMD 为 `sh -c "/bin/services.sh && bash"`——
  服务脚本跑完后 exec 交互式 bash;只给 `-d` 时无 TTY/STDIN,bash 立刻
  退出,容器 `Exited (0)` 假死(日志里服务明明都起来了)。`-dit` 保
  STDIN 与 TTY,容器才常住。

- **网络**:容器在 Kali 的 docker0 上拿独立 IP(通常 172.17.0.x);foam
  跑在 Kali 本机直连,拓扑干净(不混 Mac)。
- **重置**(快照建议的容器等价物):`docker rm -f ms2` 后按上行重起。
  **重建后 IP 大概率变**,必须重新生成 scope(下节)并过探针。

## scope

规格要求写死目标 IP(最小授权面)。容器 IP 拿到后生成
`scopes/ms2.scope`(每行一条,`#` 注释;该文件是 shared 目录 scopes/
下为本场景新增的授权证据,已在本 WP 日志声明):

```sh
IP=$(docker inspect -f '{{.NetworkSettings.IPAddress}}' ms2)
printf '# WP-12 场景二 scope——Metasploitable 容器(%s 生成;重建容器后须重新生成)\n%s/32\n' \
    "$(date -u +%F)" "$IP" > scopes/ms2.scope
```

探针要求 scope 里的 `/32` 与活容器 IP **逐行精确一致**——拿旧 scope 打
新地址会被探针挡下(护栏之外的第二道保险)。

## 执行环境

- Kali Rolling arm64;foam 代码树 `~/foam`(rsync 同步,**无 .git,别
  初始化**——关闭 commit 在 Mac 侧仓做,走既有约定)。
- `.venv`:python3 -m venv + pytest/httpx/rich/textual 等(2026-08-22
  补测时已建,Python 3.13.7)。
- LLM(一次性导出,**任何文件/日志不得落 key 值**;探针只查存在性):
  - `FOAM_LLM_BASE_URL=https://api.kimi.com/coding/v1`
  - `FOAM_LLM_MODEL=k3-256k`
  - `FOAM_LLM_API_KEY=<env 一次性导出>`
- msfconsole:metasploit-framework 已预装(6.4.84-0kali1 实测提示符为
  `msf >`;harness 提示库 `msf[56]?` 两代兼容,见
  `docs/dev-logs/WP-05.md`「补测」与陷阱 16)。

## 自检(开跑前)

```sh
tests/e2e/probe_scenario2.sh    # 退出码必须为 0
```

## 顺手项(Kali 债务收尾,开跑前先做掉)

2026-08-22 补测修复的两个测试(commit `437c5ce`)当时未经 pytest 形态
复跑,这次顺手核销:

```sh
.venv/bin/python -m pytest \
    tests/test_session.py::test_msfconsole_full_flow \
    tests/test_toolmap.py::test_scan_real_machine_smoke -v -rs
```

结果如实回填 `docs/dev-logs/WP-05.md` / `docs/dev-logs/WP-08.md` 的
「补测」节与本 WP 日志。

## 实弹(headless,全程无人触碰键盘)

```sh
PYTHONPATH=src .venv/bin/python -m foam.cli run \
    --scope scopes/ms2.scope \
    --objective "<objective 文案见下>" \
    --workdir "engagements/wp12-scenario2-$(date +%Y%m%d)"
```

**objective(自然语言,不给剧本——规格要求;弱点选择、工具选择、
战术路径全由 agent 自主):**

> 对 scope 内的靶机完成一次自主渗透,目标是拿到 shell 并取证。侦察确认
> 攻击面后,自选一个有把握的已知弱点,用持久 PTY 会话驱动 msfconsole
> 完成 use/set/exploit 并建立 session;拿到 session 后执行 `id` 和
> `uname -a` 取证。把证据与关键输出写进工作笔记和 loot。允许重试和更换
> 弱点,每次失败如实记录形态再调整。

收尾核验:

```sh
PYTHONPATH=src .venv/bin/python -m foam.cli replay "<engagement 目录>"  # 审计链 verify,exit 0
PYTHONPATH=src .venv/bin/python -m foam.cli report "<engagement 目录>"  # 报告生成
```

## 失败形态记录口径(验收 4)

每次重试都要记:尝试序号、所选弱点与模块、失败形态分类(msf 提示未识别 /
session 未建立 / exploit 失败 / 靶服务无响应 / 护栏拒绝 / provider 审核
拦截 / 模型偏航)、耗时。达标项与未达标项都进 `docs/dev-logs/WP-12.md`,
未达标不得隐瞒。

## 证据回收(回传 Mac 侧,commit 走既有约定)

- `engagements/wp12-scenario2-*/` 整目录(audit.jsonl、engagement.json、
  ENGAGEMENT.md、outputs/、index.sqlite、loot/)
- 探针输出、顺手项 pytest 输出、foam run 终端输出(tee 落盘)
- replay/report 的核验输出
