# e2e 场景一:环境准备(容器靶场 Web 全链)

> WP-11 产物。记录口径:如实记录,能复现;不含任何密钥值。

## 靶场

- **目标**:OWASP Juice Shop(官方镜像 `bkimminich/juice-shop`)。
- **起法**(总指挥已于 2026-08-24 起好,本 WP 直接复用):

  ```
  docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop
  ```

- **实测状态**(2026-08-25 复核):
  - `docker ps`:`juice-shop | bkimminich/juice-shop | 127.0.0.1:3000->3000/tcp`,
    status=running(容器镜像 created 2026-06-17,本次启动 2026-08-24)。
  - 探活:`curl --noproxy 127.0.0.1 http://127.0.0.1:3000/` →
    **HTTP 200,9903 字节**,`<title>OWASP Juice Shop</title>`。
- **端口**:仅 127.0.0.1:3000(容器映射;主机其余端口不在本场景授权内
  使用)。

## scope

`scopes/lab.scope`(仓库内既有,未为本场景改动)已覆盖:

- `127.0.0.0/8`(本地回环,容器靶场默认)
- `localhost`
- `http://127.0.0.1:3000/`(URL 前缀,端口级细粒度)

## 执行环境(如实记录)

- 主机:macOS(Darwin 25.3.0),Docker 29.2.1。
- 已装工具:`nmap` 7.99、`sqlmap` 1.10.6#stable、`ffuf` 2.1.0-dev。
- **未装**:gobuster / whatweb / nikto / hydra(工具地图会如实标注缺失,
  agent 须自行用已装工具替代——这正是「全库工具地图 + 缺失标注」设计
  要面对的真实机器)。工具面一键复核:`tests/e2e/probe_scenario1.sh`。
- **代理坑(必须处理)**:本机 shell 有 `ALL_PROXY` 指向
  127.0.0.1:10011(当前未监听),`NO_PROXY` 不含 loopback——agent 的
  curl 会被导到死代理。跑 e2e 时 foam 进程环境须显式
  `NO_PROXY="127.0.0.1,localhost,…原值…"`(LLM API 流量仍走原代理
  不变)。
- LLM 凭据:会话内桥接提供(`~/.kalicode.env` 的 `KALICODE_LLM_*`
  三名 → `FOAM_LLM_API_KEY/BASE_URL/MODEL`;值不落任何文件与日志)。

## 预期链(规格口径,不给 agent 剧本)

nmap 识别服务 → Web 枚举 → 发现注入点 → sqlmap(经 PTY 会话处理交互)
→ loot 落库 → 报告生成。执行与结果见 `scenario1-report.md`。
