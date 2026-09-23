# 冷冻电镜采集包 · 断点续传封存台

TypeScript/React 前端 + FastAPI 后端的全栈封存台。上传中断（断线、重发、服务重启、误选文件）
**绝不覆盖**已经确认的数据，封存回执全库**唯一**，进度与回执跨服务重启保留。

## 核心规则

- 会话号：`^[A-Za-z0-9]{1,32}$`；文件大小：1 B – 8 MiB。
- 固定块长 `65536` 字节，块从零起算的偏移必须对齐 65536，末块可缩短。
- 每个 `PUT` 携带：块字节、`X-Chunk-Offset`、`X-Total-Size`、`X-Content-SHA256`
  （整文件小写 SHA-256；元数据首次成功写入后，重传可省略后两个头）。
- 分块允许**乱序**到达。
- 元数据（总长度、摘要、块数）在第一个合法分块成功后**永久固定**。
- 相同重传：**幂等 200**；块内容不同或元数据不同：**409 且状态不变**。
- 未对齐、越界、块长错误：**400**，错误信息带具体偏移/长度，且不留任何状态。
- `POST /seal`：无缺块且服务端重算整文件摘要一致时，原子写入唯一回执；
  此后不可新增/更改分块（相同重传仍 200，不同内容 409）。
- 重复封存返回**同一份回执**；缺块返回 409 并列出 `missing_ranges`（闭区间块号）；
  摘要不符返回 409 且不产生回执文件。
- 新封存会话在回执落盘的同时持久保存**逐块摘要索引** `block_index.json`。
- `POST /audit`：仅已封存会话可复核，返回 `HEALTHY` / `DEGRADED` / `REPAIRING`
  及异常块范围；未封存会话返回 409 且不改变任何上传进度。旧会话首次复核先校验
  块长度与整文件摘要，成功后补建可信索引；失败明确区分**缺块**、**长度异常**、
  **逐块摘要不符**与**无法定位的整文件摘要不符**。
- `POST /repair`：提交完整原文件（原始字节作为请求体）。仅当**长度与回执摘要
  同时一致**时才替换异常块；错误文件返回稳定的 409（`length_mismatch` /
  `digest_mismatch`），封存数据零改动。修复中断后重发或服务重启会自动继续
  直至收敛；原回执与 `sealed_at` 始终不变。修复期间复核返回稳定的 `REPAIRING`。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/health` | 健康检查 |
| `GET` | `/api/uploads/{session}` | 会话状态：已确认块、缺失范围、回执 |
| `PUT` | `/api/uploads/{session}/chunks` | 上传/重传一个分块（头见上） |
| `POST` | `/api/uploads/{session}/seal` | 原子封存；已封存则返回原回执 |
| `POST` | `/api/uploads/{session}/audit` | 完整性复核（仅已封存会话），返回 HEALTHY/DEGRADED/REPAIRING 与异常块范围 |
| `POST` | `/api/uploads/{session}/repair` | 提交完整原文件修复异常块；长度+摘要双校验通过才写入 |

## 持久化与崩溃安全

`./data/<会话>/`：

```
meta.json       # 元数据，首次合法分块时原子写入后不可变
chunks/00000000 …  # 每块一个文件，写临时文件 + fsync + rename 原子落盘
receipt.json    # 仅封存成功后原子出现；存在即代表已封存
block_index.json # 封存时写入的逐块（长度+SHA-256）可信索引；
                 #   旧会话首次复核成功后补建
repair/source   # 仅修复期间存在：已通过长度+整文件摘要双校验的原文件，
                 #   是中断/重启后续修的持久进度标记；收敛后目录被移除
```

所有写操作经进程内锁串行化，落盘均为「临时文件 → fsync → 原子 rename → fsync 目录」，
服务重启/容器重建后直接从该目录重建状态。

## 前端

页面输入会话号、选择文件后浏览器本地计算整文件 SHA-256（优先 WebCrypto，
HTTP 局域网等非安全上下文自动回退到内置纯 TS 实现），逐块 `PUT` 并显示：

- 已确认分块网格与百分比、缺失范围；
- 每块错误（含定位偏移；409 明确提示数据被拒绝覆盖）；
- **重选原文件**即用原会话号**重发所有块**（服务端去重），断线后如此恢复；
- 「查询/恢复服务器进度」可在页面刷新/重启后拉回服务端权威状态；
- 封存后展示唯一回执；
- 「完整性复核」给出 HEALTHY/DEGRADED/REPAIRING、缺块/长度异常/摘要不符的块范围；
- 复核异常时在同一卡片提交**完整原文件**修复，前端本地预计算 SHA-256，
  服务端以回执长度与摘要为准，修复结果与回执变化一目了然。

## 运行（Docker Compose）

```bash
docker compose up -d web          # 打开 http://localhost:8000
HOST_PORT=9000 docker compose up -d web
```

- 宿主机端口：`${HOST_PORT:-8000}:8000`；
- 持久数据：宿主机 `./data` 挂载到容器 `/data`；
- 内置健康检查，`depends_on: service_healthy` 可供编排使用。

## 一次性 verify 服务

在完成代码测试、前端生产构建与对运行中服务的 HTTP 冒烟后**自行退出，以退出码汇报成败**：

```bash
docker compose build verify
docker compose up --exit-code-from verify verify
# 或一行：
docker compose run --rm verify
```

阶段（任一失败立即非零退出）：

1. `pytest`：后端测试（乱序、幂等、409 不改状态、定位拒绝、缺块范围、
   摘要不符无回执、封存后不可变、跨"重启"持久化、边界尺寸，以及完整性复核的
   HEALTHY/DEGRADED/REPAIRING 分类、旧会话索引补建、错误/重复修复稳定性、
   中断与重启后续修收敛、回执与封存时间不变）；
2. `npm run build`：`tsc` 类型检查 + Vite 构建；
3. `verify/smoke.py`：对 `http://web:8000` 的纯 stdlib HTTP 全链路冒烟
   （含 audit/repair 的门控与稳定结果）。

## 本地开发

```bash
# 后端
cd backend && python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
DATA_DIR=../data uvicorn app.main:app --reload

# 前端（dev server 代理 /api 与 /health 到 :8000）
cd frontend && npm install && npm run dev
```
