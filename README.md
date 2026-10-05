# Damaged ZIP Recovery API

基于 **Python + FastAPI + SQLite + zlib** 的受损 ZIP 恢复 HTTP 服务。
当 ZIP 的中央目录（central directory）缺失或被截断时，服务仅依据
**局部文件头（local file header）、DEFLATE 压缩流边界、带/不带签名的数据描述符
（data descriptor）以及 CRC-32 / 长度交叉校验** 来恢复 `STORED` 与 `DEFLATE` 条目，
并按偏移列出每个成员的名称、大小、SHA-256、归属状态（确定/候选）与损坏区间；
恢复出的原始字节可逐条下载。

## 功能特性

- `POST /recover` 流式接收不超过 **256 MiB** 的 ZIP，边收边写盘，不占内存；
- 中央目录缺失/截断时仍恢复全部可从局部结构校验的条目；
- 支持 bit 3（数据描述符）条目：DEFLATE 以压缩流自终止边界定位，
  STORED 以「签名描述符全扫 + 无签名描述符仅在结构边界前」候选 + CRC 校验定位；
- **损坏段后继续寻找成员**：只有从文件起始头连续可校验的条目标为
  `confirmed`（确定），越过坏段的条目标为 `candidate`（候选）；
- 数据中的伪头（fake `PK\x03\x04`）**不凭签名认定**：候选条目必须通过
  压缩流边界 + CRC-32 + 长度的完整校验才会被接受；
- 同一条目存在**多个可校验切分**时在 `ambiguity` 字段报告歧义，
  校验链自此断开，该条目及后续条目均为候选；
- 同名条目保留序号（`name_seq`：1、2、3…），按全局序号 `n` 下载；
- 累计展开量上限 **1 GiB**（防 zip bomb），超限/加密/ZIP64 **整单拒绝，
  不留任何半成品**（临时目录整体清除，数据库无记录）；
- Docker Compose 一键启动，容器内存限制 **512 MiB**。

## 快速启动

```bash
docker compose up --build
```

服务监听 `http://localhost:8000`。探活：

```bash
curl http://localhost:8000/healthz
# {"status":"ok"}
```

恢复结果（SQLite 元数据 + 条目原始字节）持久化在命名卷 `recovery-data`
（容器内 `/data`）中，重启后仍可通过 `GET /recover/{id}` 访问。

### 配置（环境变量）

| 变量 | 默认值 | 说明 |
|---|---|---|
| `ZIPRECOVER_DATA_DIR` | `/data` | 持久化目录（SQLite + 条目字节） |
| `ZIPRECOVER_MAX_UPLOAD_BYTES` | `268435456` (256 MiB) | 单次上传上限 |
| `ZIPRECOVER_MAX_EXPAND_BYTES` | `1073741824` (1 GiB) | 累计展开量上限 |

## API

### `POST /recover`

请求体为 ZIP 原始字节（`Content-Type: application/zip` 或
`application/octet-stream` 均可），可选查询参数 `filename` 记录原始文件名。
成功返回 `201` 与恢复报告 JSON。

```bash
curl -s -X POST "http://localhost:8000/recover?filename=corrupted.zip" \
     --data-binary @samples/corrupted.zip \
     -H "Content-Type: application/zip"
```

`samples/corrupted.zip`（三个 STORED 条目，中间一个的数据被覆写）的真实响应
（`id`、哈希、时间戳每次运行不同）：

```json
{
  "id": "d54a67da236f429bb4371219a6a66a91",
  "status": "ok",
  "created_at": "2026-10-05T20:50:51.912454+00:00",
  "upload": {
    "filename": "corrupted.zip",
    "size": 202,
    "sha256": "b055aa254e8823e12b49453aad4e138d86c5a67400a75476fd6b4957cc3bf44b"
  },
  "limits": { "max_upload_bytes": 268435456, "max_expand_bytes": 1073741824 },
  "central_directory": {
    "status": "missing",
    "cd_offset": null,
    "cd_entries": 0,
    "eocd_offset": null,
    "eocd_entries": null,
    "notes": [],
    "recovered_entries": 2
  },
  "summary": {
    "total_entries": 2,
    "confirmed": 1,
    "candidate": 1,
    "ambiguous": 0,
    "damaged_ranges": 1,
    "damaged_bytes": 86,
    "recovered_bytes": 46,
    "expanded_bytes": 148
  },
  "entries": [
    {
      "n": 0,
      "name": "a.txt",
      "name_seq": 1,
      "offset": 0,
      "data_offset": 35,
      "end_offset": 55,
      "method": "stored",
      "flags": 0,
      "compressed_size": 20,
      "size": 20,
      "crc32": "a29589d8",
      "sha256": "0eda8137c26e7f4f6028f6a55c6ac9701af75986ff60f64ba75d4b29765bb7bb",
      "status": "confirmed",
      "descriptor": "none",
      "notes": [],
      "download": "/recover/d54a67da236f429bb4371219a6a66a91/entries/0"
    },
    {
      "n": 1,
      "name": "c.txt",
      "name_seq": 1,
      "offset": 141,
      "data_offset": 176,
      "end_offset": 202,
      "method": "stored",
      "flags": 0,
      "compressed_size": 26,
      "size": 26,
      "crc32": "36ab6fee",
      "sha256": "252f37bedfddb5dfcc59d290d591d19729651ba3fa1dcc25a04471056ef58415",
      "status": "candidate",
      "descriptor": "none",
      "notes": [],
      "download": "/recover/d54a67da236f429bb4371219a6a66a91/entries/1"
    }
  ],
  "damaged_ranges": [
    { "offset": 55, "length": 86, "reason": "CRC-32 mismatch with local header" }
  ]
}
```

解读：条目 `a.txt` 从起始头连续可校验 → `confirmed`；`b.txt` 的数据 CRC
校验失败，其字节区间 `[55, 141)` 记入 `damaged_ranges`；扫描在偏移 141 处
重新找到 `c.txt` 并通过完整校验，但因越过了坏段 → `candidate`。

### `GET /recover/{id}`

再次获取报告（持久化，重启不丢）。不存在返回 `404`。

### `GET /recover/{id}/entries/{n}`

下载第 `n` 个条目的**原始字节**（解压后的文件内容）：

```bash
curl -s -D - http://localhost:8000/recover/d54a67da236f429bb4371219a6a66a91/entries/1
```

```http
HTTP/1.1 200 OK
x-entry-name: c.txt
x-entry-name-seq: 1
x-entry-status: candidate
x-entry-sha256: 252f37bedfddb5dfcc59d290d591d19729651ba3fa1dcc25a04471056ef58415
content-type: application/octet-stream
content-disposition: attachment; filename="c.txt"
content-length: 26

gamma: survived the crash
```

### `GET /recover`

列出全部恢复任务（`id`、时间、文件名、大小、SHA-256、汇总计数）。

### 同名条目

`samples/healthy.zip` 含两个同名 `notes.txt`，响应中序号递增、互不下覆盖：

```json
{"n": 0, "name": "notes.txt", "name_seq": 1, "method": "deflate", "size": 14, "status": "confirmed"}
{"n": 1, "name": "notes.txt", "name_seq": 2, "method": "deflate", "size": 15, "status": "confirmed"}
{"n": 2, "name": "logo.raw",  "name_seq": 1, "method": "stored",  "size": 1024, "status": "confirmed"}
```

下载用全局序号：`GET /recover/{id}/entries/1` → `second version\n`。

### 拒绝（整单失败，不留半成品）

| 情形 | 状态码 | 响应体 |
|---|---|---|
| 上传超过 256 MiB | `413` | `{"detail":{"error":"upload_too_large", ...}}` |
| 加密条目（flag bit 0） | `422` | `{"detail":{"error":"encrypted","message":"entry at offset 0 is encrypted (general purpose flag bit 0 set)"}}` |
| ZIP64 结构 | `422` | `{"detail":{"error":"zip64","message":"entry at offset 0 uses ZIP64 structures"}}` |
| 累计展开量超 1 GiB | `422` | `{"detail":{"error":"expand_limit_exceeded", ...}}` |

拒绝后临时目录整体删除，SQLite 无任何记录（`GET /recover` 列表不变）。

```bash
curl -s -X POST http://localhost:8000/recover --data-binary @samples/encrypted.zip
# {"detail":{"error":"encrypted","message":"entry at offset 0 is encrypted (general purpose flag bit 0 set)"}}  (HTTP 422)
```

## 报告字段语义

**条目（entries，按 `offset` 升序）**

| 字段 | 含义 |
|---|---|
| `n` | 全局序号（下载索引用） |
| `name` / `name_seq` | 条目名 / 同名序号（1 起） |
| `offset` / `data_offset` / `end_offset` | 局部头偏移 / 数据偏移 / 条目结束偏移（含描述符） |
| `method` | `stored` / `deflate` |
| `compressed_size` / `size` | 压缩后 / 原始大小（校验后的实际值） |
| `crc32` / `sha256` | 校验值（SHA-256 针对原始字节） |
| `status` | `confirmed`：从起始头连续可校验；`candidate`：越过坏段或存在歧义 |
| `descriptor` | `none` / `signature` / `nosignature` / `missing`（数据描述符形态） |
| `ambiguity` | 可选；多个可校验切分时列出全部 `{end_offset, descriptor}` |
| `notes` | 可选；如「局部头压缩大小与流边界不一致」等 |

**损坏区间（damaged_ranges）**：`{offset, length, reason}`，跳过不可校验
字节后扫描继续。

**central_directory**：`present` / `truncated` / `missing`，附 EOCD 信息；
仅用于报告，恢复不依赖它。

## 恢复算法要点

1. 从偏移 0 起走查：期望位置出现 `PK\x03\x04` 时解析局部头并**完整校验**
   一个条目；出现 `PK\x01\x02`/`PK\x05\x06` 转入中央目录报告；其余字节
   记为损坏段并向后扫描下一个**能通过完整校验**的局部头。
2. DEFLATE：以原始 deflate 流自终止边界确定压缩长度，再与局部头或
   数据描述符（先验签名 `PK\x07\x08`，再验无签名 12 字节）交叉校验
   CRC-32 与长度。
3. STORED + bit 3 且长度未知：收集全部候选切分（签名描述符任意位置；
   无签名描述符仅在下一结构边界或 EOF 前 12 字节），用一次增量 CRC 扫描
   线性校验全部候选。
4. 多个候选均通过校验 → 记录 `ambiguity`，走查选择「结束处能接续有效
   结构」的最小切分，校验链自此断开（后续条目均为候选）。
5. 加密（flag bit 0）、ZIP64（`0xFFFFFFFF` 哨兵、ZIP64 扩展字段、
   ZIP64 EOCD 结构）在走查的期望位置出现时整单拒绝；展开量超限同理。
   以上检查只在「期望位置」生效——坏段扫描中遇到的疑似伪头只会被跳过，
   不会误伤正常恢复。

## 内存设计（512 MiB 限制）

- 上传流式写临时文件（1 MiB 块），全程不驻留内存；
- 分析通过 `mmap` 只读映射（页面可回收），解压/哈希/落盘全部流式；
- 展开字节流式写入条目文件并计入 1 GiB 预算；
- 实测：256 MiB 输入、461 MiB 展开，恢复约 1.2 s，峰值 RSS ≈ 295 MiB
  （其中大部分为可回收的文件映射页）。

## 本地开发与测试

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pytest tests/                 # 19 个端到端测试
python3 scripts/make_samples.py samples/   # 重新生成示例 ZIP
ZIPRECOVER_DATA_DIR=./data uvicorn app.main:app --reload --port 8000
```

## 项目结构

```
app/
  main.py      FastAPI 路由、限额、错误映射
  recover.py   恢复引擎（局部头/流边界/数据描述符/CRC 驱动）
  store.py     SQLite 元数据 + 条目字节持久化
scripts/make_samples.py   生成 README 使用的示例 ZIP
samples/                  示例输入（healthy/no-central/corrupted/descriptors/encrypted/zip64）
tests/test_api.py         端到端测试（手工构造各类受损场景）
Dockerfile / docker-compose.yml
```
