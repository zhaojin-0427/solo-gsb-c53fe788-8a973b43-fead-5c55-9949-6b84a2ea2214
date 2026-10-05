# 受损 ZIP 恢复服务（damaged-zip-recovery）

基于 **Python + FastAPI + SQLite + zlib** 的 HTTP API：接收（可能受损的）ZIP
归档，在中央目录缺失、被截断或损坏时，依据**局部文件头、deflate 压缩流边界、
带/不带签名的数据描述符（data descriptor）以及 CRC-32/长度校验**恢复其中的
STORED 与 DEFLATE 条目，并按偏移报告每个成员的名称、大小、SHA-256、归属状态
与损坏区间；可逐条下载恢复出的原始字节。

## 功能特性

- `POST /recover` 流式接收不超过 **256 MiB** 的 ZIP 归档（边收边写临时文件，
  不把整个请求体读进内存）。
- 中央目录缺失/截断时仍能恢复 `STORED`（方法 0）与 `DEFLATE`（方法 8）条目：
  - 头部自带长度：直接按 `compressed_size` 截取并校验 CRC-32 与长度；
  - 流式写出（bit 3）：DEFLATE 以 zlib 流边界（`unused_data`）定位数据末尾，
    STORED 通过扫描数据描述符定位；**带签名 `PK\x07\x08`（16 字节）与不带签名
    （12 字节）两种描述符都支持**，并以描述符中的 CRC-32/长度与实算值交叉校验。
- **归属状态**：只有从偏移 0 起始、逐条连续可校验的条目标为 `certain`（确定）；
  越过损坏段后恢复出的条目标为 `candidate`（候选）。
- **损坏段后继续寻找成员**：扫描下一个 `PK\x03\x04` 时，候选头必须通过完整的
  CRC-32/长度校验才会被采纳——数据中的伪头不能仅凭签名认定。
- **歧义报告**：当存在多个可校验的切分（例如 STORED 数据内嵌可校验的伪描述符、
  描述符 12/16 字节两种解释同时成立、坏段后存在多个可校验的续接点）时，在
  `ambiguities` 中列出全部备选并说明所采用的切分。
- **同名条目保留序号**：`name_seq` 为同名条目出现的序号（0 起）。
- **累计展开量上限 1 GiB**（防 zip 炸弹）；上传超限、展开超限、加密条目、
  ZIP64 一律**整单拒绝**（HTTP 413/422），不写入任何半成品（临时文件与已写出
  的条目数据全部清理，数据库不留记录）。
- 恢复出的条目字节落盘保存、元数据入 SQLite，`GET /recover/{id}/entries/{n}`
  流式下载原始字节；报告持久化，可用 `GET /recover/{id}` 再次获取。
- 全程流式/分块处理（上传写盘 → mmap 解析 → 4 MiB 块解压 → 条目写盘 →
  流式下载），实测处理 158 MiB 归档（展开 750 MiB）峰值 RSS 约 220 MiB，
  可在 **512 MiB** 内存限制下运行。

## 快速开始（Docker Compose 一键启动）

```bash
docker compose up --build
```

启动后：

- 服务地址： http://localhost:8000
- 交互式接口文档（Swagger UI）： http://localhost:8000/docs
- 数据（SQLite 库与恢复出的条目）保存在名为 `recover-data` 的卷中。

`docker-compose.yml` 已为服务设置 `mem_limit: 512m`，并通过环境变量固定
256 MiB 上传上限与 1 GiB 展开上限。

### 本地开发（不用 Docker）

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
pytest                      # 运行测试
uvicorn app.main:app --reload --port 8000
```

## API 说明

### `POST /recover`

流式上传 ZIP 归档。请求体为原始字节（`Content-Type: application/zip` 或
`application/octet-stream` 均可），文件名可用查询参数 `filename` 或请求头
`X-Filename` 指定（缺省 `upload.zip`）。

```bash
curl -s -X POST "http://localhost:8000/recover?filename=example_damaged.zip" \
     -H "Content-Type: application/zip" \
     --data-binary @example_damaged.zip | jq
```

响应 `200 OK`（示例为真实输出：归档含 2 个完好条目、一段垃圾数据、以及垃圾
之后的 1 个条目；`id` 每次上传随机生成）：

```json
{
  "entries": [
    {
      "index": 0,
      "name": "readme.txt",
      "name_seq": 0,
      "offset": 0,
      "end_offset": 63,
      "header_size": 40,
      "data_offset": 40,
      "method": "stored",
      "compressed_size": 23,
      "uncompressed_size": 23,
      "crc32": "ddf1cc11",
      "sha256": "f9161b54cc9870d30e27aa2211dcd74496f6973d1f460bb6b4a5d4169136596d",
      "descriptor": null,
      "status": "certain",
      "download": "/recover/85fe51a91449487387e94663fbfefc15/entries/0"
    },
    {
      "index": 1,
      "name": "logo.bin",
      "name_seq": 0,
      "offset": 63,
      "end_offset": 167,
      "header_size": 38,
      "data_offset": 101,
      "method": "deflate",
      "compressed_size": 66,
      "uncompressed_size": 64,
      "crc32": "100ece8c",
      "sha256": "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108",
      "descriptor": null,
      "status": "certain",
      "download": "/recover/85fe51a91449487387e94663fbfefc15/entries/1"
    },
    {
      "index": 2,
      "name": "notes.md",
      "name_seq": 0,
      "offset": 178,
      "end_offset": 241,
      "header_size": 38,
      "data_offset": 216,
      "method": "stored",
      "compressed_size": 25,
      "uncompressed_size": 25,
      "crc32": "8ac2a013",
      "sha256": "31de5283eeb718213cbb2f5181691ef7b29198ecd8431e8e05d4d7b122640856",
      "descriptor": null,
      "status": "candidate",
      "download": "/recover/85fe51a91449487387e94663fbfefc15/entries/2"
    }
  ],
  "damaged_regions": [
    { "offset": 167, "length": 11, "reason": "unrecognized data" }
  ],
  "ambiguities": [],
  "central_directory": {
    "found": false,
    "offset": null,
    "entries": null,
    "consistent": false,
    "notes": []
  },
  "eocd_found": false,
  "truncated": true,
  "entry_count": 3,
  "certain_count": 2,
  "candidate_count": 1,
  "expanded_bytes": 112,
  "id": "85fe51a91449487387e94663fbfefc15",
  "filename": "example_damaged.zip",
  "size": 241,
  "sha256": "372439f3db8795a5e69cfbda5e6573f64eec791877a7c7b8606ccf2c659d8cef",
  "created_at": "2026-10-05T22:10:17.514145+00:00",
  "limits": { "max_upload_bytes": 268435456, "max_expanded_bytes": 1073741824 }
}
```

字段说明：

| 字段 | 含义 |
| --- | --- |
| `entries[].offset` / `end_offset` | 条目（局部头起始）在归档中的字节区间，按偏移升序列出 |
| `entries[].name_seq` | 同名条目序号（0 起） |
| `entries[].sha256` | 恢复出的**原始字节**的 SHA-256 |
| `entries[].status` | `certain`：从起始头连续可校验；`candidate`：越过坏段恢复 |
| `entries[].descriptor` | 数据描述符形式：`signature`（带 `PK\x07\x08`）、`plain`（不带签名）、`null`（未使用描述符） |
| `entries[].download` | 该条目原始字节的下载路径 |
| `damaged_regions[]` | 无法解析的损坏区间（`offset`+`length`+`reason`） |
| `ambiguities[]` | 多个可校验切分时的歧义记录（`kind` 为 `stored_descriptor` / `data_descriptor` / `resume_point`，含 `chosen` 与 `alternatives`） |
| `central_directory` | 中央目录/EOCD 是否存在、是否与局部头恢复结果一致 |
| `expanded_bytes` | 本次恢复累计展开的字节数（上限 1 GiB） |

### `GET /recover/{id}`

返回与 `POST /recover` 相同的报告 JSON（报告已持久化到 SQLite）。
归档不存在时返回 `404 {"detail": "archive not found"}`。

### `GET /recover/{id}/entries/{n}`

下载第 `n` 个条目（`n` 即报告中的 `index`）的**原始字节**（STORED 原样、
DEFLATE 解压后），流式响应：

```bash
curl -sOJ "http://localhost:8000/recover/85fe51a91449487387e94663fbfefc15/entries/0"
```

```text
HTTP/1.1 200 OK
content-type: application/octet-stream
content-disposition: attachment; filename="readme.txt"
content-length: 23
x-entry-name-seq: 0
x-entry-sha256: f9161b54cc9870d30e27aa2211dcd74496f6973d1f460bb6b4a5d4169136596d

Hello, recovery world!
```

条目不存在时返回 `404 {"detail": "entry not found"}`。

### 错误响应（整单拒绝，不留半成品）

| 状态码 | 触发条件 | 响应体示例 |
| --- | --- | --- |
| `413` | 上传超过 256 MiB | `{"detail": "upload exceeds the limit of 268435456 bytes"}` |
| `413` | 累计展开量超过 1 GiB（zip 炸弹） | `{"detail": "cumulative decompressed size exceeds the limit of 1073741824 bytes"}` |
| `422` | 含加密条目（flags bit0/6/13） | `{"detail": "encrypted entries are not supported"}` |
| `422` | ZIP64 归档（0xFFFFFFFF/0xFFFF 哨兵值、ZIP64 扩展字段、EOCD64 定位器） | `{"detail": "ZIP64 archives are not supported"}` |

拒绝时：临时上传文件与已写出的条目数据全部删除，数据库不写入任何记录。

```bash
$ curl -s -X POST http://localhost:8000/recover --data-binary @encrypted.zip
{"detail":"encrypted entries are not supported"}   # HTTP 422
```

## 恢复语义与实现要点

- **确定（certain）**：从偏移 0 开始，每个条目紧接前一条目末尾，且头部、
  CRC-32、压缩/原始长度全部校验通过；链条一旦断裂，其后所有条目均为候选。
- **候选（candidate）**：在损坏段之后通过"扫描签名 + 完整校验"找到的条目。
  仅凭 `PK\x03\x04` 签名不会被采纳（数据中的伪头会被 CRC/长度校验筛掉）；
  若同一坏段后存在多个可校验的续接点，取第一个并在 `ambiguities` 中报告其余。
- **数据描述符**：DEFLATE 条目以 zlib 流结束位置定位描述符；STORED 条目通过
  扫描 `PK\x07\x08` 及"下一结构前 12 字节"的候选位置，用单次增量 CRC-32 扫描
  校验 `(crc, csize, usize)` 三元组定位。多个位置同时可校验时取最早者并报告歧义。
- **中央目录**：若扫描到达 `PK\x01\x02`/`PK\x05\x06`，会解析并与局部头恢复结果
  交叉核对（`central_directory.consistent`）；中央目录本身的截断/损坏会计入
  `damaged_regions`。
- **启发式限制**：坏段中若出现带加密标志且"结构上可信"的头部（方法已知、文件名
  可打印等）会按加密整单拒绝；不可信的视为伪头跳过。不支持的压缩方法（非 0/8）
  所在的条目记为损坏区间后继续恢复。

## 配置（环境变量）

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `DATA_DIR` | `data`（容器内 `/data`） | SQLite 库、临时上传、条目数据的存放目录 |
| `MAX_UPLOAD_BYTES` | `268435456`（256 MiB） | 上传大小上限，超限返回 413 |
| `MAX_EXPANDED_BYTES` | `1073741824`（1 GiB） | 单归档累计展开量上限，超限返回 413 |

## 内存说明（512 MiB 限制）

上传流式写临时文件（不进入内存）；解析通过 `mmap` 只读映射，zlib 解压以
4 MiB 为粒度分块（`decompress(max_length)`），恢复出的条目直接写盘、SHA-256
增量计算；下载使用流式文件响应。常驻内存与归档大小基本无关，单 worker 即可
满足 512 MiB 限制（compose 已配置 `mem_limit: 512m`）。

## 项目结构

```text
app/
  main.py       # FastAPI 路由：上传流式接收、报告查询、条目下载
  recovery.py   # 核心恢复逻辑（局部头/描述符/流边界/CRC 校验、歧义报告）
  db.py         # SQLite 持久化（报告与条目元数据）
  config.py     # 环境变量配置
tests/
  test_recovery.py   # 18 个用例：完好/截断/中段损坏/伪头/歧义/同名/加密/ZIP64/超限
Dockerfile
docker-compose.yml
```
