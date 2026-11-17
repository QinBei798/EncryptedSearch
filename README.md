# EncryptedSearch (国密加密全文搜索引擎原型)

**EncryptedSearch** 是一个基于 C++17 实现的加密全文搜索引擎原型工程，核心设计为**“密文安全归档 + 带密钥盲索引检索”**：原始文档通过国密 `SM4-CBC` 流式加密存储，关键词倒排索引通过 `HMAC-SM3` 盲索引陷门保护，搜索及布尔逻辑过滤过程**无需解密原文件**，命中后可按文档 ID 按需解密还原。

---

## 核心特性

### 1. 密码学与数据安全
- **PBKDF2-SM3-HMAC 主密钥派生与域分离**：从用户主密码与随机 16 字节 Salt 派生 32 字节主密钥材料后，通过域分离标签派生三套独立秘密：
  - `16B` **SM4 文件加解密密钥**；
  - `32B` **HMAC-SM3 盲索引陷门密钥**；
  - `16B` **主密码校验指纹 (`keyVerifier`)**（写入索引头，用于冷启动加载时常量时间校验密码正误）。
- **64KB 流式 SM4-CBC 加密与随机 IV**：基于内嵌 GmSSL `SM4_CBC_CTX` 分块流式加解密，每次加密生成随机 16 字节 IV 写入文件头（`[ 16B IV | 密文 ]`），处理大文件仅占用常数级缓冲内存。
- **HMAC-SM3 密钥盲索引**：建库与检索统一使用带密钥陷门 `HMAC-SM3(indexKey, lower(keyword))`，抵御对索引文件的离线字典碰撞攻击；索引头版本升级至 `v3` 并拒绝加载旧版无密钥 `v2` 索引。

### 2. 流式分词、索引格式与真实监控
- **64KB 真·流式分词与两级边界回退**：`ParallelHasher` 采用生产者-消费者线程池，按 `64KB` 分块读取文件；在末尾 `4KB` 回溯窗口内优先寻找空白符或中英文句读分隔符（找不到时兜底回退至 UTF-8 多字节字符边界），避免跨块截断完整词或破坏 UTF-8 编码。每块切词后立即哈希累加并释放临时向量，防止大文件分词阶段内存膨胀。
- **ESIX v3 二进制索引布局**：
  ```text
  [ IndexHeader (64 Bytes) ]
    ├─ Magic ("ESIX" 0x58495345) | Version (3)
    ├─ KeywordCount (8B) | DocCount (8B)
    └─ PBKDF2 Salt (16B) | Iterations (4B) | KeyVerifier (16B) | Reserved (4B)

  [ Dictionary (词典区，启动时全量加载至内存) ]
    └─ 定长 40B/条：HMAC-SM3 Trapdoor (32B) | PostingOffset (8B)，支持 O(log N) 二分查找

  [ Posting Lists (倒排列表区，驻留磁盘按偏移量懒加载) ]
    └─ DocCount (4B) | [DocId (4B), TF (float 4B)] * N（按 DocId 升序排列）
  ```
- **真实系统与扫描监控**：`SystemMonitor` 跨平台采集真实 CPU 型号、编译器信息及进程物理内存峰值（Linux 读取 `/proc/self/status` 的 `VmHWM` / `VmRSS` 并以 `getrusage` 兜底，Windows 使用 `GetProcessMemoryInfo`）；`IndexManager` 统计真实文件数、总字节数与加密失败数。

### 3. 检索、排序与冷启动闭环
- **中英混合分词与 TF-IDF 排序**：集成 `cppjieba` 的 `CutForSearch` 模式，按 $\text{TF} \times \left(\ln\frac{N}{\text{df}+1} + 1\right)$ 计算相关性得分并降序返回。
- **布尔逻辑搜索**：内置递归下降解析器与 AST（优先级 `NOT > AND > OR`），支持 `AND`、`OR`、`AND NOT` 组合查询及双指针 $O(N+M)$ 集合归并。
- **冷启动检索与密文还原**：支持 `--search-only [工作目录]` 脱离原始明文目录独立加载索引并校验主密码；交互模式支持 `decrypt <文档路径> <输出路径>` 定位密文并流式解密还原。

---

## 目录结构

```text
EncryptedSearch/
├── CMakeLists.txt             # 构建与 CTest 测试配置
├── generate_corpus.py         # 可复现的 Zipf 长尾分布基准语料与真值清单生成器
├── include/
│   ├── core/                  # CryptoEngine、SystemMonitor 接口
│   ├── gmssl/                 # 内嵌 GmSSL SM3/SM4 头文件
│   ├── index/                 # IndexStructs (ESIX v3)、Indexer、ParallelHasher
│   └── search/                # QueryParser、Searcher
├── src/
│   ├── core/                  # 国密 C 实现 (sm3/sm4) 及 CryptoEngine、SystemMonitor
│   ├── index/                 # 扫描建库与并行流式分词实现
│   ├── search/                # 布尔语法解析与磁盘倒排检索实现
│   └── main.cpp               # CLI 入口（建库检索模式 / --search-only 冷启动模式）
├── tests/                     # 11 个 CTest 单元、端到端完整性、正确性与稳定性测试套件
└── third_party/
    └── cppjieba/              # 中文分词依赖（含 deps/limonp 与 dict 词典）
```

---

## 编译与测试

### 前置依赖
- **CMake**（>= 3.15）
- **C++17 编译器**（GCC 8+ / Clang / MSVC 2019+）
- **Python 3**（用于 `generate_corpus.py` 及部分 CLI 集成测试）
- *说明：国密 SM3/SM4 核心源码已直接内嵌在 `src/core/` 与 `include/gmssl/` 中，无需额外安装系统级 GmSSL；若克隆仓库后 `third_party/cppjieba` 为空，请确保拉取 `cppjieba` 及其 `deps/limonp` 子模块。*

### 构建与运行全部测试
```bash
# 1. 配置与编译（编译时会自动拷贝 cppjieba 词典到构建目录）
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j

# 2. 运行全部 11 个 CTest 测试套件
ctest --test-dir build --output-on-failure
```

---

## 使用方式

### 1. 生成基准测试语料（附带真值 `manifest.json`）
```bash
# 示例：生成 100MB 混合分布语料（含 20,000 词表、边界文件与外部真值清单 test_docs.manifest.json）
python3 generate_corpus.py --total-mb 100 --out-dir test_docs --clean

# 若需额外包含 1 个 100MB 单体流式大文件：
python3 generate_corpus.py --total-mb 200 --large-file-mb 100 --out-dir test_docs --clean
```

### 2. 扫描加密、建库并检索
```bash
# 可传入自定义语料目录；不传参时默认查找 test_docs_5gb 或 test_docs
./build/EncryptedSearch ./test_docs
```
按提示输入主密码后，程序将完成 SM4 流式加密归档（保存至同级 `cipher_docs/`）、v3 盲索引构建（`encrypted_search_index.bin` 与 `file_map.dat`），输出真实耗时/吞吐率/内存峰值（`VmHWM`），并进入交互式布尔检索模式：
- 输入布尔表达式查询（例如 `SM3 AND SM4`、`国密 AND NOT 分词`）；
- 输入 `decrypt <原始文档路径> <输出路径>` 解密对应密文文件；
- 输入 `exit` 退出。

### 3. 冷启动检索与密文解密（不依赖原始明文目录）
```bash
./build/EncryptedSearch --search-only .
```
程序加载磁盘索引后依据索引头 `salt` 与 `iterations` 验证主密码，通过后即可直接执行布尔检索与密文还原。

---

## 实测基准与当前已知限制

### 实测基准（200MB 混合语料，含 100MB 单文件）
在 Linux（16 硬件线程 Intel Core i5-13500H / GCC 11.4.0 Release）环境下使用 `generate_corpus.py --total-mb 200 --large-file-mb 100 --vocab-size 20000`（共 `1,647` 份文档、`200.00 MB`）：
- **扫描与 64KB 流式 SM4-CBC 加密耗时**：`1.69 s`
- **并行分词与 v3 索引落盘耗时**：`17.55 s`（生成索引体积 `12.87 MB`）
- **端到端建库总耗时 / 吞吐率**：`19.24 s` / `10.40 MB/s`
- **进程物理内存峰值（`VmHWM`）**：`225.87 MB`（含约 `135 MB` Jieba 静态词典）
- **正确性与完整性**：全部真值布尔/跨 64KB 边界查询实现 100% 精确率与召回率；冷启动解密 100MB 单文件、跨界文件与 0B 空文件后 SHA-256 与原文件逐字节一致。

### 当前已知限制
1. **单线程同步加密归档**：`IndexManager::ScanDirectory()` 目前在主线程同步执行 `EncryptFileSM4`，尚未移入线程池并发。
2. **分词全局锁串行**：`ParallelHasher` 共用全局 `cppjieba` 实例并持 `s_jiebaMutex` 锁调用 `CutForSearch`，是大语料建库的主要耗时瓶颈。
3. **单线程检索句柄**：`Searcher` 共享单个 `std::ifstream` 执行 `seekg + read`，多线程并发检索非线程安全（需改造为 `mmap` 或 `pread`）。
4. **语法与格式边界**：`QueryParser` 暂不支持括号分组 `(...)` 以及独立 `NOT A`、`A OR NOT B`；当前仅支持全量建库，不支持增量增删文档；SM4-CBC 密文暂未附带独立完整性认证标签（HMAC/GCM），`file_map.dat` 仍以明文保存文件路径映射。

---

## 开源协议

本项目基于 MIT License 开源。当前定位为学习与工程验证原型，若用于高敏数据生产环境，请结合上述已知限制补齐密文完整性认证、索引映射加密与并发检索重构后再做专业密码学审计。
