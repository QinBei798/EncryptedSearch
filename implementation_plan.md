# EncryptedSearch 优化实现计划

## 背景

基于项目分析，按**从易到难**的顺序对 EncryptedSearch 进行 6 个阶段的优化。

## 优化路线总览

| 阶段 | 类型 | 难度 | 预计改动范围 |
|------|------|------|-------------|
| Phase 1 | 安全：随机 IV | 🟢 易 | 仅改 `CryptoEngine.cpp` |
| Phase 2 | 性能：任务批量化 | 🟢 易-中 | `ParallelHasher` + `Indexer` |
| Phase 3 | 健壮：流式分词 | 🟡 中 | `Indexer.cpp` 的分词器 |
| Phase 4 | 安全：PBKDF2 密钥派生 | 🟡 中 | `CryptoEngine` + `main.cpp` |
| Phase 5 | 功能：TF-IDF 排序 | 🔴 难 | 索引格式+`Indexer`+`Searcher` |
| Phase 6 | 功能：布尔搜索 | 🔴 难 | `Searcher` 查询引擎重构 |

---

## Phase 1 — 随机 IV（安全，易）

### 问题
`DEFAULT_SM4_IV[16] = {0}` 全零固定 IV，相同明文每次产生相同密文，暴露明文模式。

### 方案
每次加密时用 `std::random_device` 生成随机 16 字节 IV，并将其**前缀写入密文文件**（IV 不需要保密）：

```
密文文件格式：[ IV (16B) | SM4-CBC 密文 (N B) ]
```

解密时先读取前 16 字节作为 IV，再解密后续内容。

### 涉及文件

#### [MODIFY] [CryptoEngine.cpp](file:///d:/VisualStudio_Coding/EncryptedSearch/src/core/CryptoEngine.cpp)
- 移除 `DEFAULT_SM4_IV` 全局常量
- `EncryptFileSM4`：生成随机 IV → 写入文件头部 → 加密后续内容
- `DecryptFileSM4`：先读取 16B IV → 再解密

#### [MODIFY] [CryptoEngine.hpp](file:///d:/VisualStudio_Coding/EncryptedSearch/include/core/CryptoEngine.hpp)
- 无需修改接口，兼容现有调用

---

## Phase 2 — 任务批量化（性能，易-中）

### 问题
`ScanDirectory` 每切出一个词就调用一次 `AddTask`，大文档产生数万次锁竞争。

### 方案
将任务粒度从"关键词"改为"文件"：

```
旧：AddTask(keyword, docId)  × 数万次（每词一次加锁）
新：AddTask(filePath, docId) × 文件数量（Worker 内部分词+哈希）
```

### 涉及文件

#### [MODIFY] [ParallelHasher.hpp](file:///d:/VisualStudio_Coding/EncryptedSearch/include/index/ParallelHasher.hpp)
- 任务类型从 `pair<string, uint32_t>` (keyword+id) 改为 `pair<string, uint32_t>` (filePath+id)
- Worker 函数内部执行分词 + 循环哈希

#### [MODIFY] [ParallelHasher.cpp](file:///d:/VisualStudio_Coding/EncryptedSearch/src/index/ParallelHasher.cpp)
- Worker 内读取文件、分词、计算哈希，所有关键词哈希后批量写入 `m_finalIndex`，只加一次 `m_indexMutex` 锁

#### [MODIFY] [Indexer.cpp](file:///d:/VisualStudio_Coding/EncryptedSearch/src/index/Indexer.cpp)
- `ScanDirectory` 中改为 `m_hasher.AddTask(path, docId)` 一次提交整个文件

> [!NOTE]
> cppjieba 的 `Jieba` 对象需要在 Worker 线程中懒加载（thread_local 或 Worker 构造时初始化），因为 Jieba 不是线程安全的。

---

## Phase 3 — 流式分词（健壮性，中）

### 问题
`tokenizeFileContent` 一次性把整个文件读入 `std::string`，遇 GB 级文件崩溃。

### 方案
分块读取文件（64KB/块），维护一个"跨块缓冲区"处理多字节字符被截断的边界情况：

```
[块1][块2][块3]...
      ↑ 块边界处保留最后一个不完整的 UTF-8 字符，拼到下一块开头
```

### 涉及文件

#### [MODIFY] [Indexer.cpp](file:///d:/VisualStudio_Coding/EncryptedSearch/src/index/Indexer.cpp)
- 重写 `tokenizeFileContent`，改为 64KB 分块读取
- 实现 UTF-8 边界检测函数，确保块边界不截断多字节字符
- cppjieba 支持对字符串分词，每块单独调用 `CutForSearch` 后合并结果

---

## Phase 4 — PBKDF2 密钥派生（安全加固，中）

### 问题
SM4 密钥硬编码在源码中，任何人反编译即可获取密钥。

### 方案
实现基于 SM3-HMAC 的 PBKDF2，由用户输入的密码+随机盐动态生成 SM4 密钥：

```
password + salt(16B) + iterations → PBKDF2-SM3-HMAC → SM4 key(16B)
```

盐和迭代次数明文保存在索引文件头部（不影响安全性）。

### 涉及文件

#### [MODIFY] [CryptoEngine.hpp](file:///d:/VisualStudio_Coding/EncryptedSearch/include/core/CryptoEngine.hpp)
- 新增 `DeriveKeySM3PBKDF2(password, salt, iterations)` 静态函数

#### [MODIFY] [CryptoEngine.cpp](file:///d:/VisualStudio_Coding/EncryptedSearch/src/core/CryptoEngine.cpp)
- 实现 PBKDF2（基于 gmssl 已有的 sm3_hmac）

#### [MODIFY] [IndexHeader] in `Indexer.hpp`
- 在 `IndexHeader` 的 `reserved[24]` 字段中存储 salt(16B) + iterations(4B)

#### [MODIFY] [main.cpp](file:///d:/VisualStudio_Coding/EncryptedSearch/src/main.cpp)
- 提示用户输入密码，派生密钥后传入 `CryptoEngine`

---

## Phase 5 — TF-IDF 排序（功能扩展，难）

### 问题
搜索结果仅支持"存在/不存在"，无法按相关性排序。

### 方案
在索引文件中每个 Posting List 条目存储 TF 值，搜索时结合文档总数计算 TF-IDF 分数：

```
TF(t,d)  = 词 t 在文档 d 中出现次数 / 文档 d 的总词数
IDF(t)   = log(总文档数 / 包含词 t 的文档数 + 1)
Score    = TF × IDF
```

### 索引格式变更
```
旧 Posting List: [ count(4B) | docId(4B) × N ]
新 Posting List: [ count(4B) | { docId(4B), tf(float,4B) } × N ]
```

### 涉及文件

#### [MODIFY] [Indexer.hpp](file:///d:/VisualStudio_Coding/EncryptedSearch/include/index/Indexer.hpp)
- `IndexHeader` 的 `version` 升至 `2`
- Posting List 格式升级

#### [MODIFY] [Indexer.cpp](file:///d:/VisualStudio_Coding/EncryptedSearch/src/index/Indexer.cpp)
- 记录每个 `(keyword, docId)` 对的出现次数（TF 词频）
- 写入索引时将 TF 值随 docId 一起写入

#### [MODIFY] [Searcher.hpp](file:///d:/VisualStudio_Coding/EncryptedSearch/include/search/Searcher.hpp)
- `Search()` 返回排序后的 `vector<pair<string, float>>`（路径+分数）

#### [MODIFY] [Searcher.cpp](file:///d:/VisualStudio_Coding/EncryptedSearch/src/search/Searcher.cpp)
- 读取 TF 值，计算 IDF（从 IndexHeader.docCount），排序后返回

---

## Phase 6 — 布尔搜索（功能扩展，难）

### 问题
不支持多关键词 AND / OR / NOT 逻辑组合。

### 方案
实现倒排列表的集合运算：

```
AND → 对已排序的 docId 列表做交集（双指针，O(N+M)）
OR  → 合并两个列表（归并排序思路）
NOT → 全集差集
```

支持查询语法示例：`"国密 AND SM4"`, `"加密 OR 分词"`

### 涉及文件

#### [NEW] [QueryParser.hpp/cpp](file:///d:/VisualStudio_Coding/EncryptedSearch/include/search/)
- 解析用户查询字符串，生成查询树（AST）
- 仅支持二元 AND / OR / NOT，无需完整语法树

#### [MODIFY] [Searcher.hpp](file:///d:/VisualStudio_Coding/EncryptedSearch/include/search/Searcher.hpp)
- 新增 `BooleanSearch(const string& query)` 接口

#### [MODIFY] [Searcher.cpp](file:///d:/VisualStudio_Coding/EncryptedSearch/src/search/Searcher.cpp)
- 实现 `GetPostingList(keyword)` 内部辅助函数
- 实现 AND/OR 集合运算

---

## 验证计划

每个 Phase 完成后：
1. **编译验证**：`cmake --build build` 无错误
2. **运行测试**：`main.cpp` 中的集成测试，对比优化前后输出
3. **安全验证（Phase 1）**：验证同一文件两次加密的密文不同（随机 IV 生效）
4. **性能验证（Phase 2）**：计时对比单次扫描耗时
5. **大文件测试（Phase 3）**：构造 100MB 测试文件验证不崩溃
