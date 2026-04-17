#include <index/ParallelHasher.hpp>
#include <cppjieba/Jieba.hpp>
#include <iostream>
#include <fstream>
#include <algorithm>

// ===========================================================
// Jieba 字典路径（相对于程序工作目录，与 CMakeLists.txt 拷贝目标一致）
// ===========================================================
static const char* DICT_PATH      = "third_party/cppjieba/dict/jieba.dict.utf8";
static const char* HMM_PATH       = "third_party/cppjieba/dict/hmm_model.utf8";
static const char* USER_DICT_PATH = "third_party/cppjieba/dict/user.dict.utf8";
static const char* IDF_PATH       = "third_party/cppjieba/dict/idf.utf8";
static const char* STOP_WORD_PATH = "third_party/cppjieba/dict/stop_words.utf8";

// ===========================================================
// Phase 2: 全局共享 Jieba 单例 + 保护锁
//
// 设计选择：使用共享单例（而非 thread_local 每线程独立实例）
//   - 优点：节省内存（字典展开后约 50~100MB，16线程下 thread_local 会占用 ~1.6GB）
//   - 代价：CutForSearch 调用被序列化（但 I/O 读文件 和 SM3 哈希 仍完全并行）
//   - 适用场景：本项目瓶颈在 I/O 和哈希计算，分词串行化影响可忽略
// ===========================================================
static std::mutex                       s_jiebaMutex;
static std::unique_ptr<cppjieba::Jieba> s_jieba;

// ===========================================================
// Phase 3: UTF-8 安全分割点辅助函数
//
// 在 data[0..size] 中找到最后一个完整 UTF-8 字符结束后的字节偏移，
// 保证在该位置切分时绝不会把多字节字符（如3字节汉字）截断。
//
// UTF-8 编码规则：
//   0x00~0x7F : ASCII 单字节首字节
//   0xC0~0xDF : 2字节字符首字节
//   0xE0~0xEF : 3字节字符首字节（大多数 CJK 汉字）
//   0xF0~0xF7 : 4字节字符首字节
//   0x80~0xBF : 延续字节（非首字节）
//
// 算法：从末尾向前找第一个非延续字节（首字节），
//       判断该字符是否在 buffer 内完整；不完整则在其之前分割。
// ===========================================================
static size_t safeUtf8SplitPoint(const char* data, size_t size) {
    if (size == 0) return 0;
    // 最多向前扫 3 字节（UTF-8 最长 4 字节，末尾最多 3 个延续字节）
    for (size_t i = 0; i < 4 && i < size; ++i) {
        unsigned char c = static_cast<unsigned char>(data[size - 1 - i]);
        if ((c & 0xC0) != 0x80) {          // 找到首字节
            size_t leadPos = size - 1 - i;
            size_t charLen;
            if      (c < 0x80) charLen = 1; // ASCII
            else if (c < 0xE0) charLen = 2; // U+0080~U+07FF
            else if (c < 0xF0) charLen = 3; // U+0800~U+FFFF（含大多数汉字）
            else               charLen = 4; // U+10000~U+10FFFF

            if (leadPos + charLen <= size) {
                return size;     // 该字符完整，整个 buffer 均安全
            } else {
                return leadPos;  // 该字符不完整，在其首字节之前分割
            }
        }
    }
    return size; // fallback（有效 UTF-8 不会走到这里）
}

// ===========================================================
// 构造 / 析构
// ===========================================================
ParallelHasher::ParallelHasher(size_t threadCount) {
    for (size_t i = 0; i < threadCount; ++i) {
        m_workers.emplace_back(&ParallelHasher::worker, this);
    }
}

ParallelHasher::~ParallelHasher() {
    {
        std::unique_lock<std::mutex> lock(m_queueMutex);
        m_stop = true;
    }
    m_cv.notify_all(); // 唤醒所有线程，让其检测 m_stop 后退出
    for (auto& thread : m_workers) {
        if (thread.joinable()) thread.join();
    }
}

// ===========================================================
// AddTask: 主线程调用，以文件为粒度提交任务
// Phase 2 对比旧设计：
//   旧: for each keyword → AddTask()  → N 次 m_queueMutex 加锁
//   新: AddTask(filePath) 一次         → 1 次 m_queueMutex 加锁
// ===========================================================
void ParallelHasher::AddTask(const std::string& filePath, uint32_t docId) {
    {
        std::unique_lock<std::mutex> lock(m_queueMutex);
        m_taskQueue.push({filePath, docId});
        m_activeTasks++;
    }
    m_cv.notify_one(); // 唤醒一个空闲 Worker
}

// ===========================================================
// worker: 每个线程的核心循环
//
// 并行策略（各步骤是否持锁）：
//   Step 1 - 读文件   → 无锁，完全并行（I/O 并行）
//   Step 2 - 分词     → s_jiebaMutex 短暂序列化（但读文件不受影响）
//   Step 3 - SM3 哈希 → 无锁，完全并行（CPU 并行）
//   Step 4 - 写结果   → m_indexMutex，每文件只加 1 次锁（旧设计每关键词 1 次）
// ===========================================================
void ParallelHasher::worker() {
    while (true) {
        std::string filePath;
        uint32_t    docId;

        // --- 从任务队列取一个文件任务 ---
        {
            std::unique_lock<std::mutex> lock(m_queueMutex);
            m_cv.wait(lock, [this] { return m_stop || !m_taskQueue.empty(); });
            if (m_stop && m_taskQueue.empty()) return;
            std::tie(filePath, docId) = std::move(m_taskQueue.front());
            m_taskQueue.pop();
        }
        // ==== 从此处起，不持任何锁，进入完全并行区 ====

        // --- Step 1+2: Phase 3 流式读取 + 逐块分词 ---
        //
        // 旧实现（Phase 2）：一次性把整个文件读入 std::string。
        //   对 GB 级文件会瞬间耗尽内存（例如 1GB 文件 = 1GB RAM 峰值占用）。
        //
        // 新实现（Phase 3）：64KB 分块读取，每块独立分词。
        //   将上一块末尾不完整的 UTF-8 字节保留为 leftover，
        //   拼到下一块开头，保证任何中文/多字节字符不被块边界截断。
        //   峰值内存：~128KB（两个缓冲区）+ Jieba 字典（固定开销）。
        //
        // 局限性：极低概率在块边界切断纯 ASCII 词（如 64KB 边界正好在
        //   "encrypt" 中间），实际影响可忽略（块远大于最长词）。
        static const size_t CHUNK_SIZE = 64 * 1024; // 64 KB

        std::vector<std::string> words; // 汇聚整个文件所有块的分词结果
        {
            std::ifstream file(filePath, std::ios::binary);
            if (!file.is_open()) {
                std::cerr << "[Worker] Cannot open file: " << filePath << std::endl;
                { std::unique_lock<std::mutex> lock(m_indexMutex); m_activeTasks--; }
                m_finishedCv.notify_all();
                continue;
            }

            // 确保 Jieba 初始化（首次调用加载字典，后续所有线程复用同一实例）
            {
                std::lock_guard<std::mutex> jieba_lock(s_jiebaMutex);
                if (!s_jieba) {
                    try {
                        s_jieba = std::make_unique<cppjieba::Jieba>(
                            DICT_PATH, HMM_PATH, USER_DICT_PATH, IDF_PATH, STOP_WORD_PATH);
                    } catch (const std::exception& e) {
                        std::cerr << "[Worker] Jieba init failed: " << e.what()
                                  << "\nPlease ensure dict files exist at: " << DICT_PATH << std::endl;
                    }
                }
            }

            std::string      leftover;          // 上一块末尾残留的不完整 UTF-8 字节
            std::vector<char> rawBuf(CHUNK_SIZE);

            while (true) {
                file.read(rawBuf.data(), CHUNK_SIZE);
                size_t bytesRead = static_cast<size_t>(file.gcount());
                if (bytesRead == 0) break;

                // 拼合：[残留前缀] + [本次读取的原始字节]
                // 通常残留仅 0~3 字节（UTF-8 最长字符 4 字节），拼合代价极低
                std::string chunk = leftover + std::string(rawBuf.data(), bytesRead);
                leftover.clear();

                // 找到安全的 UTF-8 分割点，避免截断多字节字符
                size_t splitPos = safeUtf8SplitPoint(chunk.data(), chunk.size());

                // 分割点之后的字节（0~3 字节）留到下一迭代，作为残留前缀
                if (splitPos < chunk.size()) {
                    leftover.assign(chunk.begin() + static_cast<std::ptrdiff_t>(splitPos),
                                    chunk.end());
                    chunk.resize(splitPos);
                }

                // 对本块的完整 UTF-8 内容执行分词（持 s_jiebaMutex 序列化）
                if (!chunk.empty()) {
                    std::lock_guard<std::mutex> jieba_lock(s_jiebaMutex);
                    if (s_jieba) {
                        s_jieba->CutForSearch(chunk, words);
                    }
                }
            }

            // 处理最后的残留（EOF 前不足一块的尾部）
            if (!leftover.empty()) {
                std::lock_guard<std::mutex> jieba_lock(s_jiebaMutex);
                if (s_jieba) {
                    s_jieba->CutForSearch(leftover, words);
                }
            }
        } // file 在此自动关闭（RAII）

        // --- Step 3: 并行 SM3 哈希 + 预过滤（无锁，完全并行）---
        // 预先构建批次，在写入时只需持一次 m_indexMutex
        using HashDocPair = std::pair<std::array<uint8_t, 32>, uint32_t>;
        std::vector<HashDocPair> batch;
        batch.reserve(words.size());

        for (auto& word : words) {
            // UTF-8 安全的 ASCII 转小写（只处理 0x41~0x5A，不破坏中文多字节序列）
            for (char& c : word) {
                if (c >= 'A' && c <= 'Z') c += 32;
            }
            // 过滤纯空白词
            if (word.empty() || word.find_first_not_of(" \t\n\r\v") == std::string::npos) {
                continue;
            }
            batch.emplace_back(CryptoEngine::ComputeSM3(word), docId);
        }

        // --- Step 4: 聚合 TF，批量写入索引（Phase 5 改进）---
        // 先在 Worker 本地统计该文档各个词汇出现的次数
        std::map<std::array<uint8_t, 32>, uint32_t> localTermCounts;
        for (auto& [hash, id] : batch) {
            localTermCounts[hash]++;
        }
        
        float totalWords = static_cast<float>(batch.size());

        {
            std::unique_lock<std::mutex> lock(m_indexMutex);
            // 每个唯一词仅压入一条 Posting，解决去重问题并记录 TF 值
            for (auto& [hash, count] : localTermCounts) {
                float tf = totalWords > 0.0f ? static_cast<float>(count) / totalWords : 0.0f;
                m_finalIndex[hash].push_back({docId, tf});
            }
            m_activeTasks--; // 任务完成，递减计数
        }
        m_finishedCv.notify_all(); // 通知 GetResults() 检查进度
    }
}

// ===========================================================
// GetResults: 等待全部任务完成后返回倒排索引
// ===========================================================
std::map<std::array<uint8_t, 32>, std::vector<Posting>> ParallelHasher::GetResults() {
    std::unique_lock<std::mutex> lock(m_queueMutex);
    // 条件：任务队列为空 且 没有正在处理中的任务
    m_finishedCv.wait(lock, [this] {
        return m_taskQueue.empty() && m_activeTasks == 0;
    });

    std::unique_lock<std::mutex> indexLock(m_indexMutex);
    return std::move(m_finalIndex); // std::move 避免深拷贝大 map
}