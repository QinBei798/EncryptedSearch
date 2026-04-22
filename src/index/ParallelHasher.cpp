/**
 * @file ParallelHasher.cpp
 * @brief ParallelHasher 类的实现，基于生产者-消费者模型的多线程索引构建
 * @author Antigravity
 * @date 2026-04-22
 */

#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>

#include <index/ParallelHasher.hpp>
#include <cppjieba/Jieba.hpp>
#include <iostream>
#include <fstream>
#include <algorithm>

// Jieba 分词器所需的字典文件路径（相对于运行目录）
static const char* DICT_PATH      = "third_party/cppjieba/dict/jieba.dict.utf8";
static const char* HMM_PATH       = "third_party/cppjieba/dict/hmm_model.utf8";
static const char* USER_DICT_PATH = "third_party/cppjieba/dict/user.dict.utf8";
static const char* IDF_PATH       = "third_party/cppjieba/dict/idf.utf8";
static const char* STOP_WORD_PATH = "third_party/cppjieba/dict/stop_words.utf8";

/**
 * 设计决策：全局共享 Jieba 实例
 * 优点：极大地节省内存开销（字典加载后占用约 100MB，避免了每线程一份副本导致的内存激增）。
 * 权衡：Jieba 分词接口非线程安全，需持锁访问。但由于瓶颈主要在 I/O 和哈希计算，此处的串行化影响微乎其微。
 */
static std::mutex                       s_jiebaMutex;
static std::unique_ptr<cppjieba::Jieba> s_jieba;

/**
 * @brief 在字节流中定位安全的 UTF-8 分割点
 * 
 * 逻辑：从末尾向前探测，避开多字节字符（如汉字）的中间编码，确保切分后的字符串是合法的 UTF-8。
 */
static size_t safeUtf8SplitPoint(const char* data, size_t size) {
    if (size == 0) return 0;
    for (size_t i = 0; i < 4 && i < size; ++i) {
        unsigned char c = static_cast<unsigned char>(data[size - 1 - i]);
        if ((c & 0xC0) != 0x80) { // 检测到 UTF-8 字符的首字节
            size_t leadPos = size - 1 - i;
            size_t charLen;
            if      (c < 0x80) charLen = 1;
            else if (c < 0xE0) charLen = 2;
            else if (c < 0xF0) charLen = 3;
            else               charLen = 4;

            if (leadPos + charLen <= size) return size; // 整个缓冲区字符完整
            else return leadPos;                        // 最后一个字符不完整，回退
        }
    }
    return size;
}

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
    m_cv.notify_all();
    for (auto& thread : m_workers) {
        if (thread.joinable()) thread.join();
    }
}

void ParallelHasher::AddTask(const std::string& filePath, uint32_t docId) {
    {
        std::unique_lock<std::mutex> lock(m_queueMutex);
        m_taskQueue.push({filePath, docId});
        m_activeTasks++;
    }
    m_cv.notify_one();
}

void ParallelHasher::worker() {
    while (true) {
        std::string filePath;
        uint32_t    docId;

        {
            std::unique_lock<std::mutex> lock(m_queueMutex);
            m_cv.wait(lock, [this] { return m_stop || !m_taskQueue.empty(); });
            if (m_stop && m_taskQueue.empty()) return;
            std::tie(filePath, docId) = std::move(m_taskQueue.front());
            m_taskQueue.pop();
        }

        // 步骤 1 & 2: 流式读取文件并分词
        // 采用 64KB 分块读取以处理超大文件，避免内存溢出
        static const size_t CHUNK_SIZE = 64 * 1024;
        std::vector<std::string> words;
        {
            std::ifstream file(filePath, std::ios::binary);
            if (!file.is_open()) {
                std::cerr << "[Worker] 无法打开文件: " << filePath << std::endl;
                { std::unique_lock<std::mutex> lock(m_indexMutex); m_activeTasks--; }
                m_finishedCv.notify_all();
                continue;
            }

            // 延迟初始化共享分词器
            {
                std::lock_guard<std::mutex> jieba_lock(s_jiebaMutex);
                if (!s_jieba) {
                    try {
                        s_jieba = std::make_unique<cppjieba::Jieba>(
                            DICT_PATH, HMM_PATH, USER_DICT_PATH, IDF_PATH, STOP_WORD_PATH);
                    } catch (const std::exception& e) {
                        std::cerr << "[Worker] Jieba 初始化失败: " << e.what() << std::endl;
                    }
                }
            }

            std::string      leftover;
            std::vector<char> rawBuf(CHUNK_SIZE);

            while (true) {
                file.read(rawBuf.data(), CHUNK_SIZE);
                size_t bytesRead = static_cast<size_t>(file.gcount());
                if (bytesRead == 0) break;

                std::string chunk = leftover + std::string(rawBuf.data(), bytesRead);
                leftover.clear();

                size_t splitPos = safeUtf8SplitPoint(chunk.data(), chunk.size());
                if (splitPos < chunk.size()) {
                    leftover.assign(chunk.begin() + static_cast<std::ptrdiff_t>(splitPos), chunk.end());
                    chunk.resize(splitPos);
                }

                if (!chunk.empty()) {
                    std::lock_guard<std::mutex> jieba_lock(s_jiebaMutex);
                    if (s_jieba) s_jieba->CutForSearch(chunk, words);
                }
            }

            if (!leftover.empty()) {
                std::lock_guard<std::mutex> jieba_lock(s_jiebaMutex);
                if (s_jieba) s_jieba->CutForSearch(leftover, words);
            }
        }

        // 步骤 3: 归一化处理及哈希计算（无锁并行区）
        std::map<std::array<uint8_t, 32>, uint32_t> localTermCounts;
        size_t totalValidWords = 0;

        for (auto& word : words) {
            // 转小写并过滤无效词汇
            for (char& c : word) if (c >= 'A' && c <= 'Z') c += 32;
            if (word.empty() || word.find_first_not_of(" \t\n\r\v") == std::string::npos) continue;

            localTermCounts[CryptoEngine::ComputeSM3(word)]++;
            totalValidWords++;
        }

        // 步骤 4: 计算词频 (TF) 并汇总到全局索引
        {
            std::unique_lock<std::mutex> lock(m_indexMutex);
            for (auto& [hash, count] : localTermCounts) {
                float tf = totalValidWords > 0 ? static_cast<float>(count) / totalValidWords : 0.0f;
                m_finalIndex[hash].push_back({docId, tf});
            }
            m_activeTasks--;
        }
        m_finishedCv.notify_all();
    }
}

std::map<std::array<uint8_t, 32>, std::vector<Posting>> ParallelHasher::GetResults() {
    std::unique_lock<std::mutex> lock(m_queueMutex);
    m_finishedCv.wait(lock, [this] {
        return m_taskQueue.empty() && m_activeTasks == 0;
    });

    std::unique_lock<std::mutex> indexLock(m_indexMutex);
    return std::move(m_finalIndex);
}