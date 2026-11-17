/**
 * @file ParallelHasher.cpp
 * @brief ParallelHasher 类的实现，基于生产者-消费者模型与真·流式分词的多线程索引构建
 */

#include "index/ParallelHasher.hpp"

#include <algorithm>
#include <cppjieba/Jieba.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <vector>

namespace {

// Jieba 分词器所需的字典目录（自动适配常见构建/运行路径）
std::string GetDictDir() {
    const char* candidates[] = {
        "third_party/cppjieba/dict/",
        "../third_party/cppjieba/dict/",
        "../../third_party/cppjieba/dict/",
        "../../../third_party/cppjieba/dict/"
    };
    for (const char* dir : candidates) {
        if (std::filesystem::exists(std::string(dir) + "jieba.dict.utf8")) {
            return dir;
        }
    }
    return "third_party/cppjieba/dict/";
}

std::string GetDictPath(const std::string& filename) {
    return GetDictDir() + filename;
}

/**
 * 设计决策：全局共享 Jieba 实例
 * 优点：极大地节省内存开销（字典加载后占用约 130~180MB，避免了每线程一份副本导致的内存激增）。
 * 权衡：持锁调用 CutForSearch 后立即释放锁，在无锁区完成哈希与词频累加。
 */
std::mutex                       s_jiebaMutex;
std::unique_ptr<cppjieba::Jieba> s_jieba;

cppjieba::Jieba* GetSharedJiebaLocked() {
    if (!s_jieba) {
        try {
            s_jieba = std::make_unique<cppjieba::Jieba>(
                GetDictPath("jieba.dict.utf8"),
                GetDictPath("hmm_model.utf8"),
                GetDictPath("user.dict.utf8"),
                GetDictPath("idf.utf8"),
                GetDictPath("stop_words.utf8"));
        } catch (const std::exception& e) {
            std::cerr << "[Worker] Jieba 初始化失败: " << e.what() << std::endl;
        }
    }
    return s_jieba.get();
}

bool IsAsciiWhitespace(unsigned char c) {
    return c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == '\v' || c == '\f';
}

bool IsSafePunctDelimiter(const char* data, size_t endPos, size_t& outSplitPos) {
    unsigned char c = static_cast<unsigned char>(data[endPos - 1]);
    if (IsAsciiWhitespace(c) || c == ',' || c == ';' || c == '!' || c == '?') {
        outSplitPos = endPos;
        return true;
    }
    // 常见中文全角句读分隔符（均为 3 字节 UTF-8）
    if (endPos >= 3) {
        const unsigned char b0 = static_cast<unsigned char>(data[endPos - 3]);
        const unsigned char b1 = static_cast<unsigned char>(data[endPos - 2]);
        const unsigned char b2 = static_cast<unsigned char>(data[endPos - 1]);
        const bool isCjkDelim =
            (b0 == 0xE3 && b1 == 0x80 && (b2 == 0x81 || b2 == 0x82)) || // 、 。
            (b0 == 0xEF && b1 == 0xBC && (b2 == 0x81 || b2 == 0x8C || b2 == 0x9B || b2 == 0x9F)); // ！ ， ； ？
        if (isCjkDelim) {
            outSplitPos = endPos;
            return true;
        }
    }
    return false;
}

size_t FindSafeUtf8SplitPoint(const char* data, size_t size) {
    if (size == 0) return 0;
    for (size_t i = 0; i < 4 && i < size; ++i) {
        unsigned char c = static_cast<unsigned char>(data[size - 1 - i]);
        if ((c & 0xC0) != 0x80) { // 检测到 UTF-8 字符的首字节
            size_t leadPos = size - 1 - i;
            size_t charLen = 1;
            if      (c < 0x80) charLen = 1;
            else if (c < 0xE0) charLen = 2;
            else if (c < 0xF0) charLen = 3;
            else               charLen = 4;

            return (leadPos + charLen <= size) ? size : leadPos;
        }
    }
    return size;
}

void AccumulateTokens(
    std::vector<std::string>& chunkWords,
    std::map<std::array<uint8_t, 32>, uint32_t>& localTermCounts,
    size_t& totalValidWords)
{
    for (auto& word : chunkWords) {
        for (char& c : word) {
            if (c >= 'A' && c <= 'Z') c += 32;
        }
        if (word.empty() || word.find_first_not_of(" \t\n\r\v\f") == std::string::npos) {
            continue;
        }
        localTermCounts[CryptoEngine::ComputeKeywordTrapdoor(word)]++;
        totalValidWords++;
    }
    chunkWords.clear();
}

void TokenizeAndAccumulateChunk(
    const std::string& text,
    std::vector<std::string>& chunkWords,
    std::map<std::array<uint8_t, 32>, uint32_t>& localTermCounts,
    size_t& totalValidWords)
{
    if (text.empty()) return;
    {
        std::lock_guard<std::mutex> jiebaLock(s_jiebaMutex);
        if (cppjieba::Jieba* jieba = GetSharedJiebaLocked()) {
            jieba->CutForSearch(text, chunkWords);
        } else {
            chunkWords.clear();
        }
    }
    AccumulateTokens(chunkWords, localTermCounts, totalValidWords);
}

} // namespace

size_t ParallelHasher::FindSafeSplitPoint(const char* data, size_t size) {
    if (!data || size == 0) {
        return 0;
    }

    // 一级优先：在末尾 4KB 回溯窗口内寻找空白或句读分隔符，避免跨块截断完整词
    static constexpr size_t kBacktrackWindow = 4096;
    const size_t minSearch = size > kBacktrackWindow ? (size - kBacktrackWindow) : 0;
    for (size_t pos = size; pos > minSearch; --pos) {
        size_t splitPos = 0;
        if (IsSafePunctDelimiter(data, pos, splitPos)) {
            return splitPos;
        }
    }

    // 二级兜底：无分隔符时回退至 UTF-8 字符边界，至少保证不劈裂多字节字符
    return FindSafeUtf8SplitPoint(data, size);
}

ParallelHasher::ParallelHasher(size_t threadCount) {
    const size_t workers = threadCount > 0 ? threadCount : 1;
    for (size_t i = 0; i < workers; ++i) {
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
        uint32_t    docId = 0;

        {
            std::unique_lock<std::mutex> lock(m_queueMutex);
            m_cv.wait(lock, [this] { return m_stop || !m_taskQueue.empty(); });
            if (m_stop && m_taskQueue.empty()) return;
            std::tie(filePath, docId) = std::move(m_taskQueue.front());
            m_taskQueue.pop();
        }

        // 确保任何分支退出都能在队列锁保护下递减 m_activeTasks 并唤醒 GetResults()，避免 lost-wakeup
        struct TaskGuard {
            std::mutex& queueMutex;
            std::atomic<size_t>& active;
            std::condition_variable& cv;
            ~TaskGuard() {
                {
                    std::lock_guard<std::mutex> qlock(queueMutex);
                    active--;
                }
                cv.notify_all();
            }
        } guard{m_queueMutex, m_activeTasks, m_finishedCv};

        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "[Worker] 无法打开文件: " << filePath << std::endl;
            continue;
        }

        // 64KB 真·流式分块读取：每块切词后立即哈希累计，绝不在内存积攒全文件词表
        static constexpr size_t CHUNK_SIZE = 64 * 1024;
        std::vector<char> rawBuf(CHUNK_SIZE);
        std::vector<std::string> chunkWords;
        std::string leftover;

        std::map<std::array<uint8_t, 32>, uint32_t> localTermCounts;
        size_t totalValidWords = 0;

        try {
            while (true) {
                file.read(rawBuf.data(), CHUNK_SIZE);
                const size_t bytesRead = static_cast<size_t>(file.gcount());
                if (bytesRead == 0) break;

                leftover.append(rawBuf.data(), bytesRead);
                std::string chunk = std::move(leftover);
                leftover.clear();

                const size_t splitPos = FindSafeSplitPoint(chunk.data(), chunk.size());
                if (splitPos < chunk.size()) {
                    leftover.assign(chunk.begin() + static_cast<std::ptrdiff_t>(splitPos), chunk.end());
                    chunk.resize(splitPos);
                }

                TokenizeAndAccumulateChunk(chunk, chunkWords, localTermCounts, totalValidWords);
            }

            if (!leftover.empty()) {
                TokenizeAndAccumulateChunk(leftover, chunkWords, localTermCounts, totalValidWords);
            }
        } catch (const std::exception& e) {
            std::cerr << "[Worker] 索引计算失败 (" << filePath << "): " << e.what() << std::endl;
            continue;
        }

        // 汇总本文件词频 (TF) 至全局倒排索引
        {
            std::unique_lock<std::mutex> lock(m_indexMutex);
            for (const auto& [hash, count] : localTermCounts) {
                float tf = totalValidWords > 0 ? static_cast<float>(count) / totalValidWords : 0.0f;
                m_finalIndex[hash].push_back({docId, tf});
            }
        }
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
