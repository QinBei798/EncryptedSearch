/**
 * @file test_parallel_hasher.cpp
 * @brief ParallelHasher 真·流式分词与跨块边界单元测试（TDD）
 */

#include "core/CryptoEngine.hpp"
#include "core/SystemMonitor.hpp"
#include "index/ParallelHasher.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

int g_failures = 0;

void ExpectTrue(bool cond, const std::string& msg, int line) {
    if (!cond) {
        std::cerr << "[FAIL] Line " << line << ": " << msg << std::endl;
        ++g_failures;
    }
}

template <typename T>
void ExpectEq(const T& actual, const T& expected, const std::string& msg, int line) {
    if (actual != expected) {
        std::cerr << "[FAIL] Line " << line << ": " << msg
                  << " | expected=" << expected << ", actual=" << actual << std::endl;
        ++g_failures;
    }
}

#define EXPECT_TRUE(cond, msg) ExpectTrue((cond), (msg), __LINE__)
#define EXPECT_EQ(act, exp, msg) ExpectEq((act), (exp), (msg), __LINE__)

struct TempDirGuard {
    fs::path path;
    explicit TempDirGuard(const std::string& name) {
        path = fs::temp_directory_path() / name;
        std::error_code ec;
        fs::remove_all(path, ec);
        fs::create_directories(path, ec);
    }
    ~TempDirGuard() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

void WriteFile(const fs::path& filePath, const std::string& content) {
    std::ofstream ofs(filePath, std::ios::binary);
    ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
}

void TestFindSafeSplitPoint() {
    EXPECT_EQ(ParallelHasher::FindSafeSplitPoint("", 0), size_t(0), "empty buffer returns 0");

    // 1. 优先在空白分隔符后切分，把尾部未完单词留给下一块
    const std::string textWithSpace = "hello world encrypted";
    size_t spaceSplit = ParallelHasher::FindSafeSplitPoint(textWithSpace.data(), textWithSpace.size());
    EXPECT_EQ(textWithSpace.substr(0, spaceSplit), std::string("hello world "),
              "should split after trailing whitespace so 'encrypted' stays intact");

    // 2. 换行符同样作为安全切分边界
    const std::string textWithNewline = "第一行内容\n第二行半截";
    size_t nlSplit = ParallelHasher::FindSafeSplitPoint(textWithNewline.data(), textWithNewline.size());
    EXPECT_EQ(textWithNewline.substr(0, nlSplit), std::string("第一行内容\n"),
              "should split after newline boundary");

    // 3. 回溯窗口内无分隔符时，回退到 UTF-8 字符边界，避免劈裂多字节汉字
    // 构造纯连续 3 字节汉字（无任何空白），截断最后 1 字节
    std::string pureChinese;
    for (int i = 0; i < 2000; ++i) {
        pureChinese += "国"; // 3 bytes each -> 6000 bytes (> 4KB backtrack window)
    }
    const size_t cutLen = pureChinese.size() - 2; // 最后只剩 '国' 的第 1 个字节
    size_t utf8Split = ParallelHasher::FindSafeSplitPoint(pureChinese.data(), cutLen);
    EXPECT_EQ(utf8Split, pureChinese.size() - 3,
              "no whitespace in window should fall back to safe UTF-8 boundary");

    // 4. 完整 UTF-8 序列且无分隔符时可完整消费
    size_t fullUtf8Split = ParallelHasher::FindSafeSplitPoint(pureChinese.data(), pureChinese.size());
    EXPECT_EQ(fullUtf8Split, pureChinese.size(), "complete UTF-8 buffer should return full size");
}

void TestMultiChunkRecallAndNoOverwriteBug() {
    TempDirGuard tmp("es_test_multichunk_recall");
    const fs::path docPath = tmp.path / "large_multi_chunk.txt";

    // 构造约 160KB 文件（跨越 3 个 64KB 分块），在每块埋入独立唯一关键词
    std::string content;
    content += "alphachunkone ";
    while (content.size() < 70000) {
        content += "fillerpaddingtextforchunkone ";
    }
    content += "\nbetachunktwo ";
    while (content.size() < 140000) {
        content += "fillerpaddingtextforchunktwo ";
    }
    content += "\ngammachunkthree alphachunkone\n";
    WriteFile(docPath, content);

    ParallelHasher hasher(2);
    hasher.AddTask(docPath.string(), 7);
    auto index = hasher.GetResults();

    auto hashAlpha = CryptoEngine::ComputeSM3("alphachunkone");
    auto hashBeta  = CryptoEngine::ComputeSM3("betachunktwo");
    auto hashGamma = CryptoEngine::ComputeSM3("gammachunkthree");

    EXPECT_TRUE(index.find(hashAlpha) != index.end(), "Chunk 1 token must not be overwritten");
    EXPECT_TRUE(index.find(hashBeta) != index.end(), "Chunk 2 token must not be overwritten");
    EXPECT_TRUE(index.find(hashGamma) != index.end(), "Chunk 3 token must be indexed");

    if (index.find(hashAlpha) != index.end() && index.find(hashGamma) != index.end()) {
        // alpha 出现 2 次，gamma 出现 1 次，同一文档内 TF 应约为 2:1
        float tfAlpha = index[hashAlpha][0].tf;
        float tfGamma = index[hashGamma][0].tf;
        EXPECT_TRUE(tfAlpha > tfGamma * 1.5f, "alpha appearing twice must have ~2x TF of gamma");
    }
}

void TestCrossBoundaryWordsAt64KB() {
    TempDirGuard tmp("es_test_cross_64kb");

    // 文件 A：让英文长词 "encryptedsearch" 精准横跨 65536 (64KB) 字节边界
    {
        std::string content;
        const std::string pad = "pad ";
        while (content.size() + pad.size() <= 65530) {
            content += pad;
        }
        while (content.size() < 65530) {
            content += ' ';
        }
        // "encryptedsearch" 位于 [65530, 65545)，精确跨越 65536
        content += "encryptedsearch trailing_word\n";
        const fs::path pathA = tmp.path / "cross_en.txt";
        WriteFile(pathA, content);

        ParallelHasher hasher(2);
        hasher.AddTask(pathA.string(), 0);
        auto index = hasher.GetResults();

        EXPECT_TRUE(index.find(CryptoEngine::ComputeSM3("encryptedsearch")) != index.end(),
                    "English word crossing 64KB boundary must remain intact");
    }

    // 文件 B：让中文词典词 "搜索引擎" (12 字节) 精准横跨 65536 (64KB) 字节边界
    {
        std::string content;
        const std::string pad = "填充 ";
        while (content.size() < 65529) {
            content += pad;
        }
        content += ' ';
        // 确保中文词跨越 65536 边界
        const size_t boundaryPos = content.size();
        content += "搜索引擎 测试结束\n";
        EXPECT_TRUE(boundaryPos < 65536 && boundaryPos + 12 > 65536,
                    "test setup check: Chinese word straddles 65536");

        const fs::path pathB = tmp.path / "cross_zh.txt";
        WriteFile(pathB, content);

        ParallelHasher hasher(2);
        hasher.AddTask(pathB.string(), 1);
        auto index = hasher.GetResults();

        EXPECT_TRUE(index.find(CryptoEngine::ComputeSM3("搜索引擎")) != index.end(),
                    "Chinese word crossing 64KB boundary must remain intact");
    }
}

void TestLargeFileStreamingMemoryBound() {
    TempDirGuard tmp("es_test_streaming_mem");
    const fs::path warmupPath = tmp.path / "warmup.txt";
    const fs::path bigPath = tmp.path / "big_24mb.txt";
    WriteFile(warmupPath, "warmup jieba dictionary initialization.\n");

    // 1. 先预热共享 Jieba 字典，消除首次加载字典 (~130MB) 对增量峰值的干扰
    {
        ParallelHasher warmup(1);
        warmup.AddTask(warmupPath.string(), 0);
        (void)warmup.GetResults();
    }

    const MemoryStats before = SystemMonitor::GetMemoryStats();

    // 2. 构造约 24MB 文本文件（包含数百万个 token）
    {
        std::string line = "国密算法 SM3 SM4 C++17 流式分词倒排索引测试数据。\n";
        std::string block;
        block.reserve(1024 * 1024);
        while (block.size() < 1024 * 1024) {
            block += line;
        }
        std::ofstream ofs(bigPath, std::ios::binary);
        for (int i = 0; i < 24; ++i) {
            ofs.write(block.data(), static_cast<std::streamsize>(block.size()));
        }
    }

    {
        ParallelHasher hasher(1);
        hasher.AddTask(bigPath.string(), 1);
        auto index = hasher.GetResults();
        EXPECT_TRUE(index.find(CryptoEngine::ComputeSM3("国密")) != index.end(),
                    "24MB streaming file should index '国密'");
    }

    const MemoryStats after = SystemMonitor::GetMemoryStats();
    if (before.IsValid() && after.IsValid()) {
        double deltaMB = after.peakRssMB - before.peakRssMB;
        // 若把 24MB 全部 token 存在 vector<string> 中会占用上百 MB；真流式应远小于 32MB
        EXPECT_TRUE(deltaMB < 32.0,
                    "streaming 24MB file must keep peak RSS delta < 32MB (actual delta=" +
                    std::to_string(deltaMB) + " MB)");
    }
}

} // namespace

int main() {
    TestFindSafeSplitPoint();
    TestMultiChunkRecallAndNoOverwriteBug();
    TestCrossBoundaryWordsAt64KB();
    TestLargeFileStreamingMemoryBound();

    if (g_failures > 0) {
        std::cerr << g_failures << " assertion(s) failed." << std::endl;
        return 1;
    }
    std::cout << "All ParallelHasher streaming tests passed!" << std::endl;
    return 0;
}
