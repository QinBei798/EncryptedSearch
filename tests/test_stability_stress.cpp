/**
 * @file test_stability_stress.cpp
 * @brief 稳定性测试：10,000 次高频检索循环、FD/RSS 泄漏检测、线程池启停与权限容错
 */

#include "core/CryptoEngine.hpp"
#include "core/SystemMonitor.hpp"
#include "index/Indexer.hpp"
#include "index/ParallelHasher.hpp"
#include "search/Searcher.hpp"

#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#ifdef __linux__
#include <sys/stat.h>
#include <unistd.h>
#endif

#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define ES_UNDER_TSAN 1
#endif
#endif
#if defined(__SANITIZE_THREAD__)
#define ES_UNDER_TSAN 1
#endif

namespace fs = std::filesystem;

namespace {

int g_failures = 0;

void ExpectTrue(bool cond, const std::string& msg, int line) {
    if (!cond) {
        std::cerr << "[FAIL] Line " << line << ": " << msg << std::endl;
        ++g_failures;
    }
}

#define EXPECT_TRUE(cond, msg) ExpectTrue((cond), (msg), __LINE__)

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

void WriteDoc(const fs::path& p, const std::string& content) {
    fs::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary);
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
}

int CountOpenFds() {
#ifdef __linux__
    std::error_code ec;
    int count = 0;
    for (const auto& entry : fs::directory_iterator("/proc/self/fd", ec)) {
        (void)entry;
        ++count;
    }
    return ec ? -1 : count;
#else
    return -1;
#endif
}

void TestHighFrequencyQueryLoop10K() {
    TempDirGuard tmp("es_test_stress_10k");
    const fs::path docsDir = tmp.path / "docs";
    const fs::path indexPath = tmp.path / "index.bin";
    const fs::path mapPath = tmp.path / "file_map.dat";
    fs::create_directories(docsDir);

    for (int i = 0; i < 24; ++i) {
        std::string body = "国密算法 SM3 SM4 加密检索第 " + std::to_string(i) + " 篇文档 ";
        if (i % 2 == 0) body += "alpha commonterm ";
        if (i % 3 == 0) body += "beta jieba ";
        if (i % 5 == 0) body += "gamma specialtoken ";
        body += "\n";
        WriteDoc(docsDir / ("doc_" + std::to_string(i) + ".txt"), body);
    }

    std::array<uint8_t, 16> salt{};
    salt.fill(0x91);
    CryptoEngine::DeriveKeySM3PBKDF2("stress_10k_pass", salt, 1000);

    {
        IndexManager mgr(4);
        mgr.SetCryptoParams(salt, 1000);
        mgr.ScanDirectory(docsDir.string());
        mgr.SaveToIndex(indexPath.string());
        mgr.SaveFileMap(mapPath.string());
    }

    Searcher searcher;
    EXPECT_TRUE(searcher.LoadFileMap(mapPath.string()), "LoadFileMap succeeds");
    EXPECT_TRUE(searcher.LoadIndex(indexPath.string()), "LoadIndex succeeds");
    EXPECT_TRUE(searcher.VerifyPasswordKey(), "VerifyPasswordKey succeeds");

    const auto baselineSingle = searcher.Search("SM3");
    const auto baselineAnd = searcher.BooleanSearch("alpha AND beta");
    const auto baselineAndNot = searcher.BooleanSearch("国密 AND NOT gamma");
    EXPECT_TRUE(baselineSingle.size() == 24, "baseline single search hits 24 docs");
    EXPECT_TRUE(baselineAnd.size() == 4, "baseline alpha AND beta hits 4 docs (0,6,12,18)");

    const int fdsBefore = CountOpenFds();
    const MemoryStats memBefore = SystemMonitor::GetMemoryStats();

    const std::vector<std::string> queries = {
        "sm3",
        "alpha AND beta",
        "alpha OR gamma",
        "国密 AND NOT gamma",
        "nonexistent_token_xyz",
        "AND",
        "",
        "alpha AND"
    };

    const auto start = std::chrono::steady_clock::now();
    constexpr int kIterations = 10000;
    for (int i = 0; i < kIterations; ++i) {
        const std::string& q = queries[static_cast<size_t>(i) % queries.size()];
        if ((i & 3) == 0) {
            auto r = searcher.Search(q);
            if (q == "sm3") {
                EXPECT_TRUE(r.size() == baselineSingle.size(), "Search result count stays stable across 10K loop");
            }
        } else {
            auto r = searcher.BooleanSearch(q);
            if (q == "alpha AND beta") {
                EXPECT_TRUE(r.size() == baselineAnd.size(), "Boolean AND count stays stable across 10K loop");
            } else if (q == "国密 AND NOT gamma") {
                EXPECT_TRUE(r.size() == baselineAndNot.size(), "Boolean AND NOT count stays stable across 10K loop");
            }
        }
    }
    const double elapsedSec = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();

    const int fdsAfter = CountOpenFds();
    const MemoryStats memAfter = SystemMonitor::GetMemoryStats();

    if (fdsBefore >= 0 && fdsAfter >= 0) {
        EXPECT_TRUE(fdsAfter == fdsBefore,
                    "10K queries must leak 0 file descriptors (before=" + std::to_string(fdsBefore) +
                    ", after=" + std::to_string(fdsAfter) + ")");
    }
#ifndef ES_UNDER_TSAN
    if (memBefore.IsValid() && memAfter.IsValid() && memBefore.currentRssMB >= 0.0 && memAfter.currentRssMB >= 0.0) {
        const double rssDelta = memAfter.currentRssMB - memBefore.currentRssMB;
        EXPECT_TRUE(rssDelta < 8.0,
                    "10K queries RSS drift must stay < 8MB (delta=" + std::to_string(rssDelta) + " MB)");
    }
#else
    (void)memBefore;
    (void)memAfter;
#endif

    std::cout << "[Stability] 10,000 queries completed in " << std::fixed << std::setprecision(4)
              << elapsedSec << " s (" << static_cast<int>(kIterations / (elapsedSec > 0.0 ? elapsedSec : 1.0))
              << " QPS)" << std::endl;
}

void TestThreadPoolChurnAndPermissionFaultTolerance() {
    TempDirGuard tmp("es_test_pool_churn");
    const fs::path docsDir = tmp.path / "docs";
    fs::create_directories(docsDir);

    std::array<uint8_t, 16> salt{};
    salt.fill(0x82);
    CryptoEngine::DeriveKeySM3PBKDF2("pool_churn_pass", salt, 1000);

    for (int i = 0; i < 40; ++i) {
        WriteDoc(docsDir / ("f_" + std::to_string(i) + ".txt"),
                 "多线程并发建库测试文件编号 " + std::to_string(i) + " token" + std::to_string(i) + "\n");
    }

    const int fdsBefore = CountOpenFds();
    for (int round = 0; round < 5; ++round) {
        ParallelHasher hasher(8);
        for (int i = 0; i < 40; ++i) {
            hasher.AddTask((docsDir / ("f_" + std::to_string(i) + ".txt")).string(),
                           static_cast<uint32_t>(i));
        }
        auto res = hasher.GetResults();
        EXPECT_TRUE(res.find(CryptoEngine::ComputeKeywordTrapdoor("token39")) != res.end(),
                    "multi-thread pool churn round must index all tasks");
    }
    const int fdsAfter = CountOpenFds();
    if (fdsBefore >= 0 && fdsAfter >= 0) {
        EXPECT_TRUE(fdsAfter == fdsBefore, "5x8-thread pool churn must leak 0 FDs");
    }

#ifdef __linux__
    // 测试无读取权限文件混入目录时，Worker 安全跳过且 GetResults 不死锁
    if (geteuid() != 0) {
        const fs::path lockedFile = docsDir / "unreadable.txt";
        WriteDoc(lockedFile, "secret unreadable content\n");
        chmod(lockedFile.c_str(), 0000);

        ParallelHasher hasher(4);
        hasher.AddTask(lockedFile.string(), 100);
        hasher.AddTask((docsDir / "f_0.txt").string(), 0);
        auto res = hasher.GetResults();

        chmod(lockedFile.c_str(), 0644);
        EXPECT_TRUE(res.find(CryptoEngine::ComputeKeywordTrapdoor("token0")) != res.end(),
                    "readable file still indexed even when unreadable file fails");
    }
#endif
}

} // namespace

int main() {
    TestHighFrequencyQueryLoop10K();
    TestThreadPoolChurnAndPermissionFaultTolerance();

    if (g_failures > 0) {
        std::cerr << g_failures << " assertion(s) failed." << std::endl;
        return 1;
    }
    std::cout << "All StabilityStress tests passed!" << std::endl;
    return 0;
}
