/**
 * @file test_indexer.cpp
 * @brief IndexManager 扫描统计与边界条件单元测试（TDD）
 */

#include "core/CryptoEngine.hpp"
#include "index/Indexer.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

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

void WriteBytesFile(const fs::path& filePath, const std::string& content) {
    fs::create_directories(filePath.parent_path());
    std::ofstream ofs(filePath, std::ios::binary);
    ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
}

void TestEmptyDirectoryNoUnderflow() {
    TempDirGuard tmp("es_test_empty_dir");
    IndexManager manager(2);

    // 捕获 stdout 验证不会输出无符号下溢的 4294967295
    std::ostringstream captured;
    std::streambuf* oldBuf = std::cout.rdbuf(captured.rdbuf());
    ScanStats ret = manager.ScanDirectory(tmp.path.string());
    std::cout.rdbuf(oldBuf);

    const ScanStats& stats = manager.GetStats();
    EXPECT_EQ(ret.fileCount, size_t(0), "empty dir fileCount should be 0");
    EXPECT_EQ(ret.totalBytes, uint64_t(0), "empty dir totalBytes should be 0");
    EXPECT_EQ(stats.fileCount, size_t(0), "GetStats fileCount should be 0");
    EXPECT_EQ(stats.totalBytes, uint64_t(0), "GetStats totalBytes should be 0");
    EXPECT_TRUE(captured.str().find("4294967295") == std::string::npos,
                "empty dir output must not underflow uint32_t");
}

void TestMissingDirectorySafe() {
    fs::path missing = fs::temp_directory_path() / "es_test_nonexistent_xyz_999";
    std::error_code ec;
    fs::remove_all(missing, ec);

    IndexManager manager(2);
    ScanStats stats = manager.ScanDirectory(missing.string());
    EXPECT_EQ(stats.fileCount, size_t(0), "missing dir fileCount should be 0");
    EXPECT_EQ(stats.totalBytes, uint64_t(0), "missing dir totalBytes should be 0");
}

void TestNestedFilesAndExactByteCount() {
    TempDirGuard tmp("es_test_nested_stats");
    const fs::path docsDir = tmp.path / "docs";
    fs::create_directories(docsDir);

    const std::string fileA = "";                         // 0 bytes
    const std::string fileB = "hello sm3!\n";              // 11 bytes
    const std::string fileC(2048, 'x');                   // 2048 bytes

    WriteBytesFile(docsDir / "empty.txt", fileA);
    WriteBytesFile(docsDir / "sub" / "b.txt", fileB);
    WriteBytesFile(docsDir / "sub" / "deep" / "c.txt", fileC);

    const uint64_t expectedBytes = fileA.size() + fileB.size() + fileC.size();

    IndexManager manager(2);
    ScanStats stats = manager.ScanDirectory(docsDir.string());
    EXPECT_EQ(stats.fileCount, size_t(3), "nested scan should count 3 files");
    EXPECT_EQ(stats.totalBytes, expectedBytes, "nested scan totalBytes should match exact sum");
    EXPECT_EQ(stats.encryptFailedCount, size_t(0), "no cipherDir means 0 encrypt failures");
    EXPECT_EQ(manager.GetStats().fileCount, size_t(3), "GetStats fileCount matches");
    EXPECT_EQ(manager.GetStats().totalBytes, expectedBytes, "GetStats totalBytes matches");
}

void TestEncryptFailureAndSuccessTracking() {
    TempDirGuard tmp("es_test_encrypt_stats");
    const fs::path docsDir = tmp.path / "docs";
    const fs::path cipherDir = tmp.path / "cipher";
    const fs::path badCipherDir = tmp.path / "not_created_dir" / "nested";
    fs::create_directories(docsDir);
    fs::create_directories(cipherDir);

    WriteBytesFile(docsDir / "doc1.txt", "SM3 and SM4 encrypted search test.");
    WriteBytesFile(docsDir / "doc2.txt", "Parallel indexing with C++17.");

    // 1. 测试密文输出路径不可写时失败计数准确
    {
        IndexManager failMgr(2);
        failMgr.SetCipherDir(badCipherDir.string());
        ScanStats failStats = failMgr.ScanDirectory(docsDir.string());
        EXPECT_EQ(failStats.fileCount, size_t(2), "failed cipher run still counts 2 scanned files");
        EXPECT_EQ(failStats.encryptFailedCount, size_t(2), "both files should fail encryption when cipherDir invalid");
    }

    // 2. 派生有效密钥后测试加密成功计数与索引落盘
    std::array<uint8_t, 16> salt{};
    salt.fill(0x2A);
    CryptoEngine::DeriveKeySM3PBKDF2("test_pass_123", salt, 1000);

    IndexManager okMgr(2);
    okMgr.SetCipherDir(cipherDir.string());
    okMgr.SetCryptoParams(salt, 1000);
    ScanStats okStats = okMgr.ScanDirectory(docsDir.string());

    EXPECT_EQ(okStats.fileCount, size_t(2), "valid run counts 2 files");
    EXPECT_EQ(okStats.encryptFailedCount, size_t(0), "valid run should have 0 encrypt failures");
    EXPECT_TRUE(fs::exists(cipherDir / "0.cipher"), "0.cipher should be created");
    EXPECT_TRUE(fs::exists(cipherDir / "1.cipher"), "1.cipher should be created");

    const fs::path indexPath = tmp.path / "test_index.bin";
    okMgr.SaveToIndex(indexPath.string());
    EXPECT_TRUE(fs::exists(indexPath), "index file should be written");
}

} // namespace

int main() {
    TestEmptyDirectoryNoUnderflow();
    TestMissingDirectorySafe();
    TestNestedFilesAndExactByteCount();
    TestEncryptFailureAndSuccessTracking();

    if (g_failures > 0) {
        std::cerr << g_failures << " assertion(s) failed." << std::endl;
        return 1;
    }
    std::cout << "All Indexer tests passed!" << std::endl;
    return 0;
}
