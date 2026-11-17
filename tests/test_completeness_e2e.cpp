/**
 * @file test_completeness_e2e.cpp
 * @brief 端到端完整性测试：随机 IV、零字节/特殊路径、检索命中->SM4解密->SM3一致性闭环、损坏容错（TDD）
 */

#include "core/CryptoEngine.hpp"
#include "index/IndexStructs.hpp"
#include "index/Indexer.hpp"
#include "search/Searcher.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
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

std::vector<uint8_t> ReadAllBytes(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(in)),
                                std::istreambuf_iterator<char>());
}

void WriteBytes(const fs::path& p, const std::string& content) {
    fs::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary);
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
}

void TestRandomIvProducesDistinctCiphertexts() {
    TempDirGuard tmp("es_test_random_iv");
    const fs::path plainPath = tmp.path / "same.txt";
    const fs::path cipher1 = tmp.path / "c1.cipher";
    const fs::path cipher2 = tmp.path / "c2.cipher";
    const fs::path dec1 = tmp.path / "d1.txt";
    const fs::path dec2 = tmp.path / "d2.txt";

    const std::string content = "Identical plaintext encrypted twice must produce different IV and ciphertext.\n";
    WriteBytes(plainPath, content);

    std::array<uint8_t, 16> salt{};
    salt.fill(0x71);
    CryptoEngine::DeriveKeySM3PBKDF2("iv_test_pass", salt, 1000);

    EXPECT_TRUE(CryptoEngine::EncryptFileSM4(plainPath.string(), cipher1.string()), "first encrypt succeeds");
    EXPECT_TRUE(CryptoEngine::EncryptFileSM4(plainPath.string(), cipher2.string()), "second encrypt succeeds");

    auto b1 = ReadAllBytes(cipher1);
    auto b2 = ReadAllBytes(cipher2);
    EXPECT_TRUE(b1.size() > 16 && b1.size() == b2.size(), "both ciphertexts have valid equal length");
    EXPECT_TRUE(std::memcmp(b1.data(), b2.data(), 16) != 0, "random 16B IV header must differ");
    EXPECT_TRUE(b1 != b2, "full ciphertexts must differ");

    EXPECT_TRUE(CryptoEngine::DecryptFileSM4(cipher1.string(), dec1.string()), "decrypt c1 succeeds");
    EXPECT_TRUE(CryptoEngine::DecryptFileSM4(cipher2.string(), dec2.string()), "decrypt c2 succeeds");
    EXPECT_TRUE(CryptoEngine::ComputeFileSM3(dec1.string()) == CryptoEngine::ComputeFileSM3(plainPath.string()),
                "decrypted c1 SM3 matches original");
    EXPECT_TRUE(CryptoEngine::ComputeFileSM3(dec2.string()) == CryptoEngine::ComputeFileSM3(plainPath.string()),
                "decrypted c2 SM3 matches original");
}

void TestZeroByteAndSpecialPathClosedLoop() {
    TempDirGuard tmp("es_test_closed_loop");
    const fs::path docsDir = tmp.path / "docs";
    const fs::path cipherDir = tmp.path / "cipher_docs";
    const fs::path indexPath = tmp.path / "encrypted_search_index.bin";
    const fs::path mapPath = tmp.path / "file_map.dat";
    const fs::path restoredDir = tmp.path / "restored";
    fs::create_directories(docsDir);
    fs::create_directories(cipherDir);
    fs::create_directories(restoredDir);

    // 1. 准备 0 字节文件、含中文和空格路径的大文件(>64KB)、普通中文文件
    const fs::path emptyFile = docsDir / "empty.txt";
    WriteBytes(emptyFile, "");

    const fs::path specialFile = docsDir / "子 目录" / "中文 文件 名.txt";
    std::string largeContent = "specialheadtoken ";
    while (largeContent.size() < 72000) {
        largeContent += "国密算法与流式分词填充文本。\n";
    }
    largeContent += " specialtailtoken 国密 SM4\n";
    WriteBytes(specialFile, largeContent);

    const fs::path normalFile = docsDir / "normal.txt";
    WriteBytes(normalFile, "普通文档仅包含 SM3 内容，不含特殊尾部词。\n");

    std::array<uint8_t, 16> salt{};
    for (size_t i = 0; i < salt.size(); ++i) salt[i] = static_cast<uint8_t>(0xA0 + i);
    const uint32_t iterations = 1000;

    CryptoEngine::DeriveKeySM3PBKDF2("full_loop_secret", salt, iterations);

    {
        IndexManager mgr(2);
        mgr.SetCipherDir(cipherDir.string());
        mgr.SetCryptoParams(salt, iterations);
        ScanStats stats = mgr.ScanDirectory(docsDir.string());
        EXPECT_TRUE(stats.fileCount == 3, "scanned all 3 files including 0-byte and nested special filename");
        EXPECT_TRUE(stats.encryptFailedCount == 0, "all 3 files encrypted without error");
        mgr.SaveToIndex(indexPath.string());
        mgr.SaveFileMap(mapPath.string());
    }

    // 2. 彻底清除内存密钥，模拟重新加载后恢复密钥 -> 检索 -> 定位 docId -> 解密还原 -> SM3 比对
    CryptoEngine::ResetKey();
    EXPECT_TRUE(!CryptoEngine::HasKey(), "key cleared before reload");

    Searcher searcher;
    EXPECT_TRUE(searcher.LoadFileMap(mapPath.string()), "LoadFileMap succeeds");
    EXPECT_TRUE(searcher.LoadIndex(indexPath.string()), "LoadIndex succeeds");

    const auto& hdr = searcher.GetIndexHeader();
    std::array<uint8_t, 16> diskSalt{};
    std::memcpy(diskSalt.data(), hdr.salt, diskSalt.size());
    CryptoEngine::DeriveKeySM3PBKDF2("full_loop_secret", diskSalt, hdr.iterations);
    EXPECT_TRUE(searcher.VerifyPasswordKey(), "re-derived key passes VerifyPasswordKey");

    // 验证跨多块关键词布尔检索命中特殊路径文件
    auto hits = searcher.BooleanSearch("specialheadtoken AND specialtailtoken");
    EXPECT_TRUE(hits.size() == 1, "BooleanSearch hits exact special-path large file");
    if (!hits.empty()) {
        const std::string& hitPath = hits[0].first;
        EXPECT_TRUE(hitPath == specialFile.string(), "hit path matches special Chinese+space path");

        uint32_t docId = 0;
        EXPECT_TRUE(searcher.GetDocId(hitPath, docId), "GetDocId resolves hit path");

        const fs::path cipherFile = cipherDir / (std::to_string(docId) + ".cipher");
        const fs::path restoredFile = restoredDir / "restored_special.txt";
        EXPECT_TRUE(fs::exists(cipherFile), "archived cipher file exists");
        EXPECT_TRUE(CryptoEngine::DecryptFileSM4(cipherFile.string(), restoredFile.string()),
                    "DecryptFileSM4 restores hit file");
        EXPECT_TRUE(CryptoEngine::ComputeFileSM3(restoredFile.string()) ==
                    CryptoEngine::ComputeFileSM3(specialFile.string()),
                    "restored file SM3 digest matches original file byte-for-byte");
    }

    // 验证 0 字节文件也能完整加解密还原
    uint32_t emptyDocId = 0;
    EXPECT_TRUE(searcher.GetDocId(emptyFile.string(), emptyDocId), "GetDocId resolves 0-byte file");
    const fs::path emptyCipher = cipherDir / (std::to_string(emptyDocId) + ".cipher");
    const fs::path emptyRestored = restoredDir / "restored_empty.txt";
    EXPECT_TRUE(CryptoEngine::DecryptFileSM4(emptyCipher.string(), emptyRestored.string()),
                "DecryptFileSM4 succeeds on 0-byte file");
    EXPECT_TRUE(fs::file_size(emptyRestored) == 0, "restored 0-byte file has size 0");

    uint32_t dummyId = 0;
    EXPECT_TRUE(!searcher.GetDocId("/nonexistent/path/doc.txt", dummyId),
                "GetDocId returns false for unknown path");
}

void TestCorruptedCipherAndTruncatedIndexSafe() {
    TempDirGuard tmp("es_test_corrupted");
    const fs::path shortCipher = tmp.path / "too_short.cipher";
    WriteBytes(shortCipher, "1234567890");
    EXPECT_TRUE(!CryptoEngine::DecryptFileSM4(shortCipher.string(), (tmp.path / "out.txt").string()),
                "DecryptFileSM4 rejects file smaller than IV");

    const fs::path truncIndex = tmp.path / "trunc_index.bin";
    WriteBytes(truncIndex, "ESIX_TRUNC");
    Searcher searcher;
    EXPECT_TRUE(!searcher.LoadIndex(truncIndex.string()),
                "Searcher::LoadIndex rejects truncated index header");
}

} // namespace

int main() {
    TestRandomIvProducesDistinctCiphertexts();
    TestZeroByteAndSpecialPathClosedLoop();
    TestCorruptedCipherAndTruncatedIndexSafe();

    if (g_failures > 0) {
        std::cerr << g_failures << " assertion(s) failed." << std::endl;
        return 1;
    }
    std::cout << "All CompletenessE2E tests passed!" << std::endl;
    return 0;
}
