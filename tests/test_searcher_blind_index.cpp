/**
 * @file test_searcher_blind_index.cpp
 * @brief HMAC-SM3 密钥盲索引端到端安全性、密码校验与版本防降级测试（TDD）
 */

#include "core/CryptoEngine.hpp"
#include "index/IndexStructs.hpp"
#include "index/Indexer.hpp"
#include "search/Searcher.hpp"

#include <array>
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

void WriteDoc(const fs::path& p, const std::string& text) {
    std::ofstream out(p, std::ios::binary);
    out.write(text.data(), static_cast<std::streamsize>(text.size()));
}

void TestBlindIndexEndToEndAndDictionaryResistance() {
    TempDirGuard tmp("es_test_blind_index_e2e");
    const fs::path docsDir = tmp.path / "docs";
    const fs::path indexPath = tmp.path / "index_v3.bin";
    const fs::path mapPath = tmp.path / "file_map.dat";
    fs::create_directories(docsDir);

    WriteDoc(docsDir / "doc1.txt", "国密算法 SM3 与 SM4 加密检索测试。\n");
    WriteDoc(docsDir / "doc2.txt", "倒排索引结合布尔搜索提升检索效率。\n");

    std::array<uint8_t, 16> salt{};
    for (size_t i = 0; i < salt.size(); ++i) {
        salt[i] = static_cast<uint8_t>(0x30 + i);
    }
    const uint32_t iterations = 1000;

    CryptoEngine::DeriveKeySM3PBKDF2("master_secret_right", salt, iterations);

    {
        IndexManager mgr(2);
        mgr.SetCryptoParams(salt, iterations);
        mgr.ScanDirectory(docsDir.string());
        mgr.SaveToIndex(indexPath.string());
        mgr.SaveFileMap(mapPath.string());
    }

    // 1. 直接解析磁盘二进制词典，验证抗离线字典攻击：裸 SM3 哈希不得存在于词典中
    {
        std::ifstream idxIn(indexPath, std::ios::binary);
        EXPECT_TRUE(idxIn.is_open(), "index file should open");

        IndexHeader hdr{};
        idxIn.read(reinterpret_cast<char*>(&hdr), sizeof(hdr));
        EXPECT_TRUE(hdr.magic == ESIX_MAGIC, "header magic matches ESIX");
        EXPECT_TRUE(hdr.version == ESIX_VERSION, "header version must be 3");

        std::vector<DictionaryEntry> dict(hdr.keywordCount);
        idxIn.read(reinterpret_cast<char*>(dict.data()),
                   static_cast<std::streamsize>(hdr.keywordCount * sizeof(DictionaryEntry)));

        const auto rawSm3 = CryptoEngine::ComputeSM3("sm3");
        const auto rawGuomi = CryptoEngine::ComputeSM3("国密");
        const auto trapSm3 = CryptoEngine::ComputeKeywordTrapdoor("sm3");

        bool foundRawSm3 = false;
        bool foundRawGuomi = false;
        bool foundTrapSm3 = false;
        for (const auto& entry : dict) {
            if (std::memcmp(entry.hash, rawSm3.data(), 32) == 0) foundRawSm3 = true;
            if (std::memcmp(entry.hash, rawGuomi.data(), 32) == 0) foundRawGuomi = true;
            if (std::memcmp(entry.hash, trapSm3.data(), 32) == 0) foundTrapSm3 = true;
        }
        EXPECT_TRUE(!foundRawSm3, "unkeyed SM3('sm3') must NOT appear in dictionary");
        EXPECT_TRUE(!foundRawGuomi, "unkeyed SM3('国密') must NOT appear in dictionary");
        EXPECT_TRUE(foundTrapSm3, "keyed HMAC-SM3 trapdoor('sm3') must appear in dictionary");
    }

    // 2. 正确密钥加载与检索
    Searcher searcher;
    EXPECT_TRUE(searcher.LoadFileMap(mapPath.string()), "LoadFileMap succeeds");
    EXPECT_TRUE(searcher.LoadIndex(indexPath.string()), "LoadIndex v3 succeeds");
    EXPECT_TRUE(searcher.VerifyPasswordKey(), "right password must pass VerifyPasswordKey");

    auto res1 = searcher.Search("SM3");
    EXPECT_TRUE(res1.size() == 1, "Search('SM3') with right key finds doc1");
    auto resBool = searcher.BooleanSearch("SM3 AND 国密");
    EXPECT_TRUE(resBool.size() == 1, "BooleanSearch('SM3 AND 国密') finds doc1");

    // 3. 错误密码派生后：VerifyPasswordKey 必须拒绝，且无法命中任何文档
    const auto& loadedHdr = searcher.GetIndexHeader();
    std::array<uint8_t, 16> loadedSalt{};
    std::memcpy(loadedSalt.data(), loadedHdr.salt, loadedSalt.size());

    CryptoEngine::DeriveKeySM3PBKDF2("master_secret_wrong", loadedSalt, loadedHdr.iterations);
    EXPECT_TRUE(!searcher.VerifyPasswordKey(), "wrong password must fail VerifyPasswordKey");
    EXPECT_TRUE(searcher.Search("SM3").empty(), "Search with wrong key must return empty");
    EXPECT_TRUE(searcher.BooleanSearch("SM3 OR 倒排").empty(), "BooleanSearch with wrong key must return empty");

    // 4. 使用索引头中的 salt/iterations 重新输入正确密码恢复检索
    CryptoEngine::DeriveKeySM3PBKDF2("master_secret_right", loadedSalt, loadedHdr.iterations);
    EXPECT_TRUE(searcher.VerifyPasswordKey(), "restored right password passes VerifyPasswordKey");
    EXPECT_TRUE(searcher.Search("SM3").size() == 1, "Search works again after restoring right key");
}

void TestRejectLegacyV2Index() {
    TempDirGuard tmp("es_test_reject_v2");
    const fs::path legacyPath = tmp.path / "legacy_v2.bin";

    IndexHeader legacy{};
    legacy.magic = ESIX_MAGIC;
    legacy.version = 2;
    legacy.keywordCount = 0;
    legacy.docCount = 0;
    {
        std::ofstream out(legacyPath, std::ios::binary);
        out.write(reinterpret_cast<const char*>(&legacy), sizeof(legacy));
    }

    Searcher searcher;
    EXPECT_TRUE(!searcher.LoadIndex(legacyPath.string()),
                "Searcher::LoadIndex must reject legacy v2 unkeyed index");
}

} // namespace

int main() {
    TestBlindIndexEndToEndAndDictionaryResistance();
    TestRejectLegacyV2Index();

    if (g_failures > 0) {
        std::cerr << g_failures << " assertion(s) failed." << std::endl;
        return 1;
    }
    std::cout << "All SearcherBlindIndex tests passed!" << std::endl;
    return 0;
}
