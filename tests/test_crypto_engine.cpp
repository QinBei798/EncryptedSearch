/**
 * @file test_crypto_engine.cpp
 * @brief CryptoEngine 密钥分离、HMAC-SM3 盲索引陷门与密码校验指纹单元测试（TDD）
 */

#include "core/CryptoEngine.hpp"
#include "core/SystemMonitor.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
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

void TestTrapdoorRequiresKey() {
    CryptoEngine::ResetKey();
    EXPECT_TRUE(!CryptoEngine::HasKey(), "ResetKey must clear HasKey state");

    bool threwTrapdoor = false;
    try {
        (void)CryptoEngine::ComputeKeywordTrapdoor("sm3");
    } catch (const std::runtime_error&) {
        threwTrapdoor = true;
    }
    EXPECT_TRUE(threwTrapdoor, "ComputeKeywordTrapdoor without derived key must throw");

    bool threwVerifier = false;
    try {
        (void)CryptoEngine::GetKeyVerifier();
    } catch (const std::runtime_error&) {
        threwVerifier = true;
    }
    EXPECT_TRUE(threwVerifier, "GetKeyVerifier without derived key must throw");
}

void TestHmacSm3AndDomainSeparation() {
    const std::array<uint8_t, 16> keyA = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    const std::array<uint8_t, 16> keyB = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,17};

    auto h1 = CryptoEngine::ComputeSM3HMAC(keyA.data(), keyA.size(), "secret_keyword");
    auto h2 = CryptoEngine::ComputeSM3HMAC(keyA.data(), keyA.size(), "secret_keyword");
    auto h3 = CryptoEngine::ComputeSM3HMAC(keyB.data(), keyB.size(), "secret_keyword");
    auto raw = CryptoEngine::ComputeSM3("secret_keyword");

    EXPECT_TRUE(h1 == h2, "HMAC-SM3 must be deterministic for same key and data");
    EXPECT_TRUE(h1 != h3, "HMAC-SM3 must differ for different keys");
    EXPECT_TRUE(h1 != raw, "HMAC-SM3 must differ from unkeyed raw SM3");

    std::array<uint8_t, 16> salt1{};
    salt1.fill(0x11);
    std::array<uint8_t, 16> salt2{};
    salt2.fill(0x22);

    CryptoEngine::DeriveKeySM3PBKDF2("password_alpha", salt1, 1000);
    EXPECT_TRUE(CryptoEngine::HasKey(), "HasKey should be true after DeriveKeySM3PBKDF2");
    auto trapA1 = CryptoEngine::ComputeKeywordTrapdoor("国密");
    auto verifierA1 = CryptoEngine::GetKeyVerifier();
    auto rawChinese = CryptoEngine::ComputeSM3("国密");
    EXPECT_TRUE(trapA1 != rawChinese, "Keyed trapdoor must not equal unkeyed SM3 hash");
    EXPECT_TRUE(CryptoEngine::VerifyKeyVerifier(verifierA1), "Same key must pass VerifyKeyVerifier");

    // 不同密码产生不同陷门与不同校验指纹
    CryptoEngine::DeriveKeySM3PBKDF2("password_beta", salt1, 1000);
    auto trapB1 = CryptoEngine::ComputeKeywordTrapdoor("国密");
    EXPECT_TRUE(trapB1 != trapA1, "Different password must produce different trapdoor");
    EXPECT_TRUE(!CryptoEngine::VerifyKeyVerifier(verifierA1), "Wrong password must fail VerifyKeyVerifier");

    // 相同密码 + 不同盐产生不同陷门
    CryptoEngine::DeriveKeySM3PBKDF2("password_alpha", salt2, 1000);
    auto trapA2 = CryptoEngine::ComputeKeywordTrapdoor("国密");
    EXPECT_TRUE(trapA2 != trapA1, "Different salt must produce different trapdoor");
    EXPECT_TRUE(!CryptoEngine::VerifyKeyVerifier(verifierA1), "Different salt must fail old keyVerifier");

    // 相同密码 + 相同盐恢复一致陷门与一致校验指纹
    CryptoEngine::DeriveKeySM3PBKDF2("password_alpha", salt1, 1000);
    auto trapA1Again = CryptoEngine::ComputeKeywordTrapdoor("国密");
    EXPECT_TRUE(trapA1Again == trapA1, "Same password and salt must reproduce identical trapdoor");
    EXPECT_TRUE(CryptoEngine::VerifyKeyVerifier(verifierA1), "Restored key must pass VerifyKeyVerifier");
}

void TestSm4EncryptDecryptStillWorksWithSeparatedKey() {
    const fs::path tmpDir = fs::temp_directory_path() / "es_test_crypto_sm4";
    std::error_code ec;
    fs::remove_all(tmpDir, ec);
    fs::create_directories(tmpDir, ec);

    const fs::path plainPath = tmpDir / "plain.txt";
    const fs::path cipherPath = tmpDir / "cipher.bin";
    const fs::path decPath = tmpDir / "decrypted.txt";

    const std::string payload = "SM4-CBC roundtrip verification with domain-separated key.\n";
    {
        std::ofstream out(plainPath, std::ios::binary);
        out.write(payload.data(), static_cast<std::streamsize>(payload.size()));
    }

    std::array<uint8_t, 16> salt{};
    salt.fill(0x5A);
    CryptoEngine::DeriveKeySM3PBKDF2("roundtrip_pass", salt, 1000);

    EXPECT_TRUE(CryptoEngine::EncryptFileSM4(plainPath.string(), cipherPath.string()), "EncryptFileSM4 succeeds");
    EXPECT_TRUE(CryptoEngine::DecryptFileSM4(cipherPath.string(), decPath.string()), "DecryptFileSM4 succeeds");

    std::ifstream in(decPath, std::ios::binary);
    std::string restored((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    EXPECT_TRUE(restored == payload, "Decrypted content matches original plaintext");

    fs::remove_all(tmpDir, ec);
}

void TestSm4StreamingBoundarySizes() {
    const fs::path tmpDir = fs::temp_directory_path() / "es_test_crypto_stream_bounds";
    std::error_code ec;
    fs::remove_all(tmpDir, ec);
    fs::create_directories(tmpDir, ec);

    std::array<uint8_t, 16> salt{};
    salt.fill(0x6B);
    CryptoEngine::DeriveKeySM3PBKDF2("stream_boundary_pass", salt, 1000);

    // 覆盖 0B、块边界(15/16/17B) 与 64KB 流式分块边界(65535/65536/65537B) 及跨4块尾部
    const std::vector<size_t> testSizes = {
        0, 1, 15, 16, 17, 65535, 65536, 65537, 65536 * 3 + 19
    };

    for (size_t sz : testSizes) {
        const fs::path plainPath = tmpDir / ("plain_" + std::to_string(sz) + ".bin");
        const fs::path cipherPath = tmpDir / ("cipher_" + std::to_string(sz) + ".cipher");
        const fs::path decPath = tmpDir / ("dec_" + std::to_string(sz) + ".bin");

        std::vector<uint8_t> original(sz);
        for (size_t i = 0; i < sz; ++i) {
            original[i] = static_cast<uint8_t>((i * 131 + 17) & 0xFF);
        }
        {
            std::ofstream out(plainPath, std::ios::binary);
            if (!original.empty()) {
                out.write(reinterpret_cast<const char*>(original.data()),
                          static_cast<std::streamsize>(original.size()));
            }
        }

        EXPECT_TRUE(CryptoEngine::EncryptFileSM4(plainPath.string(), cipherPath.string()),
                    "EncryptFileSM4 succeeds for size=" + std::to_string(sz));

        // 兼容格式校验：[ 16B IV | PKCS7 填充后 16B 倍数密文 ]
        const size_t expectedCipherSize = 16 + ((sz / 16) + 1) * 16;
        EXPECT_TRUE(fs::file_size(cipherPath) == expectedCipherSize,
                    "Cipher size matches [16B IV + PKCS7 ciphertext] for size=" + std::to_string(sz));

        EXPECT_TRUE(CryptoEngine::DecryptFileSM4(cipherPath.string(), decPath.string()),
                    "DecryptFileSM4 succeeds for size=" + std::to_string(sz));

        std::ifstream in(decPath, std::ios::binary);
        std::vector<uint8_t> restored((std::istreambuf_iterator<char>(in)),
                                      std::istreambuf_iterator<char>());
        EXPECT_TRUE(restored == original, "Roundtrip bytes match for size=" + std::to_string(sz));
    }

    // 校验非16字节对齐的损坏密文被安全拒绝
    const fs::path badLenCipher = tmpDir / "bad_len.cipher";
    {
        std::ofstream out(badLenCipher, std::ios::binary);
        std::vector<uint8_t> bad(16 + 17, 0xAB); // IV + 非16倍数密文
        out.write(reinterpret_cast<const char*>(bad.data()), static_cast<std::streamsize>(bad.size()));
    }
    const fs::path badOut = tmpDir / "bad_out.bin";
    EXPECT_TRUE(!CryptoEngine::DecryptFileSM4(badLenCipher.string(), badOut.string()),
                "DecryptFileSM4 rejects unaligned ciphertext length");

    fs::remove_all(tmpDir, ec);
}

void TestSm4StreamingMemoryBound() {
    const fs::path tmpDir = fs::temp_directory_path() / "es_test_crypto_stream_mem";
    std::error_code ec;
    fs::remove_all(tmpDir, ec);
    fs::create_directories(tmpDir, ec);

    const fs::path plainPath = tmpDir / "big_16mb.bin";
    const fs::path cipherPath = tmpDir / "big_16mb.cipher";
    const fs::path decPath = tmpDir / "big_16mb.dec";

    // 写入 16MB 数据（避免用内存大 vector 常驻，流式写盘）
    {
        std::vector<uint8_t> block(64 * 1024, 0x5C);
        std::ofstream out(plainPath, std::ios::binary);
        for (int i = 0; i < 256; ++i) {
            out.write(reinterpret_cast<const char*>(block.data()), static_cast<std::streamsize>(block.size()));
        }
    }

    std::array<uint8_t, 16> salt{};
    salt.fill(0x7D);
    CryptoEngine::DeriveKeySM3PBKDF2("stream_mem_pass", salt, 1000);

    const MemoryStats memBefore = SystemMonitor::GetMemoryStats();
    EXPECT_TRUE(CryptoEngine::EncryptFileSM4(plainPath.string(), cipherPath.string()),
                "16MB streaming encrypt succeeds");
    EXPECT_TRUE(CryptoEngine::DecryptFileSM4(cipherPath.string(), decPath.string()),
                "16MB streaming decrypt succeeds");
    const MemoryStats memAfter = SystemMonitor::GetMemoryStats();

    EXPECT_TRUE(CryptoEngine::ComputeFileSM3(decPath.string()) ==
                CryptoEngine::ComputeFileSM3(plainPath.string()),
                "16MB streaming decrypt SM3 matches original");

    if (memBefore.IsValid() && memAfter.IsValid()) {
        const double peakDeltaMB = memAfter.peakRssMB - memBefore.peakRssMB;
        // 旧全量读入方案会分配 2x16MB=32MB+ 内存；64KB 流式方案增量应远小于 8MB
        EXPECT_TRUE(peakDeltaMB < 8.0,
                    "16MB SM4 encrypt/decrypt must keep peak RSS delta < 8MB (actual=" +
                    std::to_string(peakDeltaMB) + " MB)");
    }

    fs::remove_all(tmpDir, ec);
}

} // namespace

int main() {
    TestTrapdoorRequiresKey();
    TestHmacSm3AndDomainSeparation();
    TestSm4EncryptDecryptStillWorksWithSeparatedKey();
    TestSm4StreamingBoundarySizes();
    TestSm4StreamingMemoryBound();

    if (g_failures > 0) {
        std::cerr << g_failures << " assertion(s) failed." << std::endl;
        return 1;
    }
    std::cout << "All CryptoEngine tests passed!" << std::endl;
    return 0;
}
