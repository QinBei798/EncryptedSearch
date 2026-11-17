/**
 * @file test_crypto_engine.cpp
 * @brief CryptoEngine 密钥分离、HMAC-SM3 盲索引陷门与密码校验指纹单元测试（TDD）
 */

#include "core/CryptoEngine.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
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

} // namespace

int main() {
    TestTrapdoorRequiresKey();
    TestHmacSm3AndDomainSeparation();
    TestSm4EncryptDecryptStillWorksWithSeparatedKey();

    if (g_failures > 0) {
        std::cerr << g_failures << " assertion(s) failed." << std::endl;
        return 1;
    }
    std::cout << "All CryptoEngine tests passed!" << std::endl;
    return 0;
}
