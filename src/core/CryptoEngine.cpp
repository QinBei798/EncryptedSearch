/**
 * @file CryptoEngine.cpp
 * @brief CryptoEngine 类的实现，集成 GmSSL 国密库
 * @author Antigravity
 * @date 2026-04-22
 */

#include <core/CryptoEngine.hpp>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <random>

extern "C" {
    #include <gmssl/sm3.h>
    #include <gmssl/sm4.h>
}

#include <algorithm>
#include <cstring>
#include <stdexcept>

// 全局静态状态，用于管理派生后的隔离密钥及密码校验指纹
static uint8_t g_sm4_key[16] = {0};
static uint8_t g_index_key[32] = {0};
static uint8_t g_key_verifier[16] = {0};
static bool g_has_key = false;

static void SecureZero(void* ptr, size_t len) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (len--) {
        *p++ = 0;
    }
}

std::array<uint8_t, 32> CryptoEngine::ComputeSM3(const std::string& keyword) {
    std::array<uint8_t, 32> digest;
    SM3_CTX ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, reinterpret_cast<const uint8_t*>(keyword.data()), keyword.length());
    sm3_finish(&ctx, digest.data());
    return digest;
}

bool CryptoEngine::HasKey() {
    return g_has_key;
}

std::array<uint8_t, 32> CryptoEngine::ComputeSM3HMAC(const uint8_t* key, size_t keyLen, const std::string& data) {
    if (!key && keyLen > 0) {
        throw std::invalid_argument("HMAC key buffer is null");
    }
    std::array<uint8_t, 32> mac{};
    SM3_HMAC_CTX ctx;
    sm3_hmac_init(&ctx, key, keyLen);
    if (!data.empty()) {
        sm3_hmac_update(&ctx, reinterpret_cast<const uint8_t*>(data.data()), data.size());
    }
    sm3_hmac_finish(&ctx, mac.data());
    SecureZero(&ctx, sizeof(ctx));
    return mac;
}

std::array<uint8_t, 32> CryptoEngine::ComputeKeywordTrapdoor(const std::string& keyword) {
    if (!g_has_key) {
        throw std::runtime_error("Blind index key has not been derived");
    }
    return ComputeSM3HMAC(g_index_key, sizeof(g_index_key), keyword);
}

std::array<uint8_t, 16> CryptoEngine::GetKeyVerifier() {
    if (!g_has_key) {
        throw std::runtime_error("Key verifier requested before key derivation");
    }
    std::array<uint8_t, 16> verifier{};
    std::memcpy(verifier.data(), g_key_verifier, verifier.size());
    return verifier;
}

bool CryptoEngine::VerifyKeyVerifier(const std::array<uint8_t, 16>& expectedVerifier) {
    if (!g_has_key) {
        return false;
    }
    uint8_t diff = 0;
    for (size_t i = 0; i < expectedVerifier.size(); ++i) {
        diff |= static_cast<uint8_t>(g_key_verifier[i] ^ expectedVerifier[i]);
    }
    return diff == 0;
}

void CryptoEngine::ResetKey() {
    SecureZero(g_sm4_key, sizeof(g_sm4_key));
    SecureZero(g_index_key, sizeof(g_index_key));
    SecureZero(g_key_verifier, sizeof(g_key_verifier));
    g_has_key = false;
}

void CryptoEngine::DeriveKeySM3PBKDF2(const std::string& password, const std::array<uint8_t, 16>& salt, uint32_t iterations) {
    // 1. 使用 SM3-HMAC PBKDF2 派生 32 字节主密钥材料
    std::array<uint8_t, 32> masterKey{};
    if (sm3_pbkdf2(password.c_str(), password.length(),
                   salt.data(), salt.size(), iterations,
                   masterKey.size(), masterKey.data()) != 1) {
        SecureZero(masterKey.data(), masterKey.size());
        throw std::runtime_error("PBKDF2 key derivation failed");
    }

    // 2. 通过域分离标签扩展为独立用途子密钥（文件加密密钥 / 索引陷门密钥 / 密码校验指纹）
    auto encSubKey = ComputeSM3HMAC(masterKey.data(), masterKey.size(), "EncryptedSearch:sm4-file-enc:v3");
    auto idxSubKey = ComputeSM3HMAC(masterKey.data(), masterKey.size(), "EncryptedSearch:sm3-blind-index:v3");
    auto verSubKey = ComputeSM3HMAC(masterKey.data(), masterKey.size(), "EncryptedSearch:key-verifier:v3");

    std::memcpy(g_sm4_key, encSubKey.data(), sizeof(g_sm4_key));
    std::memcpy(g_index_key, idxSubKey.data(), sizeof(g_index_key));
    std::memcpy(g_key_verifier, verSubKey.data(), sizeof(g_key_verifier));
    g_has_key = true;

    SecureZero(masterKey.data(), masterKey.size());
    SecureZero(encSubKey.data(), encSubKey.size());
    SecureZero(idxSubKey.data(), idxSubKey.size());
    SecureZero(verSubKey.data(), verSubKey.size());
}

bool CryptoEngine::EncryptFileSM4(const std::string& inputFilePath, const std::string& outputFilePath) {
    // 1. 读取原始明文文件
    std::ifstream in(inputFilePath, std::ios::binary | std::ios::ate);
    if (!in.is_open()) return false;
    std::streamsize size = in.tellg();
    in.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(size);
    if (!in.read(reinterpret_cast<char*>(buffer.data()), size)) return false;
    in.close();

    // 2. 生成密码学安全的随机 IV (16字节)
    // 每次加密生成不同的 IV 是 CBC 模式安全性的核心要求
    uint8_t iv[16];
    {
        std::random_device rd;
        std::uniform_int_distribution<unsigned int> dist(0, 255);
        for (auto& b : iv) {
            b = static_cast<uint8_t>(dist(rd));
        }
    }

    if (!g_has_key) {
        std::cerr << "Error: SM4 key not derived." << std::endl;
        return false;
    }

    SM4_KEY sm4_key;
    sm4_set_encrypt_key(&sm4_key, g_sm4_key);

    // SM4-CBC 包含 PKCS7 填充，加密后长度可能增加最多 16 字节
    std::vector<uint8_t> outbuf(size + 16);
    size_t outlen = 0;
    if (sm4_cbc_padding_encrypt(&sm4_key, iv, buffer.data(), size, outbuf.data(), &outlen) != 1) {
        return false;
    }

    // 3. 写入密文文件。格式：[ 16B IV | N 字节密文 ]
    std::ofstream out(outputFilePath, std::ios::binary);
    if (!out.is_open()) return false;
    out.write(reinterpret_cast<const char*>(iv), sizeof(iv));
    out.write(reinterpret_cast<const char*>(outbuf.data()), outlen);
    return true;
}

bool CryptoEngine::DecryptFileSM4(const std::string& encryptedFilePath, const std::string& outputFilePath) {
    std::ifstream in(encryptedFilePath, std::ios::binary | std::ios::ate);
    if (!in.is_open()) return false;
    std::streamsize totalSize = in.tellg();

    // 密文文件至少应包含 16B 的 IV 头部
    if (totalSize <= 16) {
        std::cerr << "Error: Encrypted file too small: " << encryptedFilePath << std::endl;
        return false;
    }

    in.seekg(0, std::ios::beg);

    // 1. 读取文件开头的 IV
    uint8_t iv[16];
    if (!in.read(reinterpret_cast<char*>(iv), sizeof(iv))) return false;

    // 2. 读取后续密文内容
    std::streamsize cipherSize = totalSize - 16;
    std::vector<uint8_t> buffer(cipherSize);
    if (!in.read(reinterpret_cast<char*>(buffer.data()), cipherSize)) return false;
    in.close();

    if (!g_has_key) {
        std::cerr << "Error: SM4 key not derived." << std::endl;
        return false;
    }

    SM4_KEY sm4_key;
    sm4_set_decrypt_key(&sm4_key, g_sm4_key);

    std::vector<uint8_t> outbuf(cipherSize);
    size_t outlen = 0;
    if (sm4_cbc_padding_decrypt(&sm4_key, iv, buffer.data(), cipherSize, outbuf.data(), &outlen) != 1) {
        return false;
    }

    // 3. 保存解密后的明文
    std::ofstream out(outputFilePath, std::ios::binary);
    if (!out.is_open()) return false;
    out.write(reinterpret_cast<const char*>(outbuf.data()), outlen);
    return true;
}

std::string CryptoEngine::ToHex(const std::array<uint8_t, 32>& data) {
    static const char hex_table[]="0123456789abcdef";
    std::string res;
    res.reserve(64);
    for(uint8_t b: data){
        res.push_back(hex_table[b>>4]);
        res.push_back(hex_table[b&0x0F]);
    }
    return res;
}

std::array<uint8_t, 32> CryptoEngine::ComputeFileSM3(const std::string& filePath) {
    std::array<uint8_t, 32> digest;
    SM3_CTX ctx;
    sm3_init(&ctx);

    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file for SM3 hashing: " + filePath);
    }

    // 分块读取文件进行哈希计算，平衡内存开销与处理效率
    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
        sm3_update(&ctx, reinterpret_cast<const uint8_t*>(buffer), file.gcount());
    }
    sm3_update(&ctx, reinterpret_cast<const uint8_t*>(buffer), file.gcount());

    sm3_finish(&ctx, digest.data());
    return digest;
}