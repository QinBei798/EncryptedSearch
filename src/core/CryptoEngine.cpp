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

// 全局静态状态，用于管理派生后的 SM4 密钥
static uint8_t g_sm4_key[16] = {0};
static bool g_has_key = false;

std::array<uint8_t, 32> CryptoEngine::ComputeSM3(const std::string& keyword) {
    std::array<uint8_t, 32> digest;
    SM3_CTX ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, (const uint8_t*)keyword.c_str(), keyword.length());
    sm3_finish(&ctx, digest.data());
    return digest;
}

bool CryptoEngine::HasKey() {
    return g_has_key;
}

void CryptoEngine::DeriveKeySM3PBKDF2(const std::string& password, const std::array<uint8_t, 16>& salt, uint32_t iterations) {
    // 使用 SM3-HMAC 作为伪随机函数的 PBKDF2 密钥派生
    if (sm3_pbkdf2(password.c_str(), password.length(), salt.data(), salt.size(), iterations, sizeof(g_sm4_key), g_sm4_key) != 1) {
        throw std::runtime_error("PBKDF2 key derivation failed");
    }
    g_has_key = true;
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