#include <core/CryptoEngine.hpp> // 引用你的头文件
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <iostream>  // For std::cerr
#include <sstream>
#include <iomanip>
#include <vector>
#include <random>  // For std::random_device, std::uniform_int_distribution

extern "C" {
    #include <gmssl/sm3.h>
    #include <gmssl/sm4.h>
}

// 使用 作用域解析符 :: 来实现成员函数
std::array<uint8_t, 32> CryptoEngine::ComputeSM3(const std::string& keyword) {
    std::array<uint8_t, 32> digest;
    SM3_CTX ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, (const uint8_t*)keyword.c_str(), keyword.length());
    sm3_finish(&ctx, digest.data());
    return digest;
}

// Phase 4: 替换为 PBKDF2-SM3-HMAC 密钥派生，消除硬编码密钥
static uint8_t g_sm4_key[16] = {0};
static bool g_has_key = false;

bool CryptoEngine::HasKey() {
    return g_has_key;
}

void CryptoEngine::DeriveKeySM3PBKDF2(const std::string& password, const std::array<uint8_t, 16>& salt, uint32_t iterations) {
    if (sm3_pbkdf2(password.c_str(), password.length(), salt.data(), salt.size(), iterations, sizeof(g_sm4_key), g_sm4_key) != 1) {
        throw std::runtime_error("PBKDF2 key derivation failed");
    }
    g_has_key = true;
}

// Phase 1: IV 已移除全局常量，改为每次加密时随机生成（见 EncryptFileSM4）

bool CryptoEngine::EncryptFileSM4(const std::string& inputFilePath, const std::string& outputFilePath) {
    // --- 读取原始文件 ---
    std::ifstream in(inputFilePath, std::ios::binary | std::ios::ate);
    if (!in.is_open()) return false;
    std::streamsize size = in.tellg();
    in.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(size);
    if (!in.read(reinterpret_cast<char*>(buffer.data()), size)) return false;
    in.close();

    // --- Phase 1: 生成密码学安全的随机 IV ---
    // 使用 std::random_device（依赖硬件熵源）生成真随机数，避免固定 IV 导致的模式泄露
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

    // SM4 CBC 模式包含 PKCS7 Padding，最大会增加 16 字节
    std::vector<uint8_t> outbuf(size + 16);
    size_t outlen = 0;
    if (sm4_cbc_padding_encrypt(&sm4_key, iv, buffer.data(), size, outbuf.data(), &outlen) != 1) {
        return false;
    }

    // --- 密文文件格式: [ IV(16B) | SM4-CBC 密文(N B) ] ---
    // IV 无需保密（CBC 模式设计），但每次必须唯一，确保相同明文产生不同密文
    std::ofstream out(outputFilePath, std::ios::binary);
    if (!out.is_open()) return false;
    out.write(reinterpret_cast<const char*>(iv), sizeof(iv));          // 前 16B: IV
    out.write(reinterpret_cast<const char*>(outbuf.data()), outlen);   // 后 N B: 密文
    return true;
}

bool CryptoEngine::DecryptFileSM4(const std::string& encryptedFilePath, const std::string& outputFilePath) {
    std::ifstream in(encryptedFilePath, std::ios::binary | std::ios::ate);
    if (!in.is_open()) return false;
    std::streamsize totalSize = in.tellg();

    // 密文文件至少包含 16B IV + 16B 最小密文块，否则文件损坏
    if (totalSize <= 16) {
        std::cerr << "Error: Encrypted file too small (missing IV header): " << encryptedFilePath << std::endl;
        return false;
    }

    in.seekg(0, std::ios::beg);

    // --- Phase 1: 从文件头读取 IV（与加密时写入的格式对应）---
    uint8_t iv[16];
    if (!in.read(reinterpret_cast<char*>(iv), sizeof(iv))) return false;

    // 读取其余的 CBC 密文部分
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

    std::vector<uint8_t> outbuf(cipherSize); // 解密后数据一定 <= 密文大小
    size_t outlen = 0;
    if (sm4_cbc_padding_decrypt(&sm4_key, iv, buffer.data(), cipherSize, outbuf.data(), &outlen) != 1) {
        return false;
    }

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
        // 实际开发应处理异常，例如抛出 std::runtime_error
        throw std::runtime_error("Failed to open file for SM3 hashing: " + filePath);
    }

    // 采用 4KB 缓冲区，这是磁盘 I/O 的黄金尺寸
    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
        sm3_update(&ctx, reinterpret_cast<const uint8_t*>(buffer), file.gcount());
    }
    // 处理最后不足 4KB 的部分
    sm3_update(&ctx, reinterpret_cast<const uint8_t*>(buffer), file.gcount());

    sm3_finish(&ctx, digest.data());
    return digest;
}