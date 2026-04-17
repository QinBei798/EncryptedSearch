#ifndef ENCRYPTEDSEARCH_CRYPTOENGINE_HPP
#define ENCRYPTEDSEARCH_CRYPTOENGINE_HPP

#include <array>    // For std::array
#include <string>   // For std::string
#include <cstdint>  // For uint8_t
#include <fstream>  // For file handling

// 声明 CryptoEngine 类
class CryptoEngine {
public:
    // 计算关键词的 SM3 哈希值 (32字节)
    static std::array<uint8_t, 32> ComputeSM3(const std::string& keyword);

    // 新增 PBKDF2 派生密钥
    static void DeriveKeySM3PBKDF2(const std::string& password, const std::array<uint8_t, 16>& salt, uint32_t iterations);

    // 检查是否已有密钥
    static bool HasKey();


    // 辅助函数：将哈希转为十六进制字符串（方便调试打印）
    static std::string ToHex(const std::array<uint8_t, 32>& data);

    // 计算文件内容的 SM3 哈希值
    static std::array<uint8_t, 32> ComputeFileSM3(const std::string& filePath);

    // 使用 SM4-CBC 模式加密文件内容
    static bool EncryptFileSM4(const std::string& inputFilePath, const std::string& outputFilePath);

    // 使用 SM4-CBC 模式解密文件内容
    static bool DecryptFileSM4(const std::string& encryptedFilePath, const std::string& outputFilePath);
};

#endif // ENCRYPTEDSEARCH_CRYPTOENGINE_HPP