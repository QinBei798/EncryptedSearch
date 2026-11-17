/**
 * @file CryptoEngine.hpp
 * @brief 国密算法加密引擎，提供 SM3 哈希计算及 SM4 加解密功能
 * @author Antigravity
 * @date 2026-04-22
 */

#ifndef ENCRYPTEDSEARCH_CRYPTOENGINE_HPP
#define ENCRYPTEDSEARCH_CRYPTOENGINE_HPP

#include <array>    // For std::array
#include <string>   // For std::string
#include <cstdint>  // For uint8_t
#include <fstream>  // For file handling

/**
 * @class CryptoEngine
 * @brief 封装了基于 GmSSL 的国密算法操作
 */
class CryptoEngine {
public:
    /**
     * @brief 计算关键词的 SM3 哈希值（无密钥摘要）
     * @param keyword 待计算的关键词字符串
     * @return 32字节的哈希值
     */
    static std::array<uint8_t, 32> ComputeSM3(const std::string& keyword);

    /**
     * @brief 计算指定密钥与数据的 HMAC-SM3 值
     * @param key 密钥缓冲区
     * @param keyLen 密钥字节长度
     * @param data 输入数据
     * @return 32字节 HMAC-SM3 摘要
     */
    static std::array<uint8_t, 32> ComputeSM3HMAC(const uint8_t* key, size_t keyLen, const std::string& data);

    /**
     * @brief 计算关键词的带密钥盲索引陷门 (HMAC-SM3)
     * @param keyword 待计算陷门的关键词
     * @return 32字节陷门值；若未派生密钥将抛出 std::runtime_error
     */
    static std::array<uint8_t, 32> ComputeKeywordTrapdoor(const std::string& keyword);

    /**
     * @brief 使用 PBKDF2-SM3-HMAC 从主密码派生独立的加密密钥、索引陷门密钥及密码校验指纹
     * @param password 用户输入的原始密码
     * @param salt 盐值
     * @param iterations 迭代次数
     */
    static void DeriveKeySM3PBKDF2(const std::string& password, const std::array<uint8_t, 16>& salt, uint32_t iterations);

    /**
     * @brief 获取当前派生密钥对应的 16 字节校验指纹（用于验证索引加载时的主密码正误）
     */
    static std::array<uint8_t, 16> GetKeyVerifier();

    /**
     * @brief 以常量时间比较验证当前派生密钥是否与预期校验指纹一致
     */
    static bool VerifyKeyVerifier(const std::array<uint8_t, 16>& expectedVerifier);

    /**
     * @brief 清除内存中缓存的派生密钥
     */
    static void ResetKey();

    /**
     * @brief 检查系统是否已成功派生出密钥
     * @return 如果密钥已就绪返回 true，否则返回 false
     */
    static bool HasKey();

    /**
     * @brief 辅助函数：将字节数据转换为十六进制字符串
     * @param data 32字节的二进制数据
     * @return 十六进制表示的字符串
     */
    static std::string ToHex(const std::array<uint8_t, 32>& data);

    /**
     * @brief 计算文件的 SM3 哈希值
     * @param filePath 目标文件路径
     * @return 文件的 32 字节哈希摘要
     */
    static std::array<uint8_t, 32> ComputeFileSM3(const std::string& filePath);

    /**
     * @brief 使用 SM4-CBC 模式加密文件
     * @param inputFilePath 原始文件路径
     * @param outputFilePath 加密后的输出文件路径
     * @return 加密成功返回 true，否则返回 false
     */
    static bool EncryptFileSM4(const std::string& inputFilePath, const std::string& outputFilePath);

    /**
     * @brief 使用 SM4-CBC 模式解密文件
     * @param encryptedFilePath 加密后的文件路径
     * @param outputFilePath 解密后的输出文件路径
     * @return 解密成功返回 true，否则返回 false
     */
    static bool DecryptFileSM4(const std::string& encryptedFilePath, const std::string& outputFilePath);
};

#endif // ENCRYPTEDSEARCH_CRYPTOENGINE_HPP