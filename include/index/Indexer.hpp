#ifndef ENCRYPTEDSEARCH_INDEXER_HPP
#define ENCRYPTEDSEARCH_INDEXER_HPP

#include <index/ParallelHasher.hpp>
#include <map>
#include <vector>
#include <string>
#include <cstdint>

// 1字节对齐，确保磁盘存储与内存结构体完全一致
#pragma pack(push, 1)
struct IndexHeader {
    uint32_t magic = 0x58495345; // "ESIX"
    uint32_t version = 2;
    uint64_t keywordCount = 0;
    uint64_t docCount = 0;
    uint8_t salt[16] = {0};
    uint32_t iterations = 0;
    uint8_t reserved[4] = {0};
};

struct DictionaryEntry {
    uint8_t hash[32]; // SM3 哈希值
    uint64_t offset;  // 对应 Posting List 在文件中的位置
};
#pragma pack(pop)

class IndexManager {
public:
    // 构造函数，初始化我们之前的并行哈希引擎
    IndexManager(size_t threads = std::thread::hardware_concurrency());

    // 扫描目录并开始异步计算哈希
    void ScanDirectory(const std::string& targetPath);

    // 等待所有哈希算完，并写入二进制索引文件
    void SaveToIndex(const std::string& indexPath);

    // 保存文档ID到文件路径的映射
    void SaveFileMap(const std::string& mapPath);

    // 设置密文文件的存储目录
    void SetCipherDir(const std::string& cipherDir);

    // 设置 PBKDF2 参数，用于保存到索引文件头
    void SetCryptoParams(const std::array<uint8_t, 16>& salt, uint32_t iterations);

private:
    ParallelHasher m_hasher;
    
    // 文件路径到 ID 的映射（高性能检索的核心：用 ID 代替字符串路径）
    std::map<uint32_t, std::string> m_fileMap;    // ID -> Path
    std::map<std::string, uint32_t> m_pathToId;   // Path -> ID
    uint32_t m_nextFileId = 0;

    // 密文保险箱存储路径
    std::string m_cipherDir;

    // 存储给索引头的加解密参数
    std::array<uint8_t, 16> m_salt = {0};
    uint32_t m_iterations = 0;
};

#endif