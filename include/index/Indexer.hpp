/**
 * @file Indexer.hpp
 * @brief 索引管理器，协调目录扫描、并行哈希计算及索引持久化
 * @author Antigravity
 * @date 2026-04-22
 */

#ifndef ENCRYPTEDSEARCH_INDEXER_HPP
#define ENCRYPTEDSEARCH_INDEXER_HPP

#include <index/IndexStructs.hpp>    // POD 结构体
#include <index/ParallelHasher.hpp>  // 并行哈希引擎
#include <map>
#include <vector>
#include <string>
#include <cstdint>

/**
 * @class IndexManager
 * @brief 负责索引的构建流程，包括文件扫描、ID 映射及数据保存
 */
class IndexManager {
public:
    /**
     * @brief 构造函数
     * @param threads 使用的并行线程数，默认取硬件核心数
     */
    IndexManager(size_t threads = std::thread::hardware_concurrency());

    /**
     * @brief 扫描指定目录，并启动异步哈希计算任务
     * @param targetPath 目标文档目录
     */
    void ScanDirectory(const std::string& targetPath);

    /**
     * @brief 等待所有任务完成，并将倒排索引写入二进制文件
     * @param indexPath 索引文件保存路径
     */
    void SaveToIndex(const std::string& indexPath);

    /**
     * @brief 保存文档 ID 到原始路径的映射关系
     * @param mapPath 映射文件保存路径
     */
    void SaveFileMap(const std::string& mapPath);

    /**
     * @brief 设置加密文档的存储目录
     * @param cipherDir 存储路径
     */
    void SetCipherDir(const std::string& cipherDir);

    /**
     * @brief 设置密钥派生参数，这些参数将写入索引文件头
     * @param salt 盐值
     * @param iterations 迭代次数
     */
    void SetCryptoParams(const std::array<uint8_t, 16>& salt, uint32_t iterations);

private:
    ParallelHasher m_hasher; ///< 并行哈希处理器
    
    std::map<uint32_t, std::string> m_fileMap;    ///< ID -> 路径 映射
    std::map<std::string, uint32_t> m_pathToId;   ///< 路径 -> ID 映射
    uint32_t m_nextFileId = 0;                    ///< 下一个可用的文件 ID

    std::string m_cipherDir;                      ///< 密文存储目录

    std::array<uint8_t, 16> m_salt = {0};         ///< 记录的盐值
    uint32_t m_iterations = 0;                    ///< 记录的迭代次数
};

#endif // ENCRYPTEDSEARCH_INDEXER_HPP