/**
 * @file IndexStructs.hpp
 * @brief 索引相关的 POD 结构体定义，用于磁盘持久化
 * @author Antigravity
 * @date 2026-04-22
 */

#ifndef ENCRYPTEDSEARCH_INDEXSTRUCTS_HPP
#define ENCRYPTEDSEARCH_INDEXSTRUCTS_HPP

#include <cstdint>

/**
 * ──────────────────────────────────────────────────────────
 *  所有跨模块共享的纯 POD 结构体（无线程依赖）
 *  Searcher / Indexer / ParallelHasher 均可安全引用此文件
 * ──────────────────────────────────────────────────────────
 */

#pragma pack(push, 1)

/**
 * @struct IndexHeader
 * @brief 索引文件头结构 (48 bytes)
 */
struct IndexHeader {
    uint32_t magic      = 0x58495345; ///< 魔数，ASCII "ESIX"
    uint32_t version    = 2;          ///< 版本号
    uint64_t keywordCount = 0;        ///< 索引中的关键词总数
    uint64_t docCount   = 0;          ///< 文档总数
    uint8_t  salt[16]   = {0};        ///< PBKDF2 盐值
    uint32_t iterations = 0;          ///< PBKDF2 迭代次数
    uint8_t  reserved[4] = {0};       ///< 预留字段
};

/**
 * @struct DictionaryEntry
 * @brief 词典区条目：存储哈希值及对应倒排列表的偏移量
 */
struct DictionaryEntry {
    uint8_t  hash[32]; ///< SM3 哈希值 (32 bytes)
    uint64_t offset;   ///< 倒排列表在文件中的字节偏移
};

/**
 * @struct Posting
 * @brief 倒排列表记录：文档ID + TF (Term Frequency)
 */
struct Posting {
    uint32_t docId;    ///< 文档唯一标识符
    float    tf;       ///< 词频，用于 TF-IDF 计算
};

#pragma pack(pop)

#endif // ENCRYPTEDSEARCH_INDEXSTRUCTS_HPP
