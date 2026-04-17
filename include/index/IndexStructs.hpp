#ifndef ENCRYPTEDSEARCH_INDEXSTRUCTS_HPP
#define ENCRYPTEDSEARCH_INDEXSTRUCTS_HPP

#include <cstdint>

// ──────────────────────────────────────────────────────────
//  所有跨模块共享的纯 POD 结构体（无线程依赖）
//  Searcher / Indexer / ParallelHasher 均可安全 include 此文件
// ──────────────────────────────────────────────────────────

#pragma pack(push, 1)

// 索引文件头 (48 bytes)
struct IndexHeader {
    uint32_t magic      = 0x58495345; // ASCII "ESIX"
    uint32_t version    = 2;
    uint64_t keywordCount = 0;
    uint64_t docCount   = 0;
    uint8_t  salt[16]   = {0};        // PBKDF2 salt
    uint32_t iterations = 0;          // PBKDF2 iteration count
    uint8_t  reserved[4] = {0};
};

// 词典区条目：哈希值 + Posting List 偏移量
struct DictionaryEntry {
    uint8_t  hash[32]; // SM3 哈希值 (32 bytes)
    uint64_t offset;   // Posting List 在文件中的字节偏移
};

// 倒排列表单条记录：文档ID + TF值
struct Posting {
    uint32_t docId;
    float    tf;
};

#pragma pack(pop)

#endif // ENCRYPTEDSEARCH_INDEXSTRUCTS_HPP
