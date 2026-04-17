#ifndef ENCRYPTEDSEARCH_SEARCHER_HPP
#define ENCRYPTEDSEARCH_SEARCHER_HPP

// 预先引入线程相关标准头（MinGW 8.1 include 顺序敏感修复）
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>

#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <array>
#include <cstdint>
#include <core/CryptoEngine.hpp>     // SM3 hashing
#include <index/IndexStructs.hpp>    // IndexHeader, DictionaryEntry, Posting (纯 POD)
#include <search/QueryParser.hpp>    // Phase 6: 查询树


class Searcher {
public:
    Searcher();
    ~Searcher();

    // 从文件加载文档ID到文件路径的映射
    bool LoadFileMap(const std::string& mapPath);

    // 从二进制索引文件加载索引 (Dictionary 部分)
    bool LoadIndex(const std::string& indexPath);

    // 根据关键词进行搜索，返回匹配的文件路径及相关性得分列表（TF-IDF 降序）
    std::vector<std::pair<std::string, float>> Search(const std::string& keyword);

    // Phase 6: 布尔搜索接口
    // 支持: "SM4 AND 国密", "加密 OR 分词", "密码学 AND NOT SM3"
    // 返回: 按 TF-IDF 聚合分数降序排列的 (文件路径, score) 列表
    std::vector<std::pair<std::string, float>> BooleanSearch(const std::string& query);

private:
    // 文档ID到文件路径的映射
    std::map<uint32_t, std::string> m_fileMap;

    // 索引文件流，保持打开状态以供 seekg 使用
    std::ifstream m_indexFileStream;

    // 索引文件头
    IndexHeader m_indexHeader;

    // 词典区：所有 DictionaryEntry 的集合，用于内存中的二分查找
    std::vector<DictionaryEntry> m_dictionary;

    // 辅助函数：在 m_dictionary 中进行二分查找
    std::vector<DictionaryEntry>::const_iterator binarySearchDictionary(
        const std::array<uint8_t, 32>& targetHash) const;

    // ── Phase 6 内部辅助 ──────────────────────────────────────────────────

    // 按 docId 升序排列的 (docId, tfidf_score) 列表
    using ScoredPostings = std::vector<std::pair<uint32_t, float>>;

    // 根据关键词查倒排索引，返回按 docId 升序排列的 TF-IDF 评分列表
    ScoredPostings GetPostingList(const std::string& keyword);

    // AND: 交集，score = scoreA + scoreB（双指针，O(N+M)）
    ScoredPostings IntersectPostings(const ScoredPostings& a, const ScoredPostings& b);

    // OR: 并集，score = max(scoreA, scoreB)（归并，O(N+M)）
    ScoredPostings UnionPostings(const ScoredPostings& a, const ScoredPostings& b);

    // NOT: 差集 A-B，保留 A 的分数（双指针，O(N+M)）
    ScoredPostings DifferencePostings(const ScoredPostings& a, const ScoredPostings& b);

    // 递归求值查询树，返回 ScoredPostings
    ScoredPostings EvaluateQuery(const std::shared_ptr<QueryNode>& node);
};

#endif // ENCRYPTEDSEARCH_SEARCHER_HPP