/**
 * @file Searcher.hpp
 * @brief 搜索器，负责加载索引并执行各类检索请求
 * @author Antigravity
 * @date 2026-04-22
 */

#ifndef ENCRYPTEDSEARCH_SEARCHER_HPP
#define ENCRYPTEDSEARCH_SEARCHER_HPP

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
#include <core/CryptoEngine.hpp>
#include <index/IndexStructs.hpp>
#include <search/QueryParser.hpp>

/**
 * @class Searcher
 * @brief 实现索引加载及关键词/布尔搜索的核心类
 */
class Searcher {
public:
    /**
     * @brief 构造函数
     */
    Searcher();

    /**
     * @brief 析构函数
     */
    ~Searcher();

    /**
     * @brief 加载文档 ID 到路径的映射文件
     * @param mapPath 映射文件路径
     * @return 加载成功返回 true
     */
    bool LoadFileMap(const std::string& mapPath);

    /**
     * @brief 加载二进制索引文件
     * @param indexPath 索引文件路径
     * @return 加载成功返回 true
     */
    bool LoadIndex(const std::string& indexPath);

    /**
     * @brief 执行关键词搜索
     * @param keyword 待查关键词
     * @return 按 TF-IDF 降序排列的 (路径, 得分) 列表
     */
    std::vector<std::pair<std::string, float>> Search(const std::string& keyword);

    /**
     * @brief 执行复杂的布尔逻辑搜索
     * @param query 布尔查询表达式（如 "SM4 AND SM3"）
     * @return 聚合后的搜索结果列表
     */
    std::vector<std::pair<std::string, float>> BooleanSearch(const std::string& query);

private:
    std::map<uint32_t, std::string> m_fileMap;        ///< ID -> 路径 映射
    std::ifstream m_indexFileStream;                  ///< 索引文件流
    IndexHeader m_indexHeader;                        ///< 索引头缓存
    std::vector<DictionaryEntry> m_dictionary;        ///< 内存词典

    /**
     * @brief 在内存词典中进行二分查找
     * @param targetHash 目标关键词的 SM3 哈希值
     * @return 指向匹配项的迭代器
     */
    std::vector<DictionaryEntry>::const_iterator binarySearchDictionary(
        const std::array<uint8_t, 32>& targetHash) const;

    using ScoredPostings = std::vector<std::pair<uint32_t, float>>;

    /**
     * @brief 获取指定关键词的原始评分倒排列表
     */
    ScoredPostings GetPostingList(const std::string& keyword);

    /**
     * @brief 集合操作：交集（AND 逻辑）
     */
    ScoredPostings IntersectPostings(const ScoredPostings& a, const ScoredPostings& b);

    /**
     * @brief 集合操作：并集（OR 逻辑）
     */
    ScoredPostings UnionPostings(const ScoredPostings& a, const ScoredPostings& b);

    /**
     * @brief 集合操作：差集（NOT 逻辑）
     */
    ScoredPostings DifferencePostings(const ScoredPostings& a, const ScoredPostings& b);

    /**
     * @brief 递归计算查询树的值
     */
    ScoredPostings EvaluateQuery(const std::shared_ptr<QueryNode>& node);
};

#endif // ENCRYPTEDSEARCH_SEARCHER_HPP