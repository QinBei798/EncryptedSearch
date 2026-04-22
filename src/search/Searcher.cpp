/**
 * @file Searcher.cpp
 * @brief Searcher 类的实现，提供索引检索、TF-IDF 评分及布尔搜索功能
 * @author Antigravity
 * @date 2026-04-22
 */

#include "search/Searcher.hpp"
#include "core/CryptoEngine.hpp"
#include <iostream>
#include <algorithm>
#include <cstring>
#include <cmath>
#include <vector>
#include <array>
#include <fstream>
#include <string>

Searcher::Searcher() {}

Searcher::~Searcher() {
    if (m_indexFileStream.is_open()) {
        m_indexFileStream.close();
    }
}

bool Searcher::LoadFileMap(const std::string& mapPath) {
    std::ifstream in(mapPath, std::ios::binary);
    if (!in) {
        std::cerr << "错误: 无法打开映射文件: " << mapPath << std::endl;
        return false;
    }

    m_fileMap.clear();

    uint32_t docId;
    uint32_t pathLen;
    while (in.read(reinterpret_cast<char*>(&docId), sizeof(uint32_t))) {
        if (!in.read(reinterpret_cast<char*>(&pathLen), sizeof(uint32_t))) return false;
        
        std::string path(pathLen, '\0');
        if (!in.read(&path[0], pathLen)) return false;
        
        m_fileMap[docId] = path;
    }

    std::cout << "已成功加载文件映射，共包含 " << m_fileMap.size() << " 条记录。" << std::endl;
    return true;
}

bool Searcher::LoadIndex(const std::string& indexPath) {
    m_indexFileStream.open(indexPath, std::ios::binary);
    if (!m_indexFileStream) {
        std::cerr << "错误: 无法打开索引文件: " << indexPath << std::endl;
        return false;
    }

    // 1. 读取文件头并验证
    m_indexFileStream.read(reinterpret_cast<char*>(&m_indexHeader), sizeof(IndexHeader));
    if (m_indexFileStream.gcount() != sizeof(IndexHeader) || m_indexHeader.magic != 0x58495345) {
        std::cerr << "错误: 索引文件头无效或版本不匹配。" << std::endl;
        m_indexFileStream.close();
        return false;
    }

    // 2. 加载词典区（用于后续二分查找）
    m_dictionary.resize(m_indexHeader.keywordCount);
    m_indexFileStream.read(reinterpret_cast<char*>(m_dictionary.data()), m_indexHeader.keywordCount * sizeof(DictionaryEntry));
    
    std::cout << "已加载索引: " << m_indexHeader.keywordCount << " 个关键词, " << m_indexHeader.docCount << " 个文档。" << std::endl;
    return true;
}

/**
 * @struct HashComparator
 * @brief 哈希值比较器，用于在词典数组中进行二分查找
 */
struct HashComparator {
    bool operator()(const DictionaryEntry& entry, const std::array<uint8_t, 32>& hash) const {
        return std::memcmp(entry.hash, hash.data(), 32) < 0;
    }
    bool operator()(const std::array<uint8_t, 32>& hash, const DictionaryEntry& entry) const {
        return std::memcmp(hash.data(), entry.hash, 32) < 0;
    }
};

std::vector<DictionaryEntry>::const_iterator Searcher::binarySearchDictionary(const std::array<uint8_t, 32>& targetHash) const {
    auto it = std::lower_bound(m_dictionary.begin(), m_dictionary.end(), targetHash, HashComparator());
    if (it != m_dictionary.end() && std::memcmp(it->hash, targetHash.data(), 32) == 0) {
        return it;
    }
    return m_dictionary.end();
}

std::vector<std::pair<std::string, float>> Searcher::Search(const std::string& keyword) {
    std::vector<std::pair<std::string, float>> results;

    if (!m_indexFileStream.is_open() || m_fileMap.empty()) return results;

    // 1. 关键词转小写并计算哈希
    std::string lowerKeyword = keyword;
    for (char& c : lowerKeyword) if (c >= 'A' && c <= 'Z') c += 32;
    std::array<uint8_t, 32> keywordHash = CryptoEngine::ComputeSM3(lowerKeyword);

    // 2. 词典检索
    auto it = binarySearchDictionary(keywordHash);
    if (it == m_dictionary.end()) return results;

    // 3. 读取倒排列表
    m_indexFileStream.clear();
    m_indexFileStream.seekg(it->offset, std::ios::beg);

    uint32_t docIdCount;
    m_indexFileStream.read(reinterpret_cast<char*>(&docIdCount), sizeof(uint32_t));

    std::vector<Posting> postings(docIdCount);
    m_indexFileStream.read(reinterpret_cast<char*>(postings.data()), docIdCount * sizeof(Posting));

    // 4. 计算 TF-IDF 权重
    // IDF 计算采用平滑策略: log(N / (df + 1)) + 1
    float idf = std::log(static_cast<float>(m_indexHeader.docCount) / static_cast<float>(docIdCount + 1)) + 1.0f;

    for (const auto& p : postings) {
        auto mapIt = m_fileMap.find(p.docId);
        if (mapIt != m_fileMap.end()) {
            results.push_back({mapIt->second, p.tf * idf});
        }
    }

    // 5. 按相关性得分降序排列
    std::sort(results.begin(), results.end(), [](const auto& a, const auto& b) {
        return a.second > b.second;
    });

    return results;
}

// --- 布尔搜索相关辅助实现 ---

Searcher::ScoredPostings Searcher::GetPostingList(const std::string& keyword) {
    ScoredPostings result;
    if (!m_indexFileStream.is_open()) return result;

    std::string lowerKeyword = keyword;
    for (char& c : lowerKeyword) if (c >= 'A' && c <= 'Z') c += 32;
    std::array<uint8_t, 32> keywordHash = CryptoEngine::ComputeSM3(lowerKeyword);

    auto it = binarySearchDictionary(keywordHash);
    if (it == m_dictionary.end()) return result;

    m_indexFileStream.clear();
    m_indexFileStream.seekg(static_cast<std::streamoff>(it->offset), std::ios::beg);

    uint32_t docIdCount = 0;
    m_indexFileStream.read(reinterpret_cast<char*>(&docIdCount), sizeof(uint32_t));

    std::vector<Posting> postings(docIdCount);
    m_indexFileStream.read(reinterpret_cast<char*>(postings.data()), docIdCount * sizeof(Posting));

    float idf = std::log(static_cast<float>(m_indexHeader.docCount) / static_cast<float>(docIdCount + 1)) + 1.0f;
    for (const auto& p : postings) result.push_back({p.docId, p.tf * idf});

    return result;
}

Searcher::ScoredPostings Searcher::IntersectPostings(const ScoredPostings& a, const ScoredPostings& b) {
    ScoredPostings result;
    size_t i = 0, j = 0;
    while (i < a.size() && j < b.size()) {
        if (a[i].first == b[j].first) {
            result.push_back({a[i].first, a[i].second + b[j].second});
            ++i; ++j;
        } else if (a[i].first < b[j].first) ++i;
        else ++j;
    }
    return result;
}

Searcher::ScoredPostings Searcher::UnionPostings(const ScoredPostings& a, const ScoredPostings& b) {
    ScoredPostings result;
    size_t i = 0, j = 0;
    while (i < a.size() && j < b.size()) {
        if (a[i].first == b[j].first) {
            result.push_back({a[i].first, std::max(a[i].second, b[j].second)});
            ++i; ++j;
        } else if (a[i].first < b[j].first) result.push_back(a[i++]);
        else result.push_back(b[j++]);
    }
    while (i < a.size()) result.push_back(a[i++]);
    while (j < b.size()) result.push_back(b[j++]);
    return result;
}

Searcher::ScoredPostings Searcher::DifferencePostings(const ScoredPostings& a, const ScoredPostings& b) {
    ScoredPostings result;
    size_t i = 0, j = 0;
    while (i < a.size()) {
        while (j < b.size() && b[j].first < a[i].first) ++j;
        if (j >= b.size() || b[j].first != a[i].first) result.push_back(a[i]);
        ++i;
    }
    return result;
}

Searcher::ScoredPostings Searcher::EvaluateQuery(const std::shared_ptr<QueryNode>& node) {
    if (!node) return {};
    switch (node->op) {
        case QueryOp::TERM: return GetPostingList(node->term);
        case QueryOp::AND: {
            // 特殊处理含有 NOT 的情况 (A AND NOT B)
            if (node->right && node->right->op == QueryOp::NOT) {
                return DifferencePostings(EvaluateQuery(node->left), EvaluateQuery(node->right->right));
            }
            if (node->left && node->left->op == QueryOp::NOT) {
                return DifferencePostings(EvaluateQuery(node->right), EvaluateQuery(node->left->right));
            }
            return IntersectPostings(EvaluateQuery(node->left), EvaluateQuery(node->right));
        }
        case QueryOp::OR: return UnionPostings(EvaluateQuery(node->left), EvaluateQuery(node->right));
        case QueryOp::NOT: return {}; // 不应作为根出现
    }
    return {};
}

std::vector<std::pair<std::string, float>> Searcher::BooleanSearch(const std::string& query) {
    auto queryTree = QueryParser::Parse(query);
    if (!queryTree) return {};

    auto scoredPostings = EvaluateQuery(queryTree);

    // 聚合后按总得分降序
    std::sort(scoredPostings.begin(), scoredPostings.end(), [](const auto& a, const auto& b) {
        return a.second > b.second;
    });

    std::vector<std::pair<std::string, float>> results;
    for (const auto& [docId, score] : scoredPostings) {
        auto it = m_fileMap.find(docId);
        if (it != m_fileMap.end()) results.push_back({it->second, score});
    }
    return results;
}
