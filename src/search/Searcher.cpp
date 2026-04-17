#include <search/Searcher.hpp>
#include <core/CryptoEngine.hpp>
#include <iostream>
#include <algorithm> // For std::lower_bound, std::sort
#include <cstring>   // For std::memcmp
#include <cmath>     // For std::log

Searcher::Searcher() {}

Searcher::~Searcher() {
    if (m_indexFileStream.is_open()) {
        m_indexFileStream.close();
    }
}

bool Searcher::LoadFileMap(const std::string& mapPath) {
    std::ifstream in(mapPath, std::ios::binary);
    if (!in) {
        std::cerr << "Error: Could not open file map for reading: " << mapPath << std::endl;
        return false;
    }

    m_fileMap.clear(); // 清空旧数据

    uint32_t docId;
    uint32_t pathLen;
    while (in.read(reinterpret_cast<char*>(&docId), sizeof(uint32_t))) {
        if (!in.read(reinterpret_cast<char*>(&pathLen), sizeof(uint32_t))) {
            std::cerr << "Error: Failed to read path length from file map." << std::endl;
            return false;
        }
        std::string path(pathLen, '\0');
        if (!in.read(&path[0], pathLen)) { // C++11 std::string 保证连续存储
            std::cerr << "Error: Failed to read path string from file map." << std::endl;
            return false;
        }
        m_fileMap[docId] = path;
    }

    std::cout << "Successfully loaded " << m_fileMap.size() << " entries from file map: " << mapPath << std::endl;
    return true;
}

bool Searcher::LoadIndex(const std::string& indexPath) {
    m_indexFileStream.open(indexPath, std::ios::binary);
    if (!m_indexFileStream) {
        std::cerr << "Error: Could not open index file for reading: " << indexPath << std::endl;
        return false;
    }

    // 1. 读取文件头
    m_indexFileStream.read(reinterpret_cast<char*>(&m_indexHeader), sizeof(IndexHeader));
    if (m_indexFileStream.gcount() != sizeof(IndexHeader) || m_indexHeader.magic != 0x58495345) {
        std::cerr << "Error: Invalid index file header or magic number." << std::endl;
        m_indexFileStream.close();
        return false;
    }

    // 2. 读取词典区到内存
    m_dictionary.resize(m_indexHeader.keywordCount);
    m_indexFileStream.read(reinterpret_cast<char*>(m_dictionary.data()), m_indexHeader.keywordCount * sizeof(DictionaryEntry));
    if (m_indexFileStream.gcount() != m_indexHeader.keywordCount * sizeof(DictionaryEntry)) {
        std::cerr << "Error: Failed to read full dictionary from index file." << std::endl;
        m_indexFileStream.close();
        return false;
    }

    std::cout << "Successfully loaded index with " << m_indexHeader.keywordCount << " keywords and " << m_indexHeader.docCount << " documents." << std::endl;
    return true;
}

// 自定义比较器用于 std::lower_bound
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

    // 检查是否找到，并且找到的哈希值是否与目标哈希值相等
    if (it != m_dictionary.end() && std::memcmp(it->hash, targetHash.data(), 32) == 0) {
        return it;
    }
    return m_dictionary.end(); // 未找到
}

std::vector<std::pair<std::string, float>> Searcher::Search(const std::string& keyword) {
    std::vector<std::pair<std::string, float>> results;

    if (!m_indexFileStream.is_open()) {
        std::cerr << "Error: Index not loaded. Call LoadIndex() first." << std::endl;
        return results;
    }
    if (m_fileMap.empty()) {
        std::cerr << "Error: File map not loaded. Call LoadFileMap() first." << std::endl;
        return results;
    }

    // 1. 搜索关键词统一转小写
    std::string lowerKeyword = keyword;
    for (char& c : lowerKeyword) {
        if (c >= 'A' && c <= 'Z') c += 32;
    }
    std::array<uint8_t, 32> keywordHash = CryptoEngine::ComputeSM3(lowerKeyword);

    // 2. 在内存中的词典区进行二分查找
    auto it = binarySearchDictionary(keywordHash);

    if (it == m_dictionary.end()) {
        // std::cout << "Keyword '" << keyword << "' not found in index." << std::endl;
        return results; // 关键词未找到
    }

    // 3. 定位到倒排列表并读取
    uint64_t postingListOffset = it->offset;
    
    // 确保 seekg 在读写之间刷新，并处理错误
    m_indexFileStream.clear(); // 清除可能存在的EOF或其他错误标志
    m_indexFileStream.seekg(postingListOffset, std::ios::beg);
    if (m_indexFileStream.fail()) {
        std::cerr << "Error: seekg to offset " << postingListOffset << " failed." << std::endl;
        return results;
    }

    uint32_t docIdCount;
    m_indexFileStream.read(reinterpret_cast<char*>(&docIdCount), sizeof(uint32_t));
    if (m_indexFileStream.gcount() != sizeof(uint32_t)) {
        std::cerr << "Error: Failed to read docId count at offset " << postingListOffset << std::endl;
        return results;
    }

    std::vector<Posting> postings(docIdCount);
    m_indexFileStream.read(reinterpret_cast<char*>(postings.data()), docIdCount * sizeof(Posting));
    if (m_indexFileStream.gcount() != docIdCount * sizeof(Posting)) {
        std::cerr << "Error: Failed to read full docId list at offset " << postingListOffset << std::endl;
        return results;
    }

    // Phase 5: 计算 IDF
    // 使用平滑的 IDF: log(总文档数 / (包含该词的文档数 + 1)) + 1.0f
    float idf = std::log(static_cast<float>(m_indexHeader.docCount) / static_cast<float>(docIdCount + 1)) + 1.0f;

    // 4. 计算 TF-IDF 将 docId 转换为文件路径
    for (const auto& p : postings) {
        auto mapIt = m_fileMap.find(p.docId);
        if (mapIt != m_fileMap.end()) {
            float score = p.tf * idf;
            results.push_back({mapIt->second, score});
        } else {
            std::cerr << "Warning: DocId " << p.docId << " found in index but not in file map." << std::endl;
        }
    }

    // 5. 按 TF-IDF 得分降序排序
    std::sort(results.begin(), results.end(), [](const std::pair<std::string, float>& a, const std::pair<std::string, float>& b) {
        return a.second > b.second; // 降序
    });

    return results;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Phase 6 — 布尔搜索实现
// ─────────────────────────────────────────────────────────────────────────────

// 根据单个关键词查倒排索引，返回按 docId 升序排列的 (docId, tfidf_score) 列表
Searcher::ScoredPostings Searcher::GetPostingList(const std::string& keyword) {
    ScoredPostings result;

    if (!m_indexFileStream.is_open()) return result;

    // 前处理：搜索关键词统一转小写（与并行哈希时保持一致）
    std::string lowerKeyword = keyword;
    for (char& c : lowerKeyword) {
        if (c >= 'A' && c <= 'Z') c += 32;
    }

    // 1. 哈希关键词
    std::array<uint8_t, 32> keywordHash = CryptoEngine::ComputeSM3(lowerKeyword);

    // 2. 词典二分查找
    auto it = binarySearchDictionary(keywordHash);
    if (it == m_dictionary.end()) return result;

    // 3. 定位并读取 Posting List
    m_indexFileStream.clear();
    m_indexFileStream.seekg(static_cast<std::streamoff>(it->offset), std::ios::beg);
    if (m_indexFileStream.fail()) return result;

    uint32_t docIdCount = 0;
    m_indexFileStream.read(reinterpret_cast<char*>(&docIdCount), sizeof(uint32_t));
    if (m_indexFileStream.gcount() != sizeof(uint32_t)) return result;

    std::vector<Posting> postings(docIdCount);
    m_indexFileStream.read(reinterpret_cast<char*>(postings.data()),
                           docIdCount * sizeof(Posting));
    if (m_indexFileStream.gcount() != static_cast<std::streamsize>(docIdCount * sizeof(Posting)))
        return result;

    // 4. 计算 IDF 并生成 TF-IDF ScoredPostings（Indexer 已保证 Posting 按 docId 升序）
    float idf = std::log(static_cast<float>(m_indexHeader.docCount) /
                         static_cast<float>(docIdCount + 1)) + 1.0f;

    result.reserve(docIdCount);
    for (const auto& p : postings) {
        result.push_back({p.docId, p.tf * idf});
    }

    return result;
}

// AND: 双指针交集，score = scoreA + scoreB
Searcher::ScoredPostings Searcher::IntersectPostings(
    const ScoredPostings& a, const ScoredPostings& b)
{
    ScoredPostings result;
    size_t i = 0, j = 0;
    while (i < a.size() && j < b.size()) {
        if (a[i].first == b[j].first) {
            result.push_back({a[i].first, a[i].second + b[j].second});
            ++i; ++j;
        } else if (a[i].first < b[j].first) {
            ++i;
        } else {
            ++j;
        }
    }
    return result;
}

// OR: 归并并集，score = max(scoreA, scoreB)
Searcher::ScoredPostings Searcher::UnionPostings(
    const ScoredPostings& a, const ScoredPostings& b)
{
    ScoredPostings result;
    size_t i = 0, j = 0;
    while (i < a.size() && j < b.size()) {
        if (a[i].first == b[j].first) {
            result.push_back({a[i].first, std::max(a[i].second, b[j].second)});
            ++i; ++j;
        } else if (a[i].first < b[j].first) {
            result.push_back(a[i++]);
        } else {
            result.push_back(b[j++]);
        }
    }
    while (i < a.size()) result.push_back(a[i++]);
    while (j < b.size()) result.push_back(b[j++]);
    return result;
}

// NOT: 双指针差集 A-B，保留 A 的分数
Searcher::ScoredPostings Searcher::DifferencePostings(
    const ScoredPostings& a, const ScoredPostings& b)
{
    ScoredPostings result;
    size_t i = 0, j = 0;
    while (i < a.size()) {
        // 将 j 推进到 b[j].first >= a[i].first
        while (j < b.size() && b[j].first < a[i].first) ++j;

        if (j >= b.size() || b[j].first != a[i].first) {
            result.push_back(a[i]); // a[i] 不在 b 中，保留
        }
        ++i;
    }
    return result;
}

// 递归求值查询树
Searcher::ScoredPostings Searcher::EvaluateQuery(
    const std::shared_ptr<QueryNode>& node)
{
    if (!node) return {};

    switch (node->op) {
        case QueryOp::TERM:
            return GetPostingList(node->term);

        case QueryOp::AND: {
            // 1. 处理 "A AND NOT B" (左正右非)
            if (node->right && node->right->op == QueryOp::NOT && (!node->left || node->left->op != QueryOp::NOT)) {
                auto leftList = EvaluateQuery(node->left);
                auto notList = EvaluateQuery(node->right->right);
                return DifferencePostings(leftList, notList);
            }
            // 2. 处理 "NOT A AND B" (左非右正)
            if (node->left && node->left->op == QueryOp::NOT && (!node->right || node->right->op != QueryOp::NOT)) {
                auto rightList = EvaluateQuery(node->right);
                auto notList = EvaluateQuery(node->left->right);
                return DifferencePostings(rightList, notList);
            }
            // 3. 正常 "A AND B"
            auto leftList = EvaluateQuery(node->left);
            auto rightList = EvaluateQuery(node->right);
            return IntersectPostings(leftList, rightList);
        }

        case QueryOp::OR: {
            auto leftList  = EvaluateQuery(node->left);
            auto rightList = EvaluateQuery(node->right);
            return UnionPostings(leftList, rightList);
        }

        case QueryOp::NOT:
            // NOT 不应作为根节点单独出现
            // 仅在 AND 分支中作为右子节点被特殊处理
            std::cerr << "[Searcher] NOT node cannot appear as root of query tree." << std::endl;
            return {};
    }
    return {};
}

// BooleanSearch 主入口
std::vector<std::pair<std::string, float>> Searcher::BooleanSearch(
    const std::string& query)
{
    // 1. 解析查询字符串为查询树
    auto queryTree = QueryParser::Parse(query);
    if (!queryTree) {
        std::cerr << "[Searcher] Failed to parse boolean query: " << query << std::endl;
        return {};
    }

    // 2. 递归求值，得到 (docId, score) 列表
    auto scoredPostings = EvaluateQuery(queryTree);

    // 3. 按 TF-IDF 聚合分数降序排列
    std::sort(scoredPostings.begin(), scoredPostings.end(),
        [](const std::pair<uint32_t, float>& a, const std::pair<uint32_t, float>& b) {
            return a.second > b.second;
        });

    // 4. 将 docId 映射为文件路径
    std::vector<std::pair<std::string, float>> results;
    results.reserve(scoredPostings.size());
    for (const auto& [docId, score] : scoredPostings) {
        auto it = m_fileMap.find(docId);
        if (it != m_fileMap.end()) {
            results.push_back({it->second, score});
        } else {
            std::cerr << "[Searcher] Warning: DocId " << docId
                      << " not found in file map." << std::endl;
        }
    }
    return results;
}
