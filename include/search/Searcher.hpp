#ifndef ENCRYPTEDSEARCH_SEARCHER_HPP
#define ENCRYPTEDSEARCH_SEARCHER_HPP

#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <array>
#include <cstdint>
#include <core/CryptoEngine.hpp> // For SM3 hashing
#include <index/Indexer.hpp>     // For IndexHeader and DictionaryEntry structs

class Searcher {
public:
    Searcher();
    ~Searcher();

    // 从文件加载文档ID到文件路径的映射
    bool LoadFileMap(const std::string& mapPath);

    // 从二进制索引文件加载索引 (Dictionary 部分)
    bool LoadIndex(const std::string& indexPath);

    // 根据关键词进行搜索，返回匹配的文件路径及相关性得分列表
    std::vector<std::pair<std::string, float>> Search(const std::string& keyword);

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
    // 返回指向找到的 DictionaryEntry 的迭代器，如果未找到则返回 m_dictionary.end()
    std::vector<DictionaryEntry>::const_iterator binarySearchDictionary(const std::array<uint8_t, 32>& targetHash) const;
};

#endif // ENCRYPTEDSEARCH_SEARCHER_HPP