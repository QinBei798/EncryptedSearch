/**
 * @file Indexer.cpp
 * @brief IndexManager 类的实现，管理索引构建全流程
 * @author Antigravity
 * @date 2026-04-22
 */

#include <iostream>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <index/Indexer.hpp>
#include <core/CryptoEngine.hpp>

namespace fs = std::filesystem;

IndexManager::IndexManager(size_t threads) : m_hasher(threads) {}

void IndexManager::ScanDirectory(const std::string& targetPath) {
    std::cout << "正在扫描目录: " << targetPath << "..." << std::endl;
    
    size_t fileCount = 0;
    try {
        for (const auto& entry : fs::recursive_directory_iterator(targetPath)) {
            if (entry.is_regular_file()) {
                std::string path = entry.path().string();
                
                // 1. 建立文件路径与文档 ID 的双向映射
                uint32_t docId = m_nextFileId++;
                m_fileMap[docId] = path;
                m_pathToId[path] = docId;
                
                // 2. 提交异步处理任务
                // ParallelHasher 将在后台线程处理文件读取、分词及哈希计算
                m_hasher.AddTask(path, docId);

                // 3. 将原文件同步加密并保存至密文存储区
                if (!m_cipherDir.empty()) {
                    std::string cipherPath = m_cipherDir + "/" + std::to_string(docId) + ".cipher";
                    if (!CryptoEngine::EncryptFileSM4(path, cipherPath)) {
                        std::cerr << "警告: 文件加密失败: " << path << std::endl;
                    }
                }

                fileCount++;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "扫描异常: " << e.what() << std::endl;
    }

    std::cout << "已提交 " << fileCount << " 个文件任务。分配 ID 范围: 0 至 " << (m_nextFileId - 1) << std::endl;
}

void IndexManager::SaveToIndex(const std::string& indexPath) {
    // 1. 获取所有并行的哈希计算结果
    auto hashResults = m_hasher.GetResults(); 
    
    std::ofstream out(indexPath, std::ios::binary);
    if (!out) {
        std::cerr << "错误: 无法打开索引文件进行写入: " << indexPath << std::endl;
        return;
    }

    // 2. 构造并写入文件头
    IndexHeader header;
    header.keywordCount = hashResults.size();
    header.docCount = m_fileMap.size();
    std::copy(m_salt.begin(), m_salt.end(), header.salt);
    header.iterations = m_iterations;
    out.write(reinterpret_cast<const char*>(&header), sizeof(IndexHeader));

    // 3. 计算起始偏移量（跳过文件头和固定长度的词典区）
    uint64_t currentPostingOffset = sizeof(IndexHeader) + (header.keywordCount * sizeof(DictionaryEntry));
    
    std::vector<DictionaryEntry> dictionary;
    std::vector<std::vector<Posting>> postingLists;

    // 4. 汇总词典信息并为每个关键词分配倒排列表偏移量
    for (auto& [hash, postings] : hashResults) {
        DictionaryEntry entry;
        std::copy(hash.begin(), hash.end(), entry.hash);
        entry.offset = currentPostingOffset;
        dictionary.push_back(entry);

        // 按文档 ID 升序排序，以支持高效的布尔搜索（双指针法）
        std::sort(postings.begin(), postings.end(),
            [](const Posting& a, const Posting& b) { return a.docId < b.docId; });
        postingLists.push_back(postings);

        // 更新下一条列表的偏移位置：4字节(计数) + Posting 数组长度
        currentPostingOffset += sizeof(uint32_t) + (postings.size() * sizeof(Posting));
    }

    // 5. 批量写入词典区，减少系统调用次数
    out.write(reinterpret_cast<const char*>(dictionary.data()), dictionary.size() * sizeof(DictionaryEntry));

    // 6. 顺序写入各关键词对应的倒排列表
    for (const auto& postings : postingLists) {
        uint32_t count = static_cast<uint32_t>(postings.size());
        out.write(reinterpret_cast<const char*>(&count), sizeof(uint32_t));
        out.write(reinterpret_cast<const char*>(postings.data()), count * sizeof(Posting));
    }

    std::cout << "已成功保存二进制索引至: " << indexPath << std::endl;
}

void IndexManager::SaveFileMap(const std::string& mapPath) {
    std::ofstream out(mapPath, std::ios::binary);
    if (!out) {
        std::cerr << "错误: 无法打开映射文件进行写入: " << mapPath << std::endl;
        return;
    }

    // 按照 [ID:4B | 长度:4B | 路径文本] 格式持久化
    for (const auto& [docId, path] : m_fileMap) {
        out.write(reinterpret_cast<const char*>(&docId), sizeof(uint32_t));
        
        uint32_t pathLen = static_cast<uint32_t>(path.length());
        out.write(reinterpret_cast<const char*>(&pathLen), sizeof(uint32_t));
        
        out.write(path.c_str(), pathLen);
    }
    
    std::cout << "已成功保存文件映射至: " << mapPath << std::endl;
}

void IndexManager::SetCipherDir(const std::string& cipherDir) {
    m_cipherDir = cipherDir;
}

void IndexManager::SetCryptoParams(const std::array<uint8_t, 16>& salt, uint32_t iterations) {
    m_salt = salt;
    m_iterations = iterations;
}