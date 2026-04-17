#include <iostream>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <index/Indexer.hpp>
#include <core/CryptoEngine.hpp>

namespace fs = std::filesystem;

IndexManager::IndexManager(size_t threads) : m_hasher(threads) {}

void IndexManager::ScanDirectory(const std::string& targetPath) {
    std::cout << "Scanning directory: " << targetPath << "..." << std::endl;
    
    size_t fileCount = 0;
    try {
        for (const auto& entry : fs::recursive_directory_iterator(targetPath)) {
            if (entry.is_regular_file()) {
                std::string path = entry.path().string();
                
                // 1. 维护内部文件 ID 映射
                uint32_t docId = m_nextFileId++;
                m_fileMap[docId] = path;
                m_pathToId[path] = docId;
                
                // 2. Phase 2: 以文件为粒度提交任务（1次锁替代旧设计的N次锁）
                // Worker 线程内部负责：读文件 → 分词（Jieba） → 批量SM3 → 批量写入索引
                m_hasher.AddTask(path, docId);

                // 3. 将原文件使用 SM4 加密并保存至密文区 (命名为 0.cipher, 1.cipher ...)
                if (!m_cipherDir.empty()) {
                    std::string cipherPath = m_cipherDir + "/" + std::to_string(docId) + ".cipher";
                    if (!CryptoEngine::EncryptFileSM4(path, cipherPath)) {
                        std::cerr << "Warning: Failed to encrypt file " << path << std::endl;
                    }
                }

                fileCount++;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Scan Error: " << e.what() << std::endl;
    }

    std::cout << "Enqueued " << fileCount << " files. IDs assigned 0 to " << (m_nextFileId - 1) << std::endl;
}

void IndexManager::SaveToIndex(const std::string& indexPath) {
    // 1. 获取所有计算好的哈希结果
    auto hashResults = m_hasher.GetResults(); // 现在返回的是 Hash -> DocId列表
    
    std::ofstream out(indexPath, std::ios::binary);
    if (!out) {
        std::cerr << "Error: Could not open index file for writing: " << indexPath << std::endl;
        return;
    }

    // 2. 写入文件头 (Header)
    IndexHeader header;
    header.keywordCount = hashResults.size();
    header.docCount = m_fileMap.size();
    std::copy(m_salt.begin(), m_salt.end(), header.salt);
    header.iterations = m_iterations;
    out.write(reinterpret_cast<const char*>(&header), sizeof(IndexHeader));

    // 3. 记录当前的偏移位置（跳过 Header 和 词典区）
    uint64_t currentPostingOffset = sizeof(IndexHeader) + (header.keywordCount * sizeof(DictionaryEntry));
    
    std::vector<DictionaryEntry> dictionary;
    std::vector<std::vector<Posting>> postingLists;

    // 4. 整理数据：将路径转为 ID，并计算偏移
    for (auto& [hash, postings] : hashResults) {
        DictionaryEntry entry;
        std::copy(hash.begin(), hash.end(), entry.hash);
        entry.offset = currentPostingOffset;
        dictionary.push_back(entry);

        // Phase 6: 对 Posting List 按 docId 升序排序，保证布尔集合运算（双指针法）正确性
        std::sort(postings.begin(), postings.end(),
            [](const Posting& a, const Posting& b) { return a.docId < b.docId; });
        postingLists.push_back(postings);

        // 更新偏移：4字节(长度) + Posting列表字节数
        currentPostingOffset += sizeof(uint32_t) + (postings.size() * sizeof(Posting));
    }

    // 5. 批量写入词典 (Dictionary) - 高性能点：一次系统调用写入全部
    out.write(reinterpret_cast<const char*>(dictionary.data()), dictionary.size() * sizeof(DictionaryEntry));

    // 6. 顺序写入倒排列表 (Posting Lists)
    for (const auto& postings : postingLists) {
        uint32_t count = static_cast<uint32_t>(postings.size());
        out.write(reinterpret_cast<const char*>(&count), sizeof(uint32_t));
        out.write(reinterpret_cast<const char*>(postings.data()), count * sizeof(Posting));
    }

    std::cout << "Successfully saved binary index to: " << indexPath << std::endl;
}

void IndexManager::SaveFileMap(const std::string& mapPath) {
    std::ofstream out(mapPath, std::ios::binary);
    if (!out) {
        std::cerr << "Error: Could not open file map for writing: " << mapPath << std::endl;
        return;
    }

    // 遍历映射表，按照 ID(4B) + PathLength(4B) + PathString(N Bytes) 格式写入
    for (const auto& [docId, path] : m_fileMap) {
        out.write(reinterpret_cast<const char*>(&docId), sizeof(uint32_t));
        
        uint32_t pathLen = static_cast<uint32_t>(path.length());
        out.write(reinterpret_cast<const char*>(&pathLen), sizeof(uint32_t));
        
        out.write(path.c_str(), pathLen);
    }
    
    std::cout << "Successfully saved file map to: " << mapPath << std::endl;
}

void IndexManager::SetCipherDir(const std::string& cipherDir) {
    m_cipherDir = cipherDir;
}

void IndexManager::SetCryptoParams(const std::array<uint8_t, 16>& salt, uint32_t iterations) {
    m_salt = salt;
    m_iterations = iterations;
}