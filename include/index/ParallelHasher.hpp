#pragma once
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <functional>
#include <map>
#include "../core/CryptoEngine.hpp"

#pragma pack(push, 1)
struct Posting {
    uint32_t docId;
    float tf;
};
#pragma pack(pop)


class ParallelHasher {
public:
    // 构造函数：初始化指定数量的工作线程
    ParallelHasher(size_t threadCount = std::thread::hardware_concurrency());
    ~ParallelHasher();

    // Phase 2: 以文件为粒度提交任务（filePath + docId）
    // Worker 线程内部负责：读文件 → 分词 → 批量 SM3 哈希 → 一次性写入结果
    // 对比旧设计（每关键词一次锁），将锁竞争从 N次/文件 降低为 1次/文件
    void AddTask(const std::string& filePath, uint32_t docId);

    // 等待所有任务完成并返回结果集：Hash -> Posting列表 (docId, tf)
    std::map<std::array<uint8_t, 32>, std::vector<Posting>> GetResults();

private:
    std::atomic<size_t> m_activeTasks{0}; // 原子计数器，记录处理中的任务
    std::condition_variable m_finishedCv; // 用于通知任务全部完成
    
    void worker(); // 工作线程的核心循环

    // 任务队列相关：存储关键词和对应的文档ID
    std::queue<std::pair<std::string, uint32_t>> m_taskQueue;
    std::mutex m_queueMutex;
    std::condition_variable m_cv;
    bool m_stop = false;

    // 结果集相关
    std::map<std::array<uint8_t, 32>, std::vector<Posting>> m_finalIndex;
    std::mutex m_indexMutex;

    std::vector<std::thread> m_workers;
};