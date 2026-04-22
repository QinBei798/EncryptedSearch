/**
 * @file ParallelHasher.hpp
 * @brief 并行哈希处理器，采用生产者-消费者模型加速文件处理
 * @author Antigravity
 * @date 2026-04-22
 */

#pragma once
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <queue>
#include <condition_variable>
#include <functional>
#include <map>
#include <index/IndexStructs.hpp>    // Posting 结构体
#include "../core/CryptoEngine.hpp"

/**
 * @class ParallelHasher
 * @brief 使用线程池并发计算多个文件的 SM3 摘要并构建倒排结构
 */
class ParallelHasher {
public:
    /**
     * @brief 构造函数，初始化工作线程
     * @param threadCount 工作线程数量
     */
    ParallelHasher(size_t threadCount = std::thread::hardware_concurrency());
    
    /**
     * @brief 析构函数，安全关闭线程池
     */
    ~ParallelHasher();

    /**
     * @brief 添加待处理的文件任务
     * @param filePath 文档路径
     * @param docId 分配的文档 ID
     */
    void AddTask(const std::string& filePath, uint32_t docId);

    /**
     * @brief 阻塞直到所有任务处理完毕，并获取最终索引结果
     * @return 映射：哈希值 -> 倒排列表 (docId, tf)
     */
    std::map<std::array<uint8_t, 32>, std::vector<Posting>> GetResults();

private:
    /**
     * @brief 工作线程核心函数
     */
    void worker();

    std::atomic<size_t> m_activeTasks{0}; ///< 正在进行的任务计数
    std::condition_variable m_finishedCv; ///< 任务全部完成的通知变量
    
    std::queue<std::pair<std::string, uint32_t>> m_taskQueue; ///< 任务队列
    std::mutex m_queueMutex;             ///< 队列同步锁
    std::condition_variable m_cv;        ///< 任务队列通知变量
    bool m_stop = false;                 ///< 停止标志

    std::map<std::array<uint8_t, 32>, std::vector<Posting>> m_finalIndex; ///< 索引汇总结果
    std::mutex m_indexMutex;             ///< 结果汇总同步锁

    std::vector<std::thread> m_workers;  ///< 工作线程池
};