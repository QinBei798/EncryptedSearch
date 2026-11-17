/**
 * @file main.cpp
 * @brief 程序入口，演示加密索引构建、文件归档、真实资源监控及布尔搜索功能
 */

#include "core/CryptoEngine.hpp"
#include "core/SystemMonitor.hpp"
#include "index/Indexer.hpp"
#include "search/Searcher.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <random>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

void PrintUsage(const char* progName) {
    std::cout << "用法: " << progName << " [语料目录路径]\n"
              << "说明: 若未指定目录，将依次尝试查找 ./test_docs_5gb、../../test_docs_5gb、./test_docs、../../test_docs。\n"
              << "      也可运行 'python3 generate_5gb_data.py' 生成 5GB 实验语料。" << std::endl;
}

bool ResolveCorpusDir(int argc, char* argv[], std::string& outDir) {
    if (argc > 1) {
        std::string arg = argv[1];
        if (arg == "-h" || arg == "--help") {
            PrintUsage(argv[0]);
            return false;
        }
        std::error_code ec;
        if (!fs::exists(arg, ec) || !fs::is_directory(arg, ec)) {
            std::cerr << "错误: 指定的语料目录不存在或不是目录: " << arg << std::endl;
            return false;
        }
        outDir = arg;
        return true;
    }

    const std::vector<std::string> candidates = {
        "./test_docs_5gb",
        "../../test_docs_5gb",
        "./test_docs",
        "../../test_docs"
    };
    std::error_code ec;
    for (const auto& dir : candidates) {
        if (fs::exists(dir, ec) && fs::is_directory(dir, ec)) {
            outDir = dir;
            return true;
        }
    }

    std::cerr << "错误: 未找到默认语料目录 (test_docs_5gb / test_docs)。\n";
    PrintUsage(argv[0]);
    return false;
}

std::string ResolveCipherDir(const std::string& corpusDir) {
    std::error_code ec;
    fs::path absCorpus = fs::absolute(fs::path(corpusDir), ec).lexically_normal();
    if (!absCorpus.has_filename()) {
        absCorpus = absCorpus.parent_path();
    }
    fs::path parent = absCorpus.parent_path();
    if (parent.empty()) {
        parent = fs::current_path(ec);
    }
    return (parent / "cipher_docs").string();
}

} // namespace

int main(int argc, char* argv[]) {
#ifdef _WIN32
    // Windows 平台下设置控制台为 UTF-8 编码，防止中文乱码
    system("chcp 65001 > nul");
#endif

    std::cout << "--- 国密加密搜索系统测试驱动 ---" << std::endl;

    std::string testDir;
    if (!ResolveCorpusDir(argc, argv, testDir)) {
        return (argc > 1 && (std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help")) ? 0 : 1;
    }

    std::string cipherDir = ResolveCipherDir(testDir);
    std::error_code ec;
    fs::create_directories(cipherDir, ec);
    if (ec) {
        std::cerr << "错误: 无法创建密文目录 " << cipherDir << ": " << ec.message() << std::endl;
        return 1;
    }

    // 1. 真实运行环境信息检测
    const SystemInfo sysInfo = SystemMonitor::GetSystemInfo();
    std::cout << "========== 实验环境参数 ==========\n";
    std::cout << "CPU: " << sysInfo.cpuModel
              << " (硬件并发线程: " << sysInfo.hardwareThreads << ")\n";
    std::cout << "Compiler: " << sysInfo.compilerInfo << "\n";
    std::cout << "语料目录: " << testDir << "\n";
    std::cout << "密文归档目录: " << cipherDir << "\n";
    std::cout << "==================================\n" << std::endl;

    // 2. 密钥安全配置 (基于 PBKDF2-SM3-HMAC)
    std::cout << "--- 安全配置 ---" << std::endl;
    std::string password;
    std::cout << "请输入主密码以保护索引和文件: ";
    if (!(std::cin >> password)) {
        std::cerr << "\n错误: 未读取到主密码。" << std::endl;
        return 1;
    }

    std::array<uint8_t, 16> salt{};
    {
        std::random_device rd;
        std::uniform_int_distribution<unsigned int> dist(0, 255);
        for (auto& b : salt) {
            b = static_cast<uint8_t>(dist(rd));
        }
    }
    const uint32_t iterations = 10000;

    std::cout << "正在通过 PBKDF2-SM3-HMAC 派生 SM4 密钥 (迭代次数: "
              << iterations << ")..." << std::endl;
    try {
        CryptoEngine::DeriveKeySM3PBKDF2(password, salt, iterations);
        std::cout << "密钥派生成功。" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "密钥派生失败: " << e.what() << std::endl;
        return 1;
    }

    // 3. 构建索引与真实耗时/内存监控
    IndexManager indexManager(sysInfo.hardwareThreads);
    indexManager.SetCipherDir(cipherDir);
    indexManager.SetCryptoParams(salt, iterations);

    std::cout << "\n正在启动流式切割与中英混合分词 (CutForSearch) ..." << std::endl;
    std::cout << "正在扫描目录并构建倒排索引 (ParallelHasher "
              << sysInfo.hardwareThreads << " 线程并发) ..." << std::endl;

    const auto scanStart = std::chrono::steady_clock::now();
    const ScanStats stats = indexManager.ScanDirectory(testDir);
    const auto scanEnd = std::chrono::steady_clock::now();

    if (stats.fileCount == 0) {
        std::cerr << "错误: 目录中未扫描到任何常规文件，终止索引构建。" << std::endl;
        return 1;
    }

    const std::string indexPath = "encrypted_search_index.bin";
    const std::string mapPath = "file_map.dat";

    const auto saveStart = std::chrono::steady_clock::now();
    indexManager.SaveToIndex(indexPath);
    indexManager.SaveFileMap(mapPath);
    const auto saveEnd = std::chrono::steady_clock::now();

    const double scanSec = std::chrono::duration<double>(scanEnd - scanStart).count();
    const double saveSec = std::chrono::duration<double>(saveEnd - saveStart).count();
    const double totalSec = std::chrono::duration<double>(saveEnd - scanStart).count();
    const uint64_t avgBytes = stats.totalBytes / stats.fileCount;
    const double totalMB = static_cast<double>(stats.totalBytes) / (1024.0 * 1024.0);
    const double throughputMBps = totalSec > 0.0 ? (totalMB / totalSec) : 0.0;

    const MemoryStats memStats = SystemMonitor::GetMemoryStats();

    const auto oldFlags = std::cout.flags();
    const auto oldPrec = std::cout.precision();

    std::cout << "\n========== 真实建库统计与监控 ==========\n";
    std::cout << "扫描文件数: " << stats.fileCount << " 份";
    if (stats.encryptFailedCount > 0) {
        std::cout << " (SM4 加密失败: " << stats.encryptFailedCount << " 份)";
    }
    std::cout << "\n";
    std::cout << "语料总大小: " << SystemMonitor::FormatBytes(stats.totalBytes)
              << " (单文件均值: " << SystemMonitor::FormatBytes(avgBytes) << ")\n";
    std::cout << std::fixed << std::setprecision(4)
              << "扫描与 SM4 加密耗时: " << scanSec << " s\n"
              << "并行分词与索引落盘耗时: " << saveSec << " s\n"
              << "端到端建库总耗时: " << totalSec << " s\n";
    std::cout << std::fixed << std::setprecision(2)
              << "端到端真实吞吐率: " << throughputMBps << " MB/s\n";
    if (memStats.IsValid()) {
        std::cout << "进程物理内存峰值 (VmHWM / Peak RSS): " << memStats.peakRssMB << " MB";
        if (memStats.currentRssMB >= 0.0) {
            std::cout << " (当前 RSS: " << memStats.currentRssMB << " MB)";
        }
        std::cout << "\n";
    } else {
        std::cout << "进程物理内存峰值: 当前平台暂不支持\n";
    }
    std::cout << "========================================\n" << std::endl;

    std::cout.flags(oldFlags);
    std::cout.precision(oldPrec);

    // 4. 检索验证
    std::cout << "--- 初始化搜索器 ---" << std::endl;
    Searcher searcher;
    if (!searcher.LoadFileMap(mapPath) || !searcher.LoadIndex(indexPath)) {
        std::cerr << "加载索引数据失败，程序退出。" << std::endl;
        return 1;
    }
    if (!searcher.VerifyPasswordKey()) {
        std::cerr << "错误: 主密码校验指纹不匹配，拒绝执行检索。" << std::endl;
        return 1;
    }

    // 5. 自动化功能测试
    std::cout << "\n--- 执行功能测试案例 ---" << std::endl;
    const std::vector<std::string> searchKeywords = {"c++", "sm3", "分词", "国密"};
    for (const auto& keyword : searchKeywords) {
        std::cout << "\n正在搜索: '" << keyword << "' ..." << std::endl;
        auto results = searcher.Search(keyword);
        if (results.empty()) {
            std::cout << "  -> 未找到匹配结果。" << std::endl;
        } else {
            for (const auto& pair : results) {
                std::cout << "  -> 匹配文档: " << pair.first
                          << " (相关性得分: " << pair.second << ")" << std::endl;
            }
        }
    }

    // 6. 布尔逻辑搜索演示
    std::cout << "\n--- 布尔逻辑搜索测试 ---" << std::endl;
    const std::vector<std::pair<std::string, std::string>> booleanQueries = {
        {"SM3 AND SM4", "交集测试"},
        {"分词 OR 加密", "并集测试"},
        {"加密 AND NOT 分词", "差集测试"}
    };

    for (const auto& bq : booleanQueries) {
        std::cout << "\n[" << bq.second << "] 表达式: \"" << bq.first << "\"" << std::endl;

        const auto searchStart = std::chrono::steady_clock::now();
        auto results = searcher.BooleanSearch(bq.first);
        const auto searchEnd = std::chrono::steady_clock::now();

        const double realLatencyMs = std::chrono::duration<double, std::milli>(searchEnd - searchStart).count();
        std::cout << "[检索延迟分析] 真实响应耗时: " << realLatencyMs << " ms\n";

        if (results.empty()) {
            std::cout << "  -> 无匹配结果。" << std::endl;
        } else {
            int printCount = 0;
            for (const auto& [path, score] : results) {
                std::cout << "  -> " << path << " (得分: " << score << ")" << std::endl;
                if (++printCount >= 5) {
                    std::cout << "  -> ... (省略其余 " << results.size() - 5
                              << " 个结果，防止刷屏)" << std::endl;
                    break;
                }
            }
        }
    }

    // 7. 交互式搜索模式
    std::cout << "\n=============================================" << std::endl;
    std::cout << "          交互式布尔搜索模式 (Interactive)      " << std::endl;
    std::cout << "=============================================" << std::endl;
    std::cout << "提示：输入如 'SM3 AND SM4' 或 'C++ OR 分词' 进行查询" << std::endl;
    std::cout << "输入 'exit' 退出程序" << std::endl;

    std::string userQuery;
    std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');

    while (true) {
        std::cout << "\n搜索请求 > ";
        if (!std::getline(std::cin, userQuery) || userQuery == "exit") {
            break;
        }
        if (userQuery.empty()) {
            continue;
        }

        auto results = searcher.BooleanSearch(userQuery);
        if (results.empty()) {
            std::cout << "  [!] 未找到匹配内容: " << userQuery << std::endl;
        } else {
            std::cout << "  [*] 检索到 " << results.size() << " 个结果:" << std::endl;
            for (const auto& [path, score] : results) {
                std::cout << "    -> " << path << " (得分: " << score << ")" << std::endl;
            }
        }
    }

    std::cout << "\n所有测试已完成。" << std::endl;
    return 0;
}
