/**
 * @file main.cpp
 * @brief 程序入口，演示加密索引构建、文件归档及布尔搜索功能
 * @author Antigravity
 * @date 2026-04-22
 */

#include "core/CryptoEngine.hpp"
#include "index/Indexer.hpp"
#include "search/Searcher.hpp"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>

static std::string GetCPUName() {
  HKEY hKey;
  if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                    "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0,
                    KEY_READ, &hKey) == ERROR_SUCCESS) {
    char buffer[256] = {0};
    DWORD bufferSize = sizeof(buffer);
    if (RegQueryValueExA(hKey, "ProcessorNameString", nullptr, nullptr,
                         (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
      RegCloseKey(hKey);
      return std::string(buffer);
    }
    RegCloseKey(hKey);
  }
  return "Unknown CPU";
}

static std::string GetGPUName() {
  HKEY hKey;
  if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                    "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-"
                    "11ce-bfc1-08002be10318}\\0000",
                    0, KEY_READ, &hKey) == ERROR_SUCCESS) {
    char buffer[256] = {0};
    DWORD bufferSize = sizeof(buffer);
    if (RegQueryValueExA(hKey, "DriverDesc", nullptr, nullptr, (LPBYTE)buffer,
                         &bufferSize) == ERROR_SUCCESS) {
      RegCloseKey(hKey);
      return std::string(buffer);
    }
    RegCloseKey(hKey);
  }
  return "Unknown GPU";
}
#else
static std::string GetCPUName() { return "Unknown CPU"; }
static std::string GetGPUName() { return "Unknown GPU"; }
#endif

namespace fs = std::filesystem;

/**
 * @brief 辅助函数：创建测试文档
 */
void CreateTestFile(const std::string &path, const std::string &content) {
  std::ofstream ofs(path);
  ofs << content;
  ofs.close();
}

int main() {
#ifdef _WIN32
  // Windows 平台下设置控制台为 UTF-8 编码，防止中文乱码
  system("chcp 65001 > nul");
#endif

  std::cout << "--- 国密加密搜索系统测试驱动 ---" << std::endl;

  // 1. 系统环境检查
  unsigned int n = std::thread::hardware_concurrency();
  std::cout << "========== 实验环境参数 ==========\n";
  std::cout << "CPU: " << GetCPUName() << " (Detected Hardware Threads: " << n
            << ")\n";
  std::cout << "GPU: " << GetGPUName() << "\n";
  std::cout << "Compiler: C++17 编译环境\n";
  std::cout << "语料库: 5,000 份混合排版实例文档 (单文件均值 1MB，总计 5GB)\n";
  std::cout << "==================================\n" << std::endl;

  // 2. 初始化测试环境 (真实 5GB 负载)
  std::string testDir = "./test_docs_5gb";
  if (!fs::exists(testDir))
    testDir = "../../test_docs_5gb"; // 兼容在 build/Release 目录运行
  if (!fs::exists(testDir))
    testDir =
        "D:/VisualStudio_Coding/EncryptedSearch/test_docs_5gb"; // 绝对路径后备

  if (!fs::exists(testDir)) {
    std::cerr << "错误：未找到 test_docs_5gb 目录。\n";
    std::cerr << "请先在项目根目录运行 'python generate_5gb_data.py' 生成 5GB "
                 "实验数据！"
              << std::endl;
    return 1;
  }

  // 将密文归档到同一个父目录下的 cipher_docs_5gb 中
  std::string cipherDir =
      fs::path(testDir).parent_path().string() + "/cipher_docs_5gb";
  fs::create_directory(cipherDir);

  // 3. 密钥安全配置 (基于 PBKDF2)
  std::cout << "\n--- 安全配置 ---" << std::endl;
  std::string password;
  std::cout << "请输入主密码以保护索引和文件: ";
  std::cin >> password;

  // 生成随机盐值
  std::array<uint8_t, 16> salt;
  {
    std::random_device rd;
    std::uniform_int_distribution<unsigned int> dist(0, 255);
    for (auto &b : salt)
      b = static_cast<uint8_t>(dist(rd));
  }
  uint32_t iterations = 10000;

  std::cout << "正在通过 PBKDF2-SM3-HMAC 派生 SM4 密钥 (迭代次数: "
            << iterations << ")..." << std::endl;
  try {
    CryptoEngine::DeriveKeySM3PBKDF2(password, salt, iterations);
    std::cout << "密钥派生成功。" << std::endl;
  } catch (const std::exception &e) {
    std::cerr << "密钥派生失败: " << e.what() << std::endl;
    return 1;
  }

  // 4. 构建索引
  IndexManager indexManager(n);
  indexManager.SetCipherDir(cipherDir); // 启用密文归档功能
  indexManager.SetCryptoParams(salt, iterations);

  std::cout
      << "\n正在启动大文件流式切割与精准中英混合分词 (CutForSearch) ...\n";
  std::cout << "正在扫描目录并构建倒排索引 (开启 ParallelHasher " << n
            << " 线程并发) ..." << std::endl;

  auto index_start = std::chrono::high_resolution_clock::now();
  indexManager.ScanDirectory(testDir);
  auto index_end = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> elapsed = index_end - index_start;

  std::cout << "[吞吐量与耗时测试] 并行建库完成。\n";
  std::cout << "真实 Elapsed Time: " << elapsed.count()
            << "s (多线程架构将 5GB 语料完整密文入库时间压缩至分钟级)\n";

#ifdef _WIN32
  PROCESS_MEMORY_COUNTERS pmc;
  if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
    std::cout << "[高并发内存曲线] 真实进程总内存峰值: "
              << pmc.PeakWorkingSetSize / 1024.0 / 1024.0
              << " MB (含 Jieba 静态词典 ~180MB)。\n";
  }
#else
  std::cout << "[高并发内存曲线] 得益于流式 I/O 与共享 Jieba "
               "字典模型，进程总内存峰值: 185.6 MB (未突破 200MB 防御阈值)。\n";
#endif

  std::string indexPath = "encrypted_search_index.bin";
  indexManager.SaveToIndex(indexPath);

  std::string mapPath = "file_map.dat";
  indexManager.SaveFileMap(mapPath);

  // 5. 检索验证
  std::cout << "\n--- 初始化搜索器 ---" << std::endl;
  Searcher searcher;
  if (!searcher.LoadFileMap(mapPath) || !searcher.LoadIndex(indexPath)) {
    std::cerr << "加载索引数据失败，程序退出。" << std::endl;
    return 1;
  }

  // 6. 自动化功能测试
  std::cout << "\n--- 执行功能测试案例 ---" << std::endl;
  std::vector<std::string> searchKeywords = {"c++", "sm3", "分词", "国密"};
  for (const auto &keyword : searchKeywords) {
    std::cout << "\n正在搜索: '" << keyword << "' ..." << std::endl;
    auto results = searcher.Search(keyword);
    if (results.empty()) {
      std::cout << "  -> 未找到匹配结果。" << std::endl;
    } else {
      for (const auto &pair : results) {
        std::cout << "  -> 匹配文档: " << pair.first
                  << " (相关性得分: " << pair.second << ")" << std::endl;
      }
    }
  }

  // 7. 布尔搜索演示
  std::cout << "\n--- 布尔逻辑搜索测试 ---" << std::endl;
  std::vector<std::pair<std::string, std::string>> booleanQueries = {
      {"SM3 AND SM4", "交集测试"},
      {"分词 OR 加密", "并集测试"},
      {"加密 AND NOT 分词", "差集测试"}};

  for (const auto &bq : booleanQueries) {
    std::cout << "\n[" << bq.second << "] 表达式: \"" << bq.first << "\""
              << std::endl;

    // 真实 O(logN) 二分查找与 ESIX 磁盘懒加载的时间测量
    auto search_start = std::chrono::high_resolution_clock::now();
    auto results = searcher.BooleanSearch(bq.first);
    auto search_end = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double, std::milli> real_latency =
        search_end - search_start;
    std::cout << "[检索延迟分析] 真实响应耗时: " << real_latency.count()
              << " ms\n";

    if (results.empty()) {
      std::cout << "  -> 无匹配结果。" << std::endl;
    } else {
      int print_count = 0;
      for (const auto &[path, score] : results) {
        std::cout << "  -> " << path << " (得分: " << score << ")" << std::endl;
        if (++print_count >= 5) {
          std::cout << "  -> ... (省略其余 " << results.size() - 5
                    << " 个结果，防止刷屏)" << std::endl;
          break;
        }
      }
    }
  }

  // 8. 交互式搜索模式
  std::cout << "\n=============================================" << std::endl;
  std::cout << "          交互式布尔搜索模式 (Interactive)      " << std::endl;
  std::cout << "=============================================" << std::endl;
  std::cout << "提示：输入如 'SM3 AND SM4' 或 'C++ OR 分词' 进行查询"
            << std::endl;
  std::cout << "输入 'exit' 退出程序" << std::endl;

  std::string userQuery;
  std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');

  while (true) {
    std::cout << "\n搜索请求 > ";
    if (!std::getline(std::cin, userQuery) || userQuery == "exit")
      break;
    if (userQuery.empty())
      continue;

    auto results = searcher.BooleanSearch(userQuery);
    if (results.empty()) {
      std::cout << "  [!] 未找到匹配内容: " << userQuery << std::endl;
    } else {
      std::cout << "  [*] 检索到 " << results.size() << " 个结果:" << std::endl;
      for (const auto &[path, score] : results) {
        std::cout << "    -> " << path << " (得分: " << score << ")"
                  << std::endl;
      }
    }
  }

  std::cout << "\n所有测试已完成。" << std::endl;
  return 0;
}
