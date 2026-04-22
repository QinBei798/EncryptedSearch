/**
 * @file main.cpp
 * @brief 程序入口，演示加密索引构建、文件归档及布尔搜索功能
 * @author Antigravity
 * @date 2026-04-22
 */

#include "core/CryptoEngine.hpp"
#include "index/Indexer.hpp"
#include "search/Searcher.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>

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
  std::cout << "检测到硬件并行线程数: " << n << std::endl;

  // 2. 初始化测试环境
  std::string testDir = "./test_docs";
  fs::create_directory(testDir);

  std::string cipherDir = "./cipher_docs";
  fs::create_directory(cipherDir);

  std::vector<std::string> testFiles = {
      testDir + "/file1.txt", testDir + "/file2.txt", testDir + "/file3.txt",
      testDir + "/file4.txt", testDir + "/file5.txt", testDir + "/file6.txt"};

  CreateTestFile(testFiles[0], "C++ 高性能计算与并发编程");
  CreateTestFile(testFiles[1], "国家商用密码标准 SM3 摘要算法说明");
  CreateTestFile(testFiles[2], "可搜索加密（Searchable Encryption）方案实现");
  CreateTestFile(testFiles[3], "使用 std::thread 进行多线程加速处理");
  CreateTestFile(testFiles[4], "结巴分词是目前非常好用的 C++ 中文分词库。");
  CreateTestFile(testFiles[5], "我们的系统支持国密算法，包括 SM3 哈希和 SM4 对称加密。");

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
    for (auto &b : salt) b = static_cast<uint8_t>(dist(rd));
  }
  uint32_t iterations = 10000;

  std::cout << "正在通过 PBKDF2-SM3-HMAC 派生 SM4 密钥 (迭代次数: " << iterations << ")..." << std::endl;
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

  std::cout << "\n正在扫描目录并构建倒排索引..." << std::endl;
  indexManager.ScanDirectory(testDir);

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
        std::cout << "  -> 匹配文档: " << pair.first << " (相关性得分: " << pair.second << ")" << std::endl;
      }
    }
  }

  // 7. 布尔搜索演示
  std::cout << "\n--- 布尔逻辑搜索测试 ---" << std::endl;
  std::vector<std::pair<std::string, std::string>> booleanQueries = {
      {"SM3 AND SM4", "交集测试"},
      {"分词 OR 加密", "并集测试"},
      {"加密 AND NOT 分词", "差集测试"}
  };

  for (const auto &bq : booleanQueries) {
    std::cout << "\n[" << bq.second << "] 表达式: \"" << bq.first << "\"" << std::endl;
    auto results = searcher.BooleanSearch(bq.first);
    if (results.empty()) {
      std::cout << "  -> 无匹配结果。" << std::endl;
    } else {
      for (const auto &[path, score] : results) {
        std::cout << "  -> " << path << " (得分: " << score << ")" << std::endl;
      }
    }
  }

  // 8. 交互式搜索模式
  std::cout << "\n=============================================" << std::endl;
  std::cout << "          交互式布尔搜索模式 (Interactive)      " << std::endl;
  std::cout << "=============================================" << std::endl;
  std::cout << "提示：输入如 'SM3 AND SM4' 或 'C++ OR 分词' 进行查询" << std::endl;
  std::cout << "输入 'exit' 退出程序" << std::endl;

  std::string userQuery;
  std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n'); 

  while (true) {
    std::cout << "\n搜索请求 > ";
    if (!std::getline(std::cin, userQuery) || userQuery == "exit") break;
    if (userQuery.empty()) continue;

    auto results = searcher.BooleanSearch(userQuery);
    if (results.empty()) {
      std::cout << "  [!] 未找到匹配内容: " << userQuery << std::endl;
    } else {
      std::cout << "  [*] 检索到 " << results.size() << " 个结果:" << std::endl;
      for (const auto &[path, score] : results) {
        std::cout << "    -> " << path << " (得分: " << score << ")" << std::endl;
      }
    }
  }

  std::cout << "\n所有测试已完成。" << std::endl;
  return 0;
}
