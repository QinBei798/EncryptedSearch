#include <iostream>
#include <fstream>
#include <filesystem>
#include "core/CryptoEngine.hpp"
#include "index/Indexer.hpp"
#include "search/Searcher.hpp"
#include <random>

namespace fs = std::filesystem;

void CreateTestFile(const std::string &path, const std::string &content) {
  std::ofstream ofs(path);
  ofs << content;
  ofs.close();
}

int main() {
#ifdef _WIN32
  system("chcp 65001 > nul");
#endif

  std::cout << "--- Multi-threaded Hashing Integration Test ---" << std::endl;

  // 1. 获取硬件支持的并发线程数
  unsigned int n = std::thread::hardware_concurrency();
  std::cout << "Detected Hardware Threads: " << n << std::endl;

  // 2. 创建临时测试文件
  std::string testDir = "./test_docs";
  fs::create_directory(testDir);

  // 2.5 创建密文保险箱目录 (加密后的物理文件将存放于此)
  std::string cipherDir = "./cipher_docs";
  fs::create_directory(cipherDir);

  std::vector<std::string> testFiles = {
      testDir + "/file1.txt", testDir + "/file2.txt", testDir + "/file3.txt",
      testDir + "/file4.txt", testDir + "/file5.txt", testDir + "/file6.txt"};

  CreateTestFile(testFiles[0], "C++ High Performance Computing");
  CreateTestFile(testFiles[1], "National Commercial Cryptography SM3");
  CreateTestFile(testFiles[2], "Searchable Encryption Implementation");
  CreateTestFile(testFiles[3], "Multi-threading with std::thread");
  CreateTestFile(testFiles[4], "结巴分词是目前非常好用的C++中文分词库。");
  CreateTestFile(testFiles[5],
                 "我们的加密搜索系统支持国密标准算法，如SM3和SM4。");

  // 3. 提示用户输入密码并派生密钥 (Phase 4 PBKDF2)
  std::cout << "\n--- Security Configuration ---" << std::endl;
  std::string password;
  std::cout << "Enter a password to encrypt your index and files: ";
  // 暂时使用简单输入代替无回显输入，实际生产可用平台特定的输入屏蔽
  std::cin >> password;

  std::array<uint8_t, 16> salt;
  {
      std::random_device rd;
      std::uniform_int_distribution<unsigned int> dist(0, 255);
      for (auto& b : salt) {
          b = static_cast<uint8_t>(dist(rd));
      }
  }
  uint32_t iterations = 10000;

  std::cout << "Deriving SM4 key using PBKDF2-SM3-HMAC (" << iterations << " iterations)..." << std::endl;
  try {
      CryptoEngine::DeriveKeySM3PBKDF2(password, salt, iterations);
      std::cout << "Key derivation successful." << std::endl;
  } catch (const std::exception& e) {
      std::cerr << "Key derivation failed: " << e.what() << std::endl;
      return 1;
  }

  // 4. 初始化索引管理器
  IndexManager indexManager(n);
  indexManager.SetCipherDir(cipherDir); // 开启 SM4 实体文件加密归档功能
  indexManager.SetCryptoParams(salt, iterations);

  // 5. 扫描目录并构建索引
  std::cout << "\nScanning directory and building index..." << std::endl;
  indexManager.ScanDirectory(testDir);

  // 6. 保存索引到文件
  std::string indexPath = "encrypted_search_index.bin";
  indexManager.SaveToIndex(indexPath);

  // 6.5 保存文件ID映射表
  std::string mapPath = "file_map.dat";
  indexManager.SaveFileMap(mapPath);

  // 7. 初始化并加载 Searcher
  std::cout << "\n--- Initializing Searcher ---" << std::endl;
  Searcher searcher;
  if (!searcher.LoadFileMap(mapPath)) {
    std::cerr << "Failed to load file map. Exiting." << std::endl;
    return 1;
  }
  if (!searcher.LoadIndex(indexPath)) {
    std::cerr << "Failed to load index. Exiting." << std::endl;
    return 1;
  }

  // 8. 进行搜索测试
  std::cout << "\n--- Performing Search Tests ---" << std::endl;
  std::vector<std::string> searchKeywords = {
      "c++", "sm3", "encryption", "分词", "中文", "国密", "加密搜索"};

  for (const auto &keyword : searchKeywords) {
    std::cout << "\nSearching for: '" << keyword << "' ..." << std::endl;
    std::vector<std::pair<std::string, float>> results = searcher.Search(keyword);

    if (results.empty()) {
      std::cout << "  -> No matching files found." << std::endl;
    } else {
      for (const auto &pair : results) {
        std::cout << "  -> Found target: " << pair.first << " (Score: " << pair.second 
                  << " | Safely encrypted in " << cipherDir << ")" << std::endl;
      }
    }
  }

  std::cout << "\nIndex creation and basic keyword hashing test complete."
            << std::endl;

  return 0;
}