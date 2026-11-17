/**
 * @file test_search_correctness.cpp
 * @brief 正确性测试：TF-IDF 精确数值校验、布尔逻辑真值表、优先级与异常语法边界
 */

#include "core/CryptoEngine.hpp"
#include "index/Indexer.hpp"
#include "search/QueryParser.hpp"
#include "search/Searcher.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

int g_failures = 0;

void ExpectTrue(bool cond, const std::string& msg, int line) {
    if (!cond) {
        std::cerr << "[FAIL] Line " << line << ": " << msg << std::endl;
        ++g_failures;
    }
}

void ExpectNear(double actual, double expected, double tol, const std::string& msg, int line) {
    double diff = std::fabs(actual - expected);
    if (diff > tol) {
        std::cerr << "[FAIL] Line " << line << ": " << msg
                  << " | expected=" << expected << ", actual=" << actual << std::endl;
        ++g_failures;
    }
}

#define EXPECT_TRUE(cond, msg) ExpectTrue((cond), (msg), __LINE__)
#define EXPECT_NEAR(act, exp, tol, msg) ExpectNear((act), (exp), (tol), (msg), __LINE__)

struct TempDirGuard {
    fs::path path;
    explicit TempDirGuard(const std::string& name) {
        path = fs::temp_directory_path() / name;
        std::error_code ec;
        fs::remove_all(path, ec);
        fs::create_directories(path, ec);
    }
    ~TempDirGuard() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

void WriteDoc(const fs::path& p, const std::string& content) {
    std::ofstream out(p, std::ios::binary);
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
}

std::set<std::string> Basenames(const std::vector<std::pair<std::string, float>>& results) {
    std::set<std::string> names;
    for (const auto& [path, score] : results) {
        (void)score;
        names.insert(fs::path(path).filename().string());
    }
    return names;
}

void TestTfIdfExactValuesAndOrdering() {
    TempDirGuard tmp("es_test_tfidf_exact");
    const fs::path docsDir = tmp.path / "docs";
    const fs::path indexPath = tmp.path / "index.bin";
    const fs::path mapPath = tmp.path / "file_map.dat";
    fs::create_directories(docsDir);

    // 使用纯空格分隔英文词，确保词频与总词数可精确手算
    WriteDoc(docsDir / "doc0.txt", "apple apple apple banana");                // 4 words, apple=3 -> tf=0.75
    WriteDoc(docsDir / "doc1.txt", "apple banana cherry date");                // 4 words, apple=1 -> tf=0.25, cherry=0.25
    WriteDoc(docsDir / "doc2.txt", "APPLE orange grape melon kiwi pear");      // 6 words, apple=1 -> tf=1/6
    WriteDoc(docsDir / "doc3.txt", "cherry orange grape melon");               // 4 words, apple=0, cherry=0.25

    std::array<uint8_t, 16> salt{};
    salt.fill(0x55);
    CryptoEngine::DeriveKeySM3PBKDF2("tfidf_test_pass", salt, 1000);

    {
        IndexManager mgr(2);
        mgr.SetCryptoParams(salt, 1000);
        mgr.ScanDirectory(docsDir.string());
        mgr.SaveToIndex(indexPath.string());
        mgr.SaveFileMap(mapPath.string());
    }

    Searcher searcher;
    EXPECT_TRUE(searcher.LoadFileMap(mapPath.string()), "LoadFileMap succeeds");
    EXPECT_TRUE(searcher.LoadIndex(indexPath.string()), "LoadIndex succeeds");

    // N=4, df("apple")=3 -> idf = ln(4 / (3 + 1)) + 1 = 1.0
    auto appleRes = searcher.Search("Apple"); // 同时验证大小写不敏感检索
    EXPECT_TRUE(appleRes.size() == 3, "Search('Apple') hits 3 docs");
    if (appleRes.size() == 3) {
        EXPECT_TRUE(fs::path(appleRes[0].first).filename() == "doc0.txt", "rank 1 is doc0");
        EXPECT_TRUE(fs::path(appleRes[1].first).filename() == "doc1.txt", "rank 2 is doc1");
        EXPECT_TRUE(fs::path(appleRes[2].first).filename() == "doc2.txt", "rank 3 is doc2");

        EXPECT_NEAR(appleRes[0].second, 0.75, 1e-5, "doc0 TF-IDF score exact");
        EXPECT_NEAR(appleRes[1].second, 0.25, 1e-5, "doc1 TF-IDF score exact");
        EXPECT_NEAR(appleRes[2].second, 1.0 / 6.0, 1e-5, "doc2 TF-IDF score exact");
    }

    // N=4, df("cherry")=2 -> idf = ln(4 / 3) + 1
    const double expectedCherryScore = 0.25 * (std::log(4.0 / 3.0) + 1.0);
    auto cherryRes = searcher.Search("cherry");
    EXPECT_TRUE(cherryRes.size() == 2, "Search('cherry') hits 2 docs");
    for (const auto& [path, score] : cherryRes) {
        (void)path;
        EXPECT_NEAR(score, expectedCherryScore, 1e-5, "cherry TF-IDF score matches formula");
    }

    EXPECT_TRUE(searcher.Search("nonexistentterm").empty(), "missing term returns empty");
}

void TestBooleanTruthTableAndPrecedence() {
    TempDirGuard tmp("es_test_boolean_truth");
    const fs::path docsDir = tmp.path / "docs";
    const fs::path indexPath = tmp.path / "index.bin";
    const fs::path mapPath = tmp.path / "file_map.dat";
    fs::create_directories(docsDir);

    // 4 篇文档完整覆盖 {alpha, beta} 真值表并附加 gamma 用于验证 AND > OR 优先级
    WriteDoc(docsDir / "d0.txt", "alpha beta");
    WriteDoc(docsDir / "d1.txt", "alpha gamma");
    WriteDoc(docsDir / "d2.txt", "beta gamma");
    WriteDoc(docsDir / "d3.txt", "delta");

    std::array<uint8_t, 16> salt{};
    salt.fill(0x66);
    CryptoEngine::DeriveKeySM3PBKDF2("boolean_test_pass", salt, 1000);

    {
        IndexManager mgr(2);
        mgr.SetCryptoParams(salt, 1000);
        mgr.ScanDirectory(docsDir.string());
        mgr.SaveToIndex(indexPath.string());
        mgr.SaveFileMap(mapPath.string());
    }

    Searcher searcher;
    EXPECT_TRUE(searcher.LoadFileMap(mapPath.string()), "LoadFileMap succeeds");
    EXPECT_TRUE(searcher.LoadIndex(indexPath.string()), "LoadIndex succeeds");

    EXPECT_TRUE((Basenames(searcher.BooleanSearch("alpha AND beta")) == std::set<std::string>{"d0.txt"}),
                "alpha AND beta -> {d0}");
    EXPECT_TRUE((Basenames(searcher.BooleanSearch("alpha OR beta")) == std::set<std::string>{"d0.txt", "d1.txt", "d2.txt"}),
                "alpha OR beta -> {d0, d1, d2}");
    EXPECT_TRUE((Basenames(searcher.BooleanSearch("alpha AND NOT beta")) == std::set<std::string>{"d1.txt"}),
                "alpha AND NOT beta -> {d1}");
    EXPECT_TRUE((Basenames(searcher.BooleanSearch("beta AND NOT alpha")) == std::set<std::string>{"d2.txt"}),
                "beta AND NOT alpha -> {d2}");
    EXPECT_TRUE((Basenames(searcher.BooleanSearch("NOT alpha AND beta")) == std::set<std::string>{"d2.txt"}),
                "NOT alpha AND beta -> {d2}");

    // 空Posting参与布尔运算边界
    EXPECT_TRUE((Basenames(searcher.BooleanSearch("alpha AND NOT missingword")) == std::set<std::string>{"d0.txt", "d1.txt"}),
                "A AND NOT <missing> -> A");
    EXPECT_TRUE(searcher.BooleanSearch("missingword AND alpha").empty(),
                "<missing> AND A -> empty");
    EXPECT_TRUE((Basenames(searcher.BooleanSearch("missingword OR beta")) == std::set<std::string>{"d0.txt", "d2.txt"}),
                "<missing> OR B -> B");

    // 优先级验证：alpha OR beta AND gamma == alpha OR (beta AND gamma) = {d0, d1, d2}
    // 若错误地左结合为 (alpha OR beta) AND gamma，则会漏掉 d0 只剩 {d1, d2}
    EXPECT_TRUE((Basenames(searcher.BooleanSearch("alpha OR beta AND gamma")) == std::set<std::string>{"d0.txt", "d1.txt", "d2.txt"}),
                "AND must bind tighter than OR (alpha OR beta AND gamma)");
    EXPECT_TRUE((Basenames(searcher.BooleanSearch("beta AND gamma OR alpha")) == std::set<std::string>{"d0.txt", "d1.txt", "d2.txt"}),
                "AND must bind tighter than OR (beta AND gamma OR alpha)");

    // 异常语法在 BooleanSearch 下必须安全返回空集不崩溃
    const std::vector<std::string> badQueries = {
        "", "   \t\n  ", "AND", "OR", "NOT", "AND alpha", "alpha AND", "alpha AND NOT", "alpha beta", "alpha NOT beta"
    };
    for (const auto& q : badQueries) {
        EXPECT_TRUE(searcher.BooleanSearch(q).empty(), "malformed BooleanSearch returns empty safely: " + q);
    }
}

void TestQueryParserAstAndMalformedBounds() {
    auto single = QueryParser::Parse("SM3");
    EXPECT_TRUE(single != nullptr && single->op == QueryOp::TERM && single->term == "SM3",
                "single term AST");

    auto prec = QueryParser::Parse("A OR B AND C");
    EXPECT_TRUE(prec != nullptr && prec->op == QueryOp::OR, "root is OR");
    if (prec) {
        EXPECT_TRUE(prec->left && prec->left->op == QueryOp::TERM && prec->left->term == "A", "left is A");
        EXPECT_TRUE(prec->right && prec->right->op == QueryOp::AND, "right is AND");
        if (prec->right) {
            EXPECT_TRUE(prec->right->left && prec->right->left->term == "B", "AND left is B");
            EXPECT_TRUE(prec->right->right && prec->right->right->term == "C", "AND right is C");
        }
    }

    auto assoc = QueryParser::Parse("A AND B AND C");
    EXPECT_TRUE(assoc != nullptr && assoc->op == QueryOp::AND && assoc->left && assoc->left->op == QueryOp::AND,
                "AND is left-associative");

    const std::vector<std::string> invalid = {
        "",
        "   \t ",
        "AND",
        "OR",
        "NOT",
        "AND A",
        "OR A",
        "A AND",
        "A OR",
        "A AND OR B",
        "A OR AND B",
        "A B",
        "A NOT B",
        "A AND NOT"
    };
    for (const auto& q : invalid) {
        EXPECT_TRUE(QueryParser::Parse(q) == nullptr, "invalid query returns nullptr: '" + q + "'");
    }

    // 超长查询压力（500 个词 OR 拼接）不应栈溢出或崩溃
    std::string longQuery = "term0";
    for (int i = 1; i < 500; ++i) {
        longQuery += " OR term" + std::to_string(i);
    }
    EXPECT_TRUE(QueryParser::Parse(longQuery) != nullptr, "500-term OR query parses safely");
}

} // namespace

int main() {
    TestTfIdfExactValuesAndOrdering();
    TestBooleanTruthTableAndPrecedence();
    TestQueryParserAstAndMalformedBounds();

    if (g_failures > 0) {
        std::cerr << g_failures << " assertion(s) failed." << std::endl;
        return 1;
    }
    std::cout << "All SearchCorrectness tests passed!" << std::endl;
    return 0;
}
