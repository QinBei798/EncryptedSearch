#ifndef ENCRYPTEDSEARCH_QUERYPARSER_HPP
#define ENCRYPTEDSEARCH_QUERYPARSER_HPP

// 预先引入与线程库相关的标准头，避免 MinGW include 顺序敏感问题
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <string>
#include <vector>
#include <memory>

// ──────────────────────────────────────────────
//  查询操作符
// ──────────────────────────────────────────────
enum class QueryOp {
    TERM,  // 叶子节点：单个关键词（直接查倒排索引）
    AND,   // 交集操作，分数 = scoreA + scoreB
    OR,    // 并集操作，分数 = max(scoreA, scoreB)
    NOT    // 一元否定（仅作为 AND 右子节点使用）
           // 结构：AND(left, NOT(nullptr, term))
};

// ──────────────────────────────────────────────
//  查询树节点 (AST)
// ──────────────────────────────────────────────
struct QueryNode {
    QueryOp op;
    std::string term;                   // 仅 TERM 节点使用
    std::shared_ptr<QueryNode> left;    // AND/OR 的左操作数；NOT 中为 nullptr
    std::shared_ptr<QueryNode> right;   // AND/OR 的右操作数；NOT 的被否定项

    // ── 工厂方法 ──

    // 创建叶子节点（关键词）
    static std::shared_ptr<QueryNode> MakeTerm(const std::string& t) {
        auto node = std::make_shared<QueryNode>();
        node->op = QueryOp::TERM;
        node->term = t;
        return node;
    }

    // 创建二元节点（AND / OR）
    static std::shared_ptr<QueryNode> MakeBinary(
        QueryOp op,
        std::shared_ptr<QueryNode> left,
        std::shared_ptr<QueryNode> right)
    {
        auto node = std::make_shared<QueryNode>();
        node->op = op;
        node->left = std::move(left);
        node->right = std::move(right);
        return node;
    }

    // 创建一元 NOT 节点（left = nullptr，right = 被否定项）
    static std::shared_ptr<QueryNode> MakeNot(std::shared_ptr<QueryNode> operand) {
        auto node = std::make_shared<QueryNode>();
        node->op = QueryOp::NOT;
        node->right = std::move(operand);
        return node;
    }
};

// ──────────────────────────────────────────────
//  查询解析器
//
//  支持扁平化布尔语法（无括号）：
//    TERM [AND|OR] TERM
//    TERM AND NOT TERM
//
//  操作符优先级（高到低）：NOT > AND > OR
//
//  示例：
//    "SM4 AND 国密"          → AND(TERM(SM4), TERM(国密))
//    "加密 OR 分词"          → OR(TERM(加密), TERM(分词))
//    "密码学 AND NOT SM3"    → AND(TERM(密码学), NOT(TERM(SM3)))
//    "C++ OR 国密 AND SM4"   → OR(TERM(C++), AND(TERM(国密), TERM(SM4)))
// ──────────────────────────────────────────────
class QueryParser {
public:
    // 解析查询字符串，返回查询树根节点
    // 失败（空串或格式错误）时返回 nullptr
    static std::shared_ptr<QueryNode> Parse(const std::string& query);

private:
    // ── Token ──
    enum class TokenType { WORD, AND, OR, NOT, END };

    struct Token {
        TokenType type;
        std::string value; // 仅 WORD 有效
    };

    // 词法分析：将查询字符串切分为 Token 序列
    // 规则：
    //   - 按空格分割
    //   - 大写 "AND" → TokenType::AND
    //   - 大写 "OR"  → TokenType::OR
    //   - 大写 "NOT" → TokenType::NOT
    //   - 其余       → TokenType::WORD
    static std::vector<Token> Tokenize(const std::string& query);

    // ── 递归下降解析（优先级：NOT > AND > OR） ──
    //
    //   ParseExpr    →  ParseAnd ( OR ParseAnd )*
    //   ParseAnd     →  ParseUnary ( AND ParseUnary )*
    //   ParseUnary   →  NOT ParseUnary | ParsePrimary
    //   ParsePrimary →  WORD
    //
    static std::shared_ptr<QueryNode> ParseExpr(
        const std::vector<Token>& tokens, size_t& pos);

    static std::shared_ptr<QueryNode> ParseAnd(
        const std::vector<Token>& tokens, size_t& pos);

    static std::shared_ptr<QueryNode> ParseUnary(
        const std::vector<Token>& tokens, size_t& pos);

    static std::shared_ptr<QueryNode> ParsePrimary(
        const std::vector<Token>& tokens, size_t& pos);
};

#endif // ENCRYPTEDSEARCH_QUERYPARSER_HPP
