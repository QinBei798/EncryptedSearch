/**
 * @file QueryParser.hpp
 * @brief 布尔查询解析器，支持关键词组合查询（AND, OR, NOT）
 * @author Antigravity
 * @date 2026-04-22
 */

#ifndef ENCRYPTEDSEARCH_QUERYPARSER_HPP
#define ENCRYPTEDSEARCH_QUERYPARSER_HPP

#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <string>
#include <vector>
#include <memory>

/**
 * @enum QueryOp
 * @brief 查询操作符枚举
 */
enum class QueryOp {
    TERM,  ///< 叶子节点：单个关键词
    AND,   ///< 交集操作
    OR,    ///< 并集操作
    NOT    ///< 否定操作（仅作为 AND 的右子节点）
};

/**
 * @struct QueryNode
 * @brief 抽象语法树 (AST) 节点结构
 */
struct QueryNode {
    QueryOp op;                         ///< 操作类型
    std::string term;                   ///< 关键词（仅 TERM 节点有效）
    std::shared_ptr<QueryNode> left;    ///< 左子节点
    std::shared_ptr<QueryNode> right;   ///< 右子节点

    /**
     * @brief 创建关键词叶子节点
     */
    static std::shared_ptr<QueryNode> MakeTerm(const std::string& t) {
        auto node = std::make_shared<QueryNode>();
        node->op = QueryOp::TERM;
        node->term = t;
        return node;
    }

    /**
     * @brief 创建二元逻辑节点
     */
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

    /**
     * @brief 创建一元 NOT 节点
     */
    static std::shared_ptr<QueryNode> MakeNot(std::shared_ptr<QueryNode> operand) {
        auto node = std::make_shared<QueryNode>();
        node->op = QueryOp::NOT;
        node->right = std::move(operand);
        return node;
    }
};

/**
 * @class QueryParser
 * @brief 将查询字符串解析为 AST 树
 * 
 * 优先级规则：NOT > AND > OR
 * 示例语法："A AND B OR C AND NOT D"
 */
class QueryParser {
public:
    /**
     * @brief 解析原始查询字符串
     * @param query 查询表达式
     * @return AST 根节点，解析失败返回 nullptr
     */
    static std::shared_ptr<QueryNode> Parse(const std::string& query);

private:
    enum class TokenType { WORD, AND, OR, NOT, END };

    struct Token {
        TokenType type;
        std::string value;
    };

    /**
     * @brief 词法分析：切分 Token
     */
    static std::vector<Token> Tokenize(const std::string& query);

    /**
     * @brief 递归下降解析：逻辑表达式
     */
    static std::shared_ptr<QueryNode> ParseExpr(const std::vector<Token>& tokens, size_t& pos);

    /**
     * @brief 递归下降解析：AND 优先级
     */
    static std::shared_ptr<QueryNode> ParseAnd(const std::vector<Token>& tokens, size_t& pos);

    /**
     * @brief 递归下降解析：一元操作符
     */
    static std::shared_ptr<QueryNode> ParseUnary(const std::vector<Token>& tokens, size_t& pos);

    /**
     * @brief 递归下降解析：基础项（单词）
     */
    static std::shared_ptr<QueryNode> ParsePrimary(const std::vector<Token>& tokens, size_t& pos);
};

#endif // ENCRYPTEDSEARCH_QUERYPARSER_HPP
