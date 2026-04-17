#include <search/QueryParser.hpp>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <cctype>

// ─────────────────────────────────────────────────────────────────────────────
//  词法分析：将查询字符串切分为 Token 序列
// ─────────────────────────────────────────────────────────────────────────────
std::vector<QueryParser::Token> QueryParser::Tokenize(const std::string& query) {
    std::vector<Token> tokens;
    std::istringstream iss(query);
    std::string word;

    while (iss >> word) {
        Token tok;
        if (word == "AND") {
            tok.type = TokenType::AND;
        } else if (word == "OR") {
            tok.type = TokenType::OR;
        } else if (word == "NOT") {
            tok.type = TokenType::NOT;
        } else {
            tok.type = TokenType::WORD;
            tok.value = word;
        }
        tokens.push_back(tok);
    }

    // 尾部哨兵 Token，避免解析时越界检查
    tokens.push_back({TokenType::END, ""});
    return tokens;
}

// ─────────────────────────────────────────────────────────────────────────────
//  ParsePrimary → WORD
// ─────────────────────────────────────────────────────────────────────────────
std::shared_ptr<QueryNode> QueryParser::ParsePrimary(
    const std::vector<Token>& tokens, size_t& pos)
{
    if (pos < tokens.size() && tokens[pos].type == TokenType::WORD) {
        auto node = QueryNode::MakeTerm(tokens[pos].value);
        ++pos;
        return node;
    }
    // 非 WORD token（如意外的 AND/OR/END），解析失败
    std::cerr << "[QueryParser] Expected WORD token at position " << pos << std::endl;
    return nullptr;
}

// ─────────────────────────────────────────────────────────────────────────────
//  ParseUnary → NOT ParseUnary | ParsePrimary
// ─────────────────────────────────────────────────────────────────────────────
std::shared_ptr<QueryNode> QueryParser::ParseUnary(
    const std::vector<Token>& tokens, size_t& pos)
{
    if (pos < tokens.size() && tokens[pos].type == TokenType::NOT) {
        ++pos; // 消费 NOT
        auto operand = ParseUnary(tokens, pos); // 递归，支持 NOT NOT（双重否定）
        if (!operand) return nullptr;
        return QueryNode::MakeNot(operand);
    }
    return ParsePrimary(tokens, pos);
}

// ─────────────────────────────────────────────────────────────────────────────
//  ParseAnd → ParseUnary ( AND ParseUnary )*
//  优先级高于 OR，低于 NOT
// ─────────────────────────────────────────────────────────────────────────────
std::shared_ptr<QueryNode> QueryParser::ParseAnd(
    const std::vector<Token>& tokens, size_t& pos)
{
    auto left = ParseUnary(tokens, pos);
    if (!left) return nullptr;

    while (pos < tokens.size() && tokens[pos].type == TokenType::AND) {
        ++pos; // 消费 AND
        auto right = ParseUnary(tokens, pos);
        if (!right) return nullptr;
        left = QueryNode::MakeBinary(QueryOp::AND, left, right);
    }
    return left;
}

// ─────────────────────────────────────────────────────────────────────────────
//  ParseExpr → ParseAnd ( OR ParseAnd )*
//  优先级最低
// ─────────────────────────────────────────────────────────────────────────────
std::shared_ptr<QueryNode> QueryParser::ParseExpr(
    const std::vector<Token>& tokens, size_t& pos)
{
    auto left = ParseAnd(tokens, pos);
    if (!left) return nullptr;

    while (pos < tokens.size() && tokens[pos].type == TokenType::OR) {
        ++pos; // 消费 OR
        auto right = ParseAnd(tokens, pos);
        if (!right) return nullptr;
        left = QueryNode::MakeBinary(QueryOp::OR, left, right);
    }
    return left;
}

// ─────────────────────────────────────────────────────────────────────────────
//  主入口
// ─────────────────────────────────────────────────────────────────────────────
std::shared_ptr<QueryNode> QueryParser::Parse(const std::string& query) {
    if (query.empty()) {
        std::cerr << "[QueryParser] Empty query string." << std::endl;
        return nullptr;
    }

    auto tokens = Tokenize(query);
    size_t pos = 0;
    auto root = ParseExpr(tokens, pos);

    // 成功解析后，pos 应指向 END token
    if (root && pos < tokens.size() && tokens[pos].type != TokenType::END) {
        std::cerr << "[QueryParser] Unexpected token after expression at position "
                  << pos << std::endl;
        return nullptr;
    }

    return root;
}
