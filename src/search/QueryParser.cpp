/**
 * @file QueryParser.cpp
 * @brief QueryParser 类的实现，基于递归下降算法的布尔查询解析
 * @author Antigravity
 * @date 2026-04-22
 */

#include <search/QueryParser.hpp>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <cctype>

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

    // 哨兵 Token，标识序列结束
    tokens.push_back({TokenType::END, ""});
    return tokens;
}

std::shared_ptr<QueryNode> QueryParser::ParsePrimary(const std::vector<Token>& tokens, size_t& pos) {
    if (pos < tokens.size() && tokens[pos].type == TokenType::WORD) {
        auto node = QueryNode::MakeTerm(tokens[pos].value);
        ++pos;
        return node;
    }
    std::cerr << "[QueryParser] 语法错误：此处应为关键词，位置: " << pos << std::endl;
    return nullptr;
}

std::shared_ptr<QueryNode> QueryParser::ParseUnary(const std::vector<Token>& tokens, size_t& pos) {
    if (pos < tokens.size() && tokens[pos].type == TokenType::NOT) {
        ++pos;
        auto operand = ParseUnary(tokens, pos); // 支持递归处理多重否定
        if (!operand) return nullptr;
        return QueryNode::MakeNot(operand);
    }
    return ParsePrimary(tokens, pos);
}

std::shared_ptr<QueryNode> QueryParser::ParseAnd(const std::vector<Token>& tokens, size_t& pos) {
    auto left = ParseUnary(tokens, pos);
    if (!left) return nullptr;

    while (pos < tokens.size() && tokens[pos].type == TokenType::AND) {
        ++pos;
        auto right = ParseUnary(tokens, pos);
        if (!right) return nullptr;
        left = QueryNode::MakeBinary(QueryOp::AND, left, right);
    }
    return left;
}

std::shared_ptr<QueryNode> QueryParser::ParseExpr(const std::vector<Token>& tokens, size_t& pos) {
    auto left = ParseAnd(tokens, pos);
    if (!left) return nullptr;

    while (pos < tokens.size() && tokens[pos].type == TokenType::OR) {
        ++pos;
        auto right = ParseAnd(tokens, pos);
        if (!right) return nullptr;
        left = QueryNode::MakeBinary(QueryOp::OR, left, right);
    }
    return left;
}

std::shared_ptr<QueryNode> QueryParser::Parse(const std::string& query) {
    if (query.empty()) {
        std::cerr << "[QueryParser] 错误：查询字符串为空。" << std::endl;
        return nullptr;
    }

    auto tokens = Tokenize(query);
    size_t pos = 0;
    auto root = ParseExpr(tokens, pos);

    // 验证是否完整解析了所有 Token
    if (root && pos < tokens.size() && tokens[pos].type != TokenType::END) {
        std::cerr << "[QueryParser] 语法错误：表达式后存在多余字符，位置: " << pos << std::endl;
        return nullptr;
    }

    return root;
}
