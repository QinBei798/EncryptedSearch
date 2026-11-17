cmake_minimum_required(VERSION 3.15)
# Triggering reconfigure to detect sm4_cbc.c
project(EncryptedSearch LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON) # 为 clangd 生成索引数据库

# 1. 包含路径：告诉编译器去 include 文件夹找 gmssl/sm3.h
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/third_party/cppjieba/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/third_party/cppjieba/deps/limonp/include)

# 1. 自动搜集所有源文件
file(GLOB_RECURSE SOURCES 
    "src/*.cpp" 
    "src/core/*.c"
)

if(MSVC)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_compile_options(/utf-8) # 强制 MSVC 使用 UTF-8 编码读取源文件
endif()

# 3. 创建可执行文件
add_executable(${PROJECT_NAME} ${SOURCES})

# 4. 设置包含路径 (现代 CMake 方式)
target_include_directories(${PROJECT_NAME} PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/cppjieba/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/cppjieba/deps/limonp/include
)

# 5. 链接库：多线程和 Filesystem (MinGW 8.1.0 必须链接 stdc++fs)
find_package(Threads REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE 
    Threads::Threads
)

if(CMAKE_COMPILER_IS_GNUCXX)
    target_link_libraries(${PROJECT_NAME} PRIVATE stdc++fs)
endif()

if(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE psapi)
endif()

# 6. 自动将分词词典拷贝到生成目录，确保程序能运行
# MSVC 输出在 build/Debug/，MinGW 输出在 build/，两处都拷贝
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/third_party/cppjieba/dict"
     DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/third_party/cppjieba")
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/third_party/cppjieba/dict"
     DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/Debug/third_party/cppjieba")

# 7. 单元测试配置 (CTest)
enable_testing()
add_executable(test_system_monitor
    tests/test_system_monitor.cpp
    src/core/SystemMonitor.cpp
)
target_include_directories(test_system_monitor PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
if(WIN32)
    target_link_libraries(test_system_monitor PRIVATE psapi)
endif()
add_test(NAME SystemMonitorTests COMMAND test_system_monitor)

add_executable(test_indexer
    tests/test_indexer.cpp
    src/index/Indexer.cpp
    src/index/ParallelHasher.cpp
    src/core/CryptoEngine.cpp
    src/core/hex.c
    src/core/sm3.c
    src/core/sm3_digest.c
    src/core/sm3_hmac.c
    src/core/sm3_pbkdf2.c
    src/core/sm4.c
    src/core/sm4_cbc.c
)
target_include_directories(test_indexer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/cppjieba/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/cppjieba/deps/limonp/include
)
target_link_libraries(test_indexer PRIVATE Threads::Threads)
if(CMAKE_COMPILER_IS_GNUCXX)
    target_link_libraries(test_indexer PRIVATE stdc++fs)
endif()
add_test(NAME IndexerTests COMMAND test_indexer)

add_executable(test_parallel_hasher
    tests/test_parallel_hasher.cpp
    src/index/ParallelHasher.cpp
    src/core/CryptoEngine.cpp
    src/core/SystemMonitor.cpp
    src/core/hex.c
    src/core/sm3.c
    src/core/sm3_digest.c
    src/core/sm3_hmac.c
    src/core/sm3_pbkdf2.c
    src/core/sm4.c
    src/core/sm4_cbc.c
)
target_include_directories(test_parallel_hasher PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/cppjieba/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/cppjieba/deps/limonp/include
)
target_link_libraries(test_parallel_hasher PRIVATE Threads::Threads)
if(CMAKE_COMPILER_IS_GNUCXX)
    target_link_libraries(test_parallel_hasher PRIVATE stdc++fs)
endif()
if(WIN32)
    target_link_libraries(test_parallel_hasher PRIVATE psapi)
endif()
add_test(NAME ParallelHasherTests COMMAND test_parallel_hasher)

add_executable(test_crypto_engine
    tests/test_crypto_engine.cpp
    src/core/CryptoEngine.cpp
    src/core/hex.c
    src/core/sm3.c
    src/core/sm3_digest.c
    src/core/sm3_hmac.c
    src/core/sm3_pbkdf2.c
    src/core/sm4.c
    src/core/sm4_cbc.c
)
target_include_directories(test_crypto_engine PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
add_test(NAME CryptoEngineTests COMMAND test_crypto_engine)

add_executable(test_searcher_blind_index
    tests/test_searcher_blind_index.cpp
    src/index/Indexer.cpp
    src/index/ParallelHasher.cpp
    src/search/Searcher.cpp
    src/search/QueryParser.cpp
    src/core/CryptoEngine.cpp
    src/core/hex.c
    src/core/sm3.c
    src/core/sm3_digest.c
    src/core/sm3_hmac.c
    src/core/sm3_pbkdf2.c
    src/core/sm4.c
    src/core/sm4_cbc.c
)
target_include_directories(test_searcher_blind_index PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/cppjieba/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/cppjieba/deps/limonp/include
)
target_link_libraries(test_searcher_blind_index PRIVATE Threads::Threads)
if(CMAKE_COMPILER_IS_GNUCXX)
    target_link_libraries(test_searcher_blind_index PRIVATE stdc++fs)
endif()
add_test(NAME SearcherBlindIndexTests COMMAND test_searcher_blind_index)

add_executable(test_completeness_e2e
    tests/test_completeness_e2e.cpp
    src/index/Indexer.cpp
    src/index/ParallelHasher.cpp
    src/search/Searcher.cpp
    src/search/QueryParser.cpp
    src/core/CryptoEngine.cpp
    src/core/hex.c
    src/core/sm3.c
    src/core/sm3_digest.c
    src/core/sm3_hmac.c
    src/core/sm3_pbkdf2.c
    src/core/sm4.c
    src/core/sm4_cbc.c
)
target_include_directories(test_completeness_e2e PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/cppjieba/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/cppjieba/deps/limonp/include
)
target_link_libraries(test_completeness_e2e PRIVATE Threads::Threads)
if(CMAKE_COMPILER_IS_GNUCXX)
    target_link_libraries(test_completeness_e2e PRIVATE stdc++fs)
endif()
add_test(NAME CompletenessE2ETests COMMAND test_completeness_e2e)

find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
    add_test(
        NAME CliRealMonitoringTest
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cli_monitoring.py
            $<TARGET_FILE:${PROJECT_NAME}>
            ${CMAKE_CURRENT_SOURCE_DIR}
    )
    add_test(
        NAME CliColdStartTest
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cli_cold_start.py
            $<TARGET_FILE:${PROJECT_NAME}>
            ${CMAKE_CURRENT_SOURCE_DIR}
    )
endif()