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

# 6. 自动将分词词典拷贝到生成目录，确保程序能运行
# MSVC 输出在 build/Debug/，MinGW 输出在 build/，两处都拷贝
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/third_party/cppjieba/dict"
     DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/third_party/cppjieba")
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/third_party/cppjieba/dict"
     DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/Debug/third_party/cppjieba")