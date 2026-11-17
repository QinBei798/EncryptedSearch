/**
 * @file SystemMonitor.hpp
 * @brief 跨平台系统环境与资源监控工具（CPU、编译器、物理内存峰值与容量格式化）
 */

#ifndef ENCRYPTEDSEARCH_SYSTEM_MONITOR_HPP
#define ENCRYPTEDSEARCH_SYSTEM_MONITOR_HPP

#include <cstdint>
#include <string>

/**
 * @struct MemoryStats
 * @brief 进程物理内存统计信息（单位：MB；负值表示当前平台或状态不可用）
 */
struct MemoryStats {
    double currentRssMB = -1.0; ///< 当前常驻物理内存 (VmRSS / WorkingSetSize)
    double peakRssMB    = -1.0; ///< 历史物理内存峰值 (VmHWM / PeakWorkingSetSize)

    bool IsValid() const { return peakRssMB >= 0.0; }
};

/**
 * @struct SystemInfo
 * @brief 运行环境硬件与编译器摘要信息
 */
struct SystemInfo {
    std::string  cpuModel;
    std::string  compilerInfo;
    unsigned int hardwareThreads = 0;
};

/**
 * @class SystemMonitor
 * @brief 提供跨平台（Linux / Windows）进程内存采样、硬件信息识别与格式化辅助接口
 */
class SystemMonitor {
public:
    /**
     * @brief 获取当前进程物理内存与峰值物理内存（Linux 读取 /proc/self/status 的 VmHWM/VmRSS）
     */
    static MemoryStats GetMemoryStats();

    /**
     * @brief 解析 Linux /proc/self/status 文本中的 VmRSS 与 VmHWM 字段
     */
    static MemoryStats ParseProcStatus(const std::string& content);

    /**
     * @brief 获取本机 CPU 型号名称
     */
    static std::string GetCPUName();

    /**
     * @brief 解析 Linux /proc/cpuinfo 文本提取 CPU 型号
     */
    static std::string ParseCpuInfo(const std::string& content);

    /**
     * @brief 获取当前编译器名称、版本及 C++ 标准
     */
    static std::string GetCompilerInfo();

    /**
     * @brief 获取完整系统环境摘要
     */
    static SystemInfo GetSystemInfo();

    /**
     * @brief 将字节数格式化为人类可读字符串（B / KB / MB / GB / TB）
     */
    static std::string FormatBytes(uint64_t bytes);
};

#endif // ENCRYPTEDSEARCH_SYSTEM_MONITOR_HPP
