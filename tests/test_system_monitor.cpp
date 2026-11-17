/**
 * @file test_system_monitor.cpp
 * @brief SystemMonitor 单元测试（TDD）
 */

#include "core/SystemMonitor.hpp"

#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

int g_failures = 0;

void ExpectTrue(bool cond, const std::string& msg, int line) {
    if (!cond) {
        std::cerr << "[FAIL] Line " << line << ": " << msg << std::endl;
        ++g_failures;
    }
}

void ExpectEqStr(const std::string& actual, const std::string& expected, const std::string& msg, int line) {
    if (actual != expected) {
        std::cerr << "[FAIL] Line " << line << ": " << msg
                  << " | expected=\"" << expected << "\", actual=\"" << actual << "\"" << std::endl;
        ++g_failures;
    }
}

void ExpectNear(double actual, double expected, double tol, const std::string& msg, int line) {
    double diff = actual > expected ? (actual - expected) : (expected - actual);
    if (diff > tol) {
        std::cerr << "[FAIL] Line " << line << ": " << msg
                  << " | expected=" << expected << ", actual=" << actual << std::endl;
        ++g_failures;
    }
}

#define EXPECT_TRUE(cond, msg) ExpectTrue((cond), (msg), __LINE__)
#define EXPECT_EQ_STR(act, exp, msg) ExpectEqStr((act), (exp), (msg), __LINE__)
#define EXPECT_NEAR(act, exp, tol, msg) ExpectNear((act), (exp), (tol), (msg), __LINE__)

void TestFormatBytes() {
    EXPECT_EQ_STR(SystemMonitor::FormatBytes(0), "0 B", "zero bytes");
    EXPECT_EQ_STR(SystemMonitor::FormatBytes(512), "512 B", "sub-KB bytes");
    EXPECT_EQ_STR(SystemMonitor::FormatBytes(1024), "1.00 KB", "exact 1 KB");
    EXPECT_EQ_STR(SystemMonitor::FormatBytes(1536), "1.50 KB", "1.5 KB");
    EXPECT_EQ_STR(SystemMonitor::FormatBytes(1024ULL * 1024ULL), "1.00 MB", "exact 1 MB");
    EXPECT_EQ_STR(SystemMonitor::FormatBytes(5ULL * 1024ULL * 1024ULL * 1024ULL), "5.00 GB", "5 GB");
    EXPECT_EQ_STR(SystemMonitor::FormatBytes(2ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL), "2.00 TB", "2 TB");
}

void TestParseProcStatus() {
    const std::string sample =
        "Name:\tEncryptedSearch\n"
        "State:\tR (running)\n"
        "VmPeak:\t  210000 kB\n"
        "VmSize:\t  200000 kB\n"
        "VmHWM:\t  190054 kB\n"
        "VmRSS:\t  131072 kB\n";

    MemoryStats stats = SystemMonitor::ParseProcStatus(sample);
    EXPECT_TRUE(stats.IsValid(), "parsed proc status should be valid");
    EXPECT_NEAR(stats.peakRssMB, 190054.0 / 1024.0, 0.01, "VmHWM MB conversion");
    EXPECT_NEAR(stats.currentRssMB, 131072.0 / 1024.0, 0.01, "VmRSS MB conversion");

    MemoryStats emptyStats = SystemMonitor::ParseProcStatus("");
    EXPECT_TRUE(!emptyStats.IsValid(), "empty proc status should be invalid");
    EXPECT_NEAR(emptyStats.peakRssMB, -1.0, 0.001, "empty VmHWM should be -1");
    EXPECT_NEAR(emptyStats.currentRssMB, -1.0, 0.001, "empty VmRSS should be -1");

    const std::string malformed = "VmHWM:\tnot_a_number kB\nVmRSS:\t2048 kB\n";
    MemoryStats partial = SystemMonitor::ParseProcStatus(malformed);
    EXPECT_TRUE(!partial.IsValid(), "malformed VmHWM should keep peak invalid");
    EXPECT_NEAR(partial.currentRssMB, 2.0, 0.001, "valid VmRSS still parsed");

    const std::string badSuffix = "VmHWM:\t123abc kB\nVmRSS:\t1024 MB\n";
    MemoryStats rejected = SystemMonitor::ParseProcStatus(badSuffix);
    EXPECT_TRUE(!rejected.IsValid(), "invalid numeric suffix should be rejected");
    EXPECT_NEAR(rejected.currentRssMB, -1.0, 0.001, "non-kB unit should be rejected");
}

void TestParseCpuInfo() {
    const std::string x86Sample =
        "processor\t: 0\n"
        "vendor_id\t: GenuineIntel\n"
        "model name\t:   Intel(R) Core(TM) i7-13700H\n"
        "cpu MHz\t\t: 2400.000\n";
    EXPECT_EQ_STR(SystemMonitor::ParseCpuInfo(x86Sample), "Intel(R) Core(TM) i7-13700H", "x86 model name");

    const std::string armSample =
        "processor\t: 0\n"
        "BogoMIPS\t: 48.00\n"
        "Hardware\t: Apple Silicon M2\n";
    EXPECT_EQ_STR(SystemMonitor::ParseCpuInfo(armSample), "Apple Silicon M2", "ARM Hardware fallback");

    EXPECT_EQ_STR(SystemMonitor::ParseCpuInfo("processor : 0\n"), "Unknown CPU", "missing CPU model fallback");
}

void TestLiveSystemQueries() {
    // 分配并按页写入 16MB 内存，确保触发物理页分配使 VmHWM 真实增长
    std::vector<uint8_t> touchBuf(16 * 1024 * 1024, 0x5A);
    volatile uint8_t sink = 0;
    for (size_t i = 0; i < touchBuf.size(); i += 4096) {
        touchBuf[i] = static_cast<uint8_t>((i >> 12) & 0xFF);
        sink = touchBuf[i];
    }
    (void)sink;

    MemoryStats liveMem = SystemMonitor::GetMemoryStats();
    EXPECT_TRUE(liveMem.IsValid(), "live GetMemoryStats should succeed");
    EXPECT_TRUE(liveMem.peakRssMB >= 16.0, "peak RSS must reflect >=16MB allocated buffer");
    EXPECT_TRUE(liveMem.currentRssMB > 0.0, "current RSS must be positive");
    EXPECT_TRUE(liveMem.peakRssMB >= liveMem.currentRssMB, "peak RSS must be >= current RSS");

    std::string cpu = SystemMonitor::GetCPUName();
    EXPECT_TRUE(!cpu.empty(), "CPU name must be non-empty");

    std::string compiler = SystemMonitor::GetCompilerInfo();
    EXPECT_TRUE(!compiler.empty(), "Compiler info must be non-empty");
    EXPECT_TRUE(compiler.find("C++17") != std::string::npos, "Compiler info should mention C++17");

    SystemInfo info = SystemMonitor::GetSystemInfo();
    EXPECT_TRUE(info.hardwareThreads >= 1, "hardwareThreads must be >= 1");
    EXPECT_EQ_STR(info.cpuModel, cpu, "SystemInfo cpuModel matches GetCPUName");
    EXPECT_EQ_STR(info.compilerInfo, compiler, "SystemInfo compilerInfo matches GetCompilerInfo");
}

} // namespace

int main() {
    TestFormatBytes();
    TestParseProcStatus();
    TestParseCpuInfo();
    TestLiveSystemQueries();

    if (g_failures > 0) {
        std::cerr << g_failures << " assertion(s) failed." << std::endl;
        return 1;
    }
    std::cout << "All SystemMonitor tests passed!" << std::endl;
    return 0;
}
