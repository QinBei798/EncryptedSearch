/**
 * @file SystemMonitor.cpp
 * @brief SystemMonitor 类的跨平台实现
 */

#include "core/SystemMonitor.hpp"

#include <cctype>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#elif defined(__linux__)
#include <sys/resource.h>
#include <sys/utsname.h>
#endif

namespace {

std::string Trim(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) {
        ++start;
    }
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) {
        --end;
    }
    return s.substr(start, end - start);
}

bool ReadWholeFile(const std::string& path, std::string& out) {
    std::ifstream in(path);
    if (!in.is_open()) {
        return false;
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    out = ss.str();
    return true;
}

bool TryParseProcKbField(const std::string& line, const std::string& prefix, double& outMB) {
    if (line.compare(0, prefix.size(), prefix) != 0) {
        return false;
    }
    std::string rest = Trim(line.substr(prefix.size()));
    if (rest.empty()) {
        return false;
    }
    char* endPtr = nullptr;
    double kb = std::strtod(rest.c_str(), &endPtr);
    if (endPtr == rest.c_str() || kb < 0.0) {
        return false;
    }
    if (*endPtr != '\0' && !std::isspace(static_cast<unsigned char>(*endPtr))) {
        return false;
    }
    std::string unit = Trim(endPtr);
    if (!unit.empty() && unit != "kB" && unit != "KB") {
        return false;
    }
    outMB = kb / 1024.0;
    return true;
}

std::string ExtractCpuField(const std::string& content, const std::string& key) {
    std::istringstream iss(content);
    std::string line;
    while (std::getline(iss, line)) {
        size_t colon = line.find(':');
        if (colon == std::string::npos) {
            continue;
        }
        if (Trim(line.substr(0, colon)) == key) {
            std::string val = Trim(line.substr(colon + 1));
            if (!val.empty()) {
                return val;
            }
        }
    }
    return "";
}

std::string GetCppStandardLabel() {
#ifdef _MSVC_LANG
    long ver = _MSVC_LANG;
#else
    long ver = __cplusplus;
#endif
    if (ver >= 202002L) return "C++20";
    if (ver >= 201703L) return "C++17";
    if (ver >= 201402L) return "C++14";
    if (ver >= 201103L) return "C++11";
    return "C++";
}

} // namespace

MemoryStats SystemMonitor::ParseProcStatus(const std::string& content) {
    MemoryStats stats;
    std::istringstream iss(content);
    std::string line;
    while (std::getline(iss, line)) {
        TryParseProcKbField(line, "VmHWM:", stats.peakRssMB);
        TryParseProcKbField(line, "VmRSS:", stats.currentRssMB);
    }
    return stats;
}

MemoryStats SystemMonitor::GetMemoryStats() {
#ifdef _WIN32
    MemoryStats stats;
    PROCESS_MEMORY_COUNTERS pmc{};
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        constexpr double kBytesPerMB = 1024.0 * 1024.0;
        stats.currentRssMB = static_cast<double>(pmc.WorkingSetSize) / kBytesPerMB;
        stats.peakRssMB    = static_cast<double>(pmc.PeakWorkingSetSize) / kBytesPerMB;
    }
    return stats;
#elif defined(__linux__)
    MemoryStats stats;
    std::string content;
    if (ReadWholeFile("/proc/self/status", content)) {
        stats = ParseProcStatus(content);
    }
    if (stats.peakRssMB < 0.0) {
        struct rusage ru{};
        if (getrusage(RUSAGE_SELF, &ru) == 0 && ru.ru_maxrss >= 0) {
            stats.peakRssMB = static_cast<double>(ru.ru_maxrss) / 1024.0;
        }
    }
    return stats;
#else
    return {};
#endif
}

std::string SystemMonitor::ParseCpuInfo(const std::string& content) {
    const std::vector<std::string> candidateKeys = {"model name", "Model", "Hardware", "Processor"};
    for (const auto& key : candidateKeys) {
        std::string val = ExtractCpuField(content, key);
        if (!val.empty()) {
            return val;
        }
    }
    return "Unknown CPU";
}

std::string SystemMonitor::GetCPUName() {
#ifdef _WIN32
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buffer[256] = {0};
        DWORD bufferSize = sizeof(buffer);
        if (RegQueryValueExA(hKey, "ProcessorNameString", nullptr, nullptr,
                             reinterpret_cast<LPBYTE>(buffer), &bufferSize) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            std::string name = Trim(buffer);
            if (!name.empty()) {
                return name;
            }
        } else {
            RegCloseKey(hKey);
        }
    }
    return "Unknown CPU";
#elif defined(__linux__)
    std::string content;
    if (ReadWholeFile("/proc/cpuinfo", content)) {
        std::string cpu = ParseCpuInfo(content);
        if (cpu != "Unknown CPU") {
            return cpu;
        }
    }
    struct utsname uts{};
    if (uname(&uts) == 0 && uts.machine[0] != '\0') {
        return std::string(uts.machine);
    }
    return "Unknown CPU";
#else
    return "Unknown CPU";
#endif
}

std::string SystemMonitor::GetCompilerInfo() {
    std::ostringstream oss;
#if defined(__clang__)
    oss << "Clang " << __clang_major__ << "." << __clang_minor__ << "." << __clang_patchlevel__;
#elif defined(__GNUC__)
    oss << "GCC " << __GNUC__ << "." << __GNUC_MINOR__ << "." << __GNUC_PATCHLEVEL__;
#elif defined(_MSC_VER)
    oss << "MSVC " << _MSC_VER;
#else
    oss << "Unknown Compiler";
#endif
    oss << " (" << GetCppStandardLabel() << ")";
    return oss.str();
}

SystemInfo SystemMonitor::GetSystemInfo() {
    SystemInfo info;
    info.cpuModel        = GetCPUName();
    info.compilerInfo    = GetCompilerInfo();
    unsigned int threads = std::thread::hardware_concurrency();
    info.hardwareThreads = threads > 0 ? threads : 1;
    return info;
}

std::string SystemMonitor::FormatBytes(uint64_t bytes) {
    if (bytes < 1024ULL) {
        return std::to_string(bytes) + " B";
    }
    static const char* kUnits[] = {"B", "KB", "MB", "GB", "TB"};
    double value = static_cast<double>(bytes);
    size_t unitIdx = 0;
    while (value >= 1024.0 && unitIdx < 4) {
        value /= 1024.0;
        ++unitIdx;
    }
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << value << " " << kUnits[unitIdx];
    return oss.str();
}
