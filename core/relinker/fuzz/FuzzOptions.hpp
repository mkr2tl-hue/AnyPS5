#pragma once

#include <relinker/pipeline/Conversion.hpp>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <span>
#include <vector>

namespace Relinker::Fuzz {

enum ExtendedOption : std::uint16_t {
    OptionRosetta = 1u << 0,
    OptionAvx = 1u << 1,
    OptionFrameRedZone = 1u << 2,
    OptionLazyBinding = 1u << 3,
    OptionSkipSyscallCheck = 1u << 4,
    OptionTrapSdkSyscallStubs = 1u << 5,
    OptionFunctionSymbolRoots = 1u << 6,
    OptionOmitUnavailableDependencies = 1u << 7,
    OptionWindowsGui = 1u << 8,
    OptionTraceImports = 1u << 9,
    OptionWindowsDiagnostics = 1u << 10,
    OptionFixedBase = 1u << 11
};

inline constexpr unsigned FixedBaseShift = 12;
inline constexpr std::uint64_t HighestFixedBase = 0x7fffffff0000;

struct FuzzCase {
    ConversionOptions Options;
    std::span<const std::uint8_t> Executable;
};

[[nodiscard]] constexpr bool HasExtendedOptions(const std::uint8_t selector) {
    return (selector >> 3) >= 3;
}

[[nodiscard]] constexpr std::uint64_t FixedBaseFor(const std::uint16_t options) {
    const unsigned index = (options >> FixedBaseShift) & 0x0f;
    return index == 0x0f ? HighestFixedBase : static_cast<std::uint64_t>(index + 2) << (16 + index);
}

[[nodiscard]] inline std::optional<FuzzCase> DecodeFuzzInput(const std::span<const std::uint8_t> data) {
    if (data.empty()) return std::nullopt;
    const std::uint8_t selector = data[0];
    FuzzCase result;
    auto& options = result.Options;
    switch (selector % 3) {
    case 0: options.Target = TargetSystem::Linux; break;
    case 1: options.Target = TargetSystem::Windows; break;
    default: options.Target = TargetSystem::MacOs; break;
    }
    options.ToIntel = (selector & 0x04) != 0;
    options.UnusedFilterLevel = (selector >> 3) % 3;
    if (!HasExtendedOptions(selector)) {
        result.Executable = data.subspan(1);
        return result;
    }
    if (data.size() < 3) return std::nullopt;
    const auto extended = static_cast<std::uint16_t>(data[1] | (data[2] << 8));
    result.Executable = data.subspan(3);
    const bool onLinux = options.Target == TargetSystem::Linux;
    const bool onWindows = options.Target == TargetSystem::Windows;
    const bool onMacos = options.Target == TargetSystem::MacOs;
    const auto has = [&](const ExtendedOption option) { return (extended & option) != 0; };
    options.ToRosetta = has(OptionRosetta) && !onWindows;
    options.ToAvx = has(OptionAvx) && onMacos;
    if (options.ToRosetta || options.ToAvx) options.ToIntel = true;
    options.FrameRedZone = has(OptionFrameRedZone) && onWindows;
    options.LazyBinding = has(OptionLazyBinding);
    options.SkipSyscallCheck = has(OptionSkipSyscallCheck);
    options.TrapSdkSyscallStubs = has(OptionTrapSdkSyscallStubs) && !options.SkipSyscallCheck;
    options.FunctionSymbolRoots = has(OptionFunctionSymbolRoots);
    options.OmitUnavailableDependencies = has(OptionOmitUnavailableDependencies) && onLinux;
    options.WindowsGui = has(OptionWindowsGui) && onWindows;
    options.TraceImports = has(OptionTraceImports) && !options.LazyBinding;
    options.WindowsDiagnostics = has(OptionWindowsDiagnostics) && onWindows;
    if (has(OptionFixedBase)) {
        const auto base = FixedBaseFor(extended);
        if (onWindows) options.WindowsFixedBase = base;
        else if (onMacos) options.MacosFixedBase = base;
        else if (!options.LazyBinding) options.LinuxFixedBase = base;
    }
    return result;
}

inline constexpr std::size_t MaxGuestModules = 4;
inline constexpr std::size_t MaxModuleNameLength = 64;

[[nodiscard]] inline std::string ModuleFileName(const std::span<const std::uint8_t> name, const std::size_t index) {
    const auto allowed = [](const std::uint8_t character) {
        return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-';
    };
    std::string text(name.begin(), name.end());
    if (text.empty() || text.size() > MaxModuleNameLength || text == "." || text == ".." || !std::all_of(name.begin(), name.end(), allowed))
        return "libFuzz" + std::to_string(index) + ".prx";
    return text;
}

[[nodiscard]] inline std::vector<std::span<const std::uint8_t>> SplitRecords(std::span<const std::uint8_t> data, const std::size_t maxRecords) {
    std::vector<std::span<const std::uint8_t>> records;
    while (records.size() < maxRecords && data.size() >= 4) {
        const std::size_t length = static_cast<std::size_t>(data[0]) | static_cast<std::size_t>(data[1]) << 8
            | static_cast<std::size_t>(data[2]) << 16 | static_cast<std::size_t>(data[3]) << 24;
        data = data.subspan(4);
        if (length > data.size()) break;
        records.push_back(data.first(length));
        data = data.subspan(length);
    }
    return records;
}

}
