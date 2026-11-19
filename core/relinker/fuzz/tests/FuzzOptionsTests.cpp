#include "../FuzzOptions.hpp"
#include <relinker/pipeline/Conversion.hpp>
#include <io/NativePath.hpp>
#include <array>
#include <cstdint>
#include <exception>
#include <functional>
#include <sstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

using Relinker::ConversionOptions;
using Relinker::TargetSystem;
using namespace Relinker::Fuzz;

class SilentProgress final : public Domain::IProgress {
public:
    void Report(const Domain::ProgressEvent&) override {}
    void Message(std::string_view) override {}
};

std::string hex(const std::uint64_t value) {
    std::ostringstream text;
    text << "0x" << std::hex << value;
    return text.str();
}

void require(const bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

bool sameExtendedFields(const ConversionOptions& left, const ConversionOptions& right) {
    return left.ToRosetta == right.ToRosetta && left.ToAvx == right.ToAvx && left.FrameRedZone == right.FrameRedZone
        && left.SkipSyscallCheck == right.SkipSyscallCheck && left.TrapSdkSyscallStubs == right.TrapSdkSyscallStubs
        && left.FunctionSymbolRoots == right.FunctionSymbolRoots && left.LazyBinding == right.LazyBinding
        && left.OmitUnavailableDependencies == right.OmitUnavailableDependencies && left.WindowsGui == right.WindowsGui
        && left.TraceImports == right.TraceImports && left.WindowsFixedBase == right.WindowsFixedBase
        && left.WindowsDiagnostics == right.WindowsDiagnostics && left.LinuxFixedBase == right.LinuxFixedBase
        && left.MacosFixedBase == right.MacosFixedBase;
}

void legacySelectorsKeepTheirMeaning() {
    const std::array<std::uint8_t, 4> executable{0x7f, 'E', 'L', 'F'};
    unsigned legacy = 0;
    for (unsigned selector = 0; selector < 256; ++selector) {
        if (HasExtendedOptions(static_cast<std::uint8_t>(selector))) continue;
        ++legacy;
        std::vector<std::uint8_t> data{static_cast<std::uint8_t>(selector)};
        data.insert(data.end(), executable.begin(), executable.end());
        const auto decoded = DecodeFuzzInput(data);
        require(decoded.has_value(), "a legacy selector was not decoded: " + std::to_string(selector));
        const auto expectedTarget = selector % 3 == 0 ? TargetSystem::Linux : selector % 3 == 1 ? TargetSystem::Windows : TargetSystem::MacOs;
        require(decoded->Options.Target == expectedTarget, "legacy target changed for selector " + std::to_string(selector));
        require(decoded->Options.ToIntel == ((selector & 4) != 0), "legacy --to-intel changed for selector " + std::to_string(selector));
        require(decoded->Options.UnusedFilterLevel == (selector >> 3) % 3, "legacy filter level changed for selector " + std::to_string(selector));
        require(sameExtendedFields(decoded->Options, ConversionOptions{}), "a legacy selector enabled an extended option: " + std::to_string(selector));
        require(decoded->Executable.size() == executable.size() && decoded->Executable.data() == data.data() + 1, "a legacy selector did not pass the remaining bytes through: " + std::to_string(selector));
    }
    require(legacy == 24, "expected 24 legacy selectors, found " + std::to_string(legacy));
    require(!DecodeFuzzInput({}).has_value(), "an empty input was decoded");
}

void extendedSelectorsNeedTheirOptionWords() {
    for (unsigned selector = 0; selector < 256; ++selector) {
        if (!HasExtendedOptions(static_cast<std::uint8_t>(selector))) continue;
        for (std::size_t size = 1; size < 3; ++size) {
            const std::vector<std::uint8_t> data(size, static_cast<std::uint8_t>(selector));
            require(!DecodeFuzzInput(data).has_value(), "an extended selector without its option word was decoded: " + std::to_string(selector));
        }
        const std::vector<std::uint8_t> data{static_cast<std::uint8_t>(selector), 0, 0, 0x7f};
        const auto decoded = DecodeFuzzInput(data);
        require(decoded.has_value() && decoded->Executable.size() == 1 && decoded->Executable.data() == data.data() + 3, "an extended selector did not skip its option word: " + std::to_string(selector));
    }
}

void fixedBasesAreValidAddresses() {
    for (unsigned index = 0; index < 16; ++index) {
        const auto base = FixedBaseFor(static_cast<std::uint16_t>(index << FixedBaseShift));
        require(base >= 0x20000 && base <= HighestFixedBase && base % 0x10000 == 0, "fixed base " + hex(base) + " is outside the addresses the command line accepts");
    }
}

void everyExtendedConfigurationPassesConversionValidation() {
    SilentProgress progress;
    std::array<bool, 16> reached{};
    std::array<std::function<bool(const ConversionOptions&)>, 12> fields{
        [](const ConversionOptions& options) { return options.ToRosetta; },
        [](const ConversionOptions& options) { return options.ToAvx; },
        [](const ConversionOptions& options) { return options.FrameRedZone; },
        [](const ConversionOptions& options) { return options.LazyBinding; },
        [](const ConversionOptions& options) { return options.SkipSyscallCheck; },
        [](const ConversionOptions& options) { return options.TrapSdkSyscallStubs; },
        [](const ConversionOptions& options) { return options.FunctionSymbolRoots; },
        [](const ConversionOptions& options) { return options.OmitUnavailableDependencies; },
        [](const ConversionOptions& options) { return options.WindowsGui; },
        [](const ConversionOptions& options) { return options.TraceImports; },
        [](const ConversionOptions& options) { return options.WindowsDiagnostics; },
        [](const ConversionOptions& options) { return options.WindowsFixedBase || options.LinuxFixedBase || options.MacosFixedBase; }};
    unsigned checked = 0;
    for (unsigned target = 0; target < 3; ++target) {
        for (unsigned intel = 0; intel < 2; ++intel) {
            const auto selector = static_cast<std::uint8_t>(target | (intel << 2) | (3u << 3));
            for (unsigned extended = 0; extended < 0x10000; ++extended) {
                const std::array<std::uint8_t, 3> data{selector, static_cast<std::uint8_t>(extended), static_cast<std::uint8_t>(extended >> 8)};
                const auto decoded = DecodeFuzzInput(data);
                require(decoded.has_value() && decoded->Executable.empty(), "an extended configuration was not decoded");
                for (std::size_t field = 0; field < fields.size(); ++field) reached[field] = reached[field] || fields[field](decoded->Options);
                Relinker::ConversionInput input;
                input.InputPath = Io::NativePath("/input/eboot.bin");
                input.OutputPath = Io::NativePath("/output/eboot");
                input.ModuleRoot = "/input";
                std::string failure = "conversion accepted an empty executable";
                try {
                    static_cast<void>(Relinker::Conversion(progress).Convert(std::move(input), decoded->Options));
                } catch (const std::exception& error) {
                    failure = error.what();
                }
                require(failure == "File too small for ELF header", "selector " + std::to_string(selector) + " with options " + hex(extended) + " was refused before the executable was read: " + failure);
                ++checked;
            }
        }
    }
    for (std::size_t field = 0; field < fields.size(); ++field) require(reached[field], "extended option bit " + std::to_string(field) + " never reaches the conversion options");
    std::cout << checked << " extended fuzzer configurations pass conversion option validation\n";
}

}

int main() {
    try {
        legacySelectorsKeepTheirMeaning();
        extendedSelectorsNeedTheirOptionWords();
        fixedBasesAreValidAddresses();
        everyExtendedConfigurationPassesConversionValidation();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
