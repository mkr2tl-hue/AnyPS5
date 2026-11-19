#include "FuzzOptions.hpp"
#include <relinker/pipeline/Conversion.hpp>
#include <io/NativePath.hpp>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <string_view>

namespace {

class SilentProgress final : public Domain::IProgress {
public:
    void Report(const Domain::ProgressEvent&) override {}
    void Message(std::string_view) override {}
};

}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    auto decoded = Relinker::Fuzz::DecodeFuzzInput({data, size});
    if (!decoded) return 0;
    const auto records = Relinker::Fuzz::SplitRecords(decoded->Executable, 1 + 2 * Relinker::Fuzz::MaxGuestModules);
    if (records.size() < 3) return 0;
    auto options = decoded->Options;
    options.LazyBinding = false;
    Relinker::ConversionInput input;
    input.InputPath = Io::NativePath("/input/eboot.bin");
    input.OutputPath = Io::NativePath("/output/eboot");
    input.ModuleRoot = "/input";
    input.Executable.assign(records.front().begin(), records.front().end());
    for (std::size_t index = 1; index + 1 < records.size(); index += 2)
        input.Modules.push_back({Io::NativePath("/input/sce_module/" + Relinker::Fuzz::ModuleFileName(records[index], index / 2)), {records[index + 1].begin(), records[index + 1].end()}, {}});
    SilentProgress progress;
    try {
        Relinker::Conversion(progress).Convert(std::move(input), options);
    } catch (const std::exception&) {
    }
    return 0;
}
