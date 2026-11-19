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
    Relinker::ConversionInput input;
    input.InputPath = Io::NativePath("/input/eboot.bin");
    input.OutputPath = Io::NativePath("/output/eboot");
    input.ModuleRoot = "/input";
    input.Executable.assign(decoded->Executable.begin(), decoded->Executable.end());
    SilentProgress progress;
    try {
        Relinker::Conversion(progress).Convert(std::move(input), decoded->Options);
    } catch (const std::exception&) {
    }
    return 0;
}
