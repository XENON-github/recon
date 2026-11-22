// libFuzzer target: JSON parser + baseline loader + report writer escaping.
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "recon/baseline.hpp"
#include "recon/json.hpp"
#include "recon/report.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    using namespace recon;
    const std::string_view in(reinterpret_cast<const char*>(data), size);
    (void)json::parse(in);
    Baseline b;
    std::string err;
    (void)parse_baseline(in, b, err);
    // Whatever bytes a hostile banner contains, our own output must remain valid JSON text.
    const std::string escaped = "\"" + json_escape(in) + "\"";
    if (!json::parse(escaped).value) __builtin_trap();
    (void)csv_field(in);
    return 0;
}
