// Baseline comparison ("drift detection"): did anything new open since the last scan?
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "recon/report.hpp"

namespace recon {

struct Baseline {
    std::string path;
    std::vector<DriftEntry> open;  // every port the baseline report lists as open
};

// Parses a report previously produced by `recon --json`. Returns false with `error` set if the
// text is not valid JSON or is not a recon report (schema_version 1).
bool parse_baseline(std::string_view json_text, Baseline& out, std::string& error);

// Reads and parses a baseline file (refuses files over 64 MiB).
bool load_baseline(const std::string& path, Baseline& out, std::string& error);

Drift compute_drift(const ScanReport& current, const Baseline& base,
                    const std::vector<std::uint16_t>& tcp_scanned,
                    const std::vector<std::uint16_t>& udp_scanned);

}  // namespace recon
