// Scan orchestration: ties the reactor, worker pool, probe engine and report model together.
#pragma once

#include <vector>

#include "recon/options.hpp"
#include "recon/report.hpp"

namespace recon {

// Runs the whole scan described by `opt` against `targets`. Honours `cancel` (returns partial
// results with summary.status == "cancelled"). Throws std::runtime_error on fatal failures.
ScanReport run_scan(const Options& opt, const std::vector<Target>& targets, const CancelToken& cancel);

}  // namespace recon
