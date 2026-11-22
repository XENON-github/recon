#include "recon/baseline.hpp"

#include <algorithm>
#include <fstream>
#include <iterator>
#include <set>
#include <tuple>

#include "recon/json.hpp"

namespace recon {

bool parse_baseline(std::string_view text, Baseline& out, std::string& error) {
    const json::ParseResult r = json::parse(text);
    if (!r.value) {
        error = "baseline is not valid JSON: " + r.error + " (at byte " + std::to_string(r.offset) + ")";
        return false;
    }
    const json::Value& root = *r.value;
    const json::Value* ver = root.find("schema_version");
    const json::Value* hosts = root.find("hosts");
    if (!root.is_object() || ver == nullptr || !ver->is_number() || ver->as_number() != 1.0 ||
        hosts == nullptr || !hosts->is_array()) {
        error = "baseline is not a recon report (expected schema_version 1 with a 'hosts' array)";
        return false;
    }
    out.open.clear();
    for (const json::Value& h : hosts->items()) {
        const json::Value* addr = h.find("address");
        const json::Value* ports = h.find("ports");
        if (addr == nullptr || !addr->is_string() || ports == nullptr || !ports->is_array()) continue;
        for (const json::Value& p : ports->items()) {
            const json::Value* num = p.find("port");
            const json::Value* proto = p.find("protocol");
            const json::Value* state = p.find("state");
            if (num == nullptr || proto == nullptr || state == nullptr || !num->is_number()) continue;
            if (state->as_string() != "open") continue;
            const double n = num->as_number();
            if (n < 1.0 || n > 65535.0) continue;  // ignore malformed entries rather than trusting them
            DriftEntry e;
            e.address = addr->as_string();
            e.protocol = proto->as_string();
            e.port = static_cast<std::uint16_t>(n);
            if (const json::Value* svc = p.find("service")) {
                if (const json::Value* name = svc->find("name")) e.service = name->as_string();
            }
            out.open.push_back(std::move(e));
        }
    }
    return true;
}

bool load_baseline(const std::string& path, Baseline& out, std::string& error) {
    constexpr std::streamoff kMax = 64LL * 1024 * 1024;
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        error = "cannot open baseline '" + path + "'";
        return false;
    }
    f.seekg(0, std::ios::end);
    const std::streamoff size = f.tellg();
    if (size < 0 || size > kMax) {
        error = "baseline '" + path + "' is too large or unreadable (limit 64 MiB)";
        return false;
    }
    f.seekg(0);
    const std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    out.path = path;
    return parse_baseline(text, out, error);
}

Drift compute_drift(const ScanReport& cur, const Baseline& base,
                    const std::vector<std::uint16_t>& tcp_scanned,
                    const std::vector<std::uint16_t>& udp_scanned) {
    using Key = std::tuple<std::string, std::string, std::uint16_t>;
    std::set<Key> now_open, base_open;
    std::set<std::string> hosts_now;
    for (const HostRecord& h : cur.hosts) {
        hosts_now.insert(h.address);
        for (const PortRecord& p : h.ports) {
            if (p.state == PortState::Open) now_open.emplace(h.address, to_string(p.protocol), p.port);
        }
    }
    for (const DriftEntry& e : base.open) base_open.emplace(e.address, e.protocol, e.port);

    Drift d;
    d.baseline_path = base.path;
    for (const HostRecord& h : cur.hosts) {
        for (const PortRecord& p : h.ports) {
            if (p.state != PortState::Open) continue;
            if (base_open.count(Key{h.address, to_string(p.protocol), p.port}) == 0) {
                d.new_open.push_back({h.address, to_string(p.protocol), p.port,
                                      p.detection ? p.detection->service : std::string()});
            }
        }
    }
    for (const DriftEntry& e : base.open) {
        const auto& scanned = e.protocol == "udp" ? udp_scanned : tcp_scanned;
        const bool covered = hosts_now.count(e.address) != 0 &&
                             std::binary_search(scanned.begin(), scanned.end(), e.port);
        if (covered && now_open.count(Key{e.address, e.protocol, e.port}) == 0) d.no_longer_open.push_back(e);
    }
    return d;
}

}  // namespace recon
