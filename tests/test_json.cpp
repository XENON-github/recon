#include <fstream>
#include <random>
#include <sstream>

#include "recon/baseline.hpp"
#include "recon/json.hpp"
#include "recon/options.hpp"
#include "recon/report.hpp"
#include "testing.hpp"

using namespace recon;
using std::string;

static bool ok(const string& t) { return json::parse(t).value.has_value(); }

TEST(json_accepts_valid_documents) {
    for (const char* t : {"null", "true", "false", "0", "-0", "12", "-1.5e+10", "1E2", "\"\"", "[]", "{}", " [1 , 2 ,\n3] ",
                          "{\"a\":{\"b\":[null,{\"c\":\"d\"}]}}", "\"\\u00e9\\n\\t\\\"\\\\\\/\"", "\"\\ud83d\\ude00\"", "\"caf\xc3\xa9\""}) {
        CHECK(ok(t));
    }
}

TEST(json_rejects_invalid_documents) {
    for (const char* t : {"", " ", "nul", "tru", "01", "1.", ".5", "+1", "1e", "--1", "[1,]", "[,1]", "{\"a\":1,}", "{a:1}", "{\"a\" 1}",
                          "[1 2]", "\"abc", "\"a\nb\"", "\"\\x41\"", "\"\\u12\"", "\"\\uZZZZ\"", "\"\\ud800\"", "\"\\udc00\"",
                          "\"\\ud800\\u0041\"", "[1] x", "{} {}", "'single'", "NaN", "Infinity", "\"\xff\"", "\"\xc3\"",
                          "\"\xc0\xaf\"", "\"\xed\xa0\x80\"", "[", "{\"a\":", "[[[["}) {
        CHECK(!ok(t));
    }
}

TEST(json_decodes_values_and_unicode) {
    auto r = json::parse("{\"s\":\"a\\u00e9\\ud83d\\ude00\",\"n\":-12.5e1,\"b\":true,\"arr\":[1,2,3],\"dup\":1,\"dup\":2}");
    CHECK(r.value.has_value());
    const auto& v = *r.value;
    CHECK_EQ(v.find("s")->as_string(), string("a\xc3\xa9\xf0\x9f\x98\x80"));
    CHECK_EQ(v.find("n")->as_number(), -125.0);
    CHECK(v.find("b")->as_bool());
    CHECK_EQ(v.find("arr")->items().size(), std::size_t(3));
    CHECK_EQ(v.find("dup")->as_number(), 1.0);  // first wins
    CHECK(v.find("missing") == nullptr);
    CHECK_EQ(v.find("n")->as_string(), string(""));  // wrong-type accessors are safe, not UB
}

TEST(json_depth_limit_prevents_stack_exhaustion) {
    const string deep(100000, '[');
    auto r = json::parse(deep);
    CHECK(!r.value.has_value());
    CHECK(r.error.find("deep") != string::npos);
    string nested = string(60, '[') + string(60, ']');
    CHECK(ok(nested));
    CHECK(!json::parse(string(65, '[') + string(65, ']')).value.has_value());
}

TEST(json_error_offsets_are_reported) {
    auto r = json::parse("[1, 2, @]");
    CHECK(!r.value.has_value());
    CHECK_EQ(r.offset, std::size_t(7));
}

TEST(json_fuzz_never_crashes) {
    std::mt19937 rng(12345);
    const string seeds[] = {"{\"a\":[1,2,{\"b\":\"c\\u00e9\"}],\"d\":null,\"e\":-1.5e3}", "[true,false,null,\"\\ud83d\\ude00\"]",
                            "{\"schema_version\":1,\"hosts\":[{\"address\":\"1.2.3.4\",\"ports\":[{\"port\":22,\"protocol\":\"tcp\",\"state\":\"open\"}]}]}"};
    for (int i = 0; i < 40000; ++i) {
        string d;
        if (i % 3 == 0) {
            d.resize(rng() % 200);
            for (auto& c : d) c = static_cast<char>(rng());
        } else {
            d = seeds[rng() % 3];
            for (unsigned m = 0, n = 1 + rng() % 5; m < n && !d.empty(); ++m) d[rng() % d.size()] = static_cast<char>(rng());
            if (rng() % 4 == 0 && !d.empty()) d.resize(rng() % d.size());
        }
        (void)json::parse(d);
    }
    CHECK(true);
}

TEST(json_roundtrip_of_our_own_report_output) {
    ScanReport r;
    r.started_utc = "2030-01-01T00:00:00Z";
    HostRecord h;
    h.address = "10.0.0.1";
    PortRecord p;
    p.port = 443;
    Detection d;
    d.service = "https";
    d.banner = string("weird \xff\x01\"\\ banner");
    d.tls_info = TlsInfo{};
    p.detection = d;
    h.ports.push_back(p);
    r.hosts.push_back(h);
    std::ostringstream os;
    write_json(os, r);
    auto parsed = json::parse(os.str());
    CHECK(parsed.value.has_value());
    CHECK_EQ(parsed.value->find("schema_version")->as_number(), 1.0);
}

// ---- baseline / drift ---------------------------------------------------------------------

static ScanReport report_with(std::initializer_list<std::pair<const char*, int>> open) {
    ScanReport r;
    for (auto& [addr, port] : open) {
        auto it = std::find_if(r.hosts.begin(), r.hosts.end(), [&](const HostRecord& h) { return h.address == addr; });
        if (it == r.hosts.end()) { r.hosts.push_back({}); r.hosts.back().address = addr; it = r.hosts.end() - 1; }
        PortRecord p;
        p.port = static_cast<std::uint16_t>(port);
        p.state = PortState::Open;
        Detection d;
        d.service = "svc" + std::to_string(port);
        p.detection = d;
        it->ports.push_back(p);
    }
    return r;
}

static Baseline baseline_of(const ScanReport& r) {
    std::ostringstream os;
    write_json(os, r);
    Baseline b;
    string err;
    CHECK(parse_baseline(os.str(), b, err));
    return b;
}

TEST(drift_detects_new_and_gone_ports) {
    const Baseline base = baseline_of(report_with({{"10.0.0.1", 22}, {"10.0.0.1", 80}, {"10.0.0.2", 443}}));
    CHECK_EQ(base.open.size(), std::size_t(3));
    ScanReport now = report_with({{"10.0.0.1", 22}, {"10.0.0.1", 8080}, {"10.0.0.2", 443}});
    const Drift d = compute_drift(now, base, {22, 80, 443, 8080}, {});
    CHECK_EQ(d.new_open.size(), std::size_t(1));
    CHECK_EQ(d.new_open[0].port, 8080);
    CHECK_EQ(d.new_open[0].service, string("svc8080"));
    CHECK_EQ(d.no_longer_open.size(), std::size_t(1));
    CHECK_EQ(d.no_longer_open[0].port, 80);
}

TEST(drift_ignores_ports_and_hosts_that_were_not_scanned) {
    const Baseline base = baseline_of(report_with({{"10.0.0.1", 22}, {"10.0.0.1", 3306}, {"10.0.0.9", 22}}));
    ScanReport now = report_with({});
    now.hosts.push_back({});
    now.hosts[0].address = "10.0.0.1";
    // Only port 22 was scanned, and host 10.0.0.9 was not targeted: 3306 and 10.0.0.9 must not be reported gone.
    const Drift d = compute_drift(now, base, {22}, {});
    CHECK_EQ(d.no_longer_open.size(), std::size_t(1));
    CHECK_EQ(d.no_longer_open[0].port, 22);
    CHECK(d.new_open.empty());
}

TEST(baseline_rejects_non_reports_and_survives_garbage) {
    Baseline b;
    string err;
    CHECK(!parse_baseline("not json", b, err));
    CHECK(!parse_baseline("{}", b, err));
    CHECK(!parse_baseline("{\"schema_version\":2,\"hosts\":[]}", b, err));
    CHECK(!parse_baseline("[]", b, err));
    CHECK(parse_baseline("{\"schema_version\":1,\"hosts\":[]}", b, err));
    // Malformed entries are skipped, never trusted (port 0, 70000, wrong types).
    CHECK(parse_baseline("{\"schema_version\":1,\"hosts\":[{\"address\":\"h\",\"ports\":[{\"port\":0,\"protocol\":\"tcp\",\"state\":\"open\"},"
                         "{\"port\":70000,\"protocol\":\"tcp\",\"state\":\"open\"},{\"port\":\"22\",\"protocol\":\"tcp\",\"state\":\"open\"},"
                         "{\"port\":22,\"protocol\":\"tcp\",\"state\":\"closed\"},{\"port\":23,\"protocol\":\"tcp\",\"state\":\"open\"}]},7,null]}", b, err));
    CHECK_EQ(b.open.size(), std::size_t(1));
    CHECK_EQ(b.open[0].port, 23);
    CHECK(!load_baseline("/nonexistent/baseline.json", b, err));
}

// ---- options: profiles, target files, new flags ---------------------------------------------

TEST(profiles_set_defaults_and_flags_override) {
    Options o;
    string e;
    CHECK(parse_args({"h", "--profile", "stealth"}, o, e) == ParseStatus::Ok);
    CHECK(o.tcp_common);
    CHECK_EQ(o.rate, 20.0);
    CHECK_EQ(o.max_inflight, std::size_t(8));
    CHECK_EQ(o.retries, 2);
    Options o2;
    CHECK(parse_args({"h", "--rate", "50", "--profile=stealth"}, o2, e) == ParseStatus::Ok);  // flag order must not matter
    CHECK_EQ(o2.rate, 50.0);
    CHECK_EQ(o2.max_inflight, std::size_t(8));
    Options o3;
    CHECK(parse_args({"h", "--profile", "full"}, o3, e) == ParseStatus::Ok);
    CHECK(o3.tcp_all);
    Options o4;
    CHECK(parse_args({"h", "--profile", "nope"}, o4, e) == ParseStatus::Error);
    CHECK(e.find("quick") != string::npos);
}

TEST(target_file_line_length_is_bounded) {
    const string path = "/tmp/recon_longline_test.txt";
    { std::ofstream f(path); f << "10.0.0.1\n" << string(5000, 'a') << "\n10.0.0.2\n"; }
    std::vector<string> t;
    string e;
    CHECK(!read_target_file(path, t, e));
    CHECK(e.find("line 2") != string::npos && e.find("4096") != string::npos);
    { std::ofstream f(path); f << string(4096, 'a') << "\n"; }   // exactly at the limit is accepted
    t.clear();
    CHECK(read_target_file(path, t, e));
    CHECK_EQ(t.size(), std::size_t(1));
    { std::ofstream f(path); f << "10.0.0.1"; }                    // no trailing newline
    t.clear();
    CHECK(read_target_file(path, t, e));
    CHECK_EQ(t, (std::vector<string>{"10.0.0.1"}));
    { std::ofstream f(path); f << "\n\n  \n#only a comment\n"; }  // nothing but blanks and comments
    t.clear();
    CHECK(read_target_file(path, t, e));
    CHECK(t.empty());
    std::remove(path.c_str());
}

TEST(target_file_parsing) {
    const string path = "/tmp/recon_targets_test.txt";
    { std::ofstream f(path); f << "# lab\n10.0.0.1\n\n  10.0.0.2   # web\r\nexample.org\n#10.9.9.9\n"; }
    std::vector<string> t;
    string e;
    CHECK(read_target_file(path, t, e));
    CHECK_EQ(t, (std::vector<string>{"10.0.0.1", "10.0.0.2", "example.org"}));
    Options o;
    CHECK(parse_args({"-iL", path, "-pCT", "--baseline", "b.json", "--color", "never", "--no-progress", "--banner-wait", "2500"}, o, e) == ParseStatus::Ok);
    CHECK_EQ(o.banner_wait_ms, 2500);
    CHECK_EQ(o.targets.size(), std::size_t(3));
    CHECK(o.baseline_path == "b.json" && o.color == AutoMode::Off && o.progress == AutoMode::Off);
    CHECK(!read_target_file("/nonexistent/targets", t, e));
    Options bad;
    CHECK(parse_args({"h", "-pCT", "--color", "rainbow"}, bad, e) == ParseStatus::Error);
    std::remove(path.c_str());
}

// ---- table colour must never change layout --------------------------------------------------

static string strip_ansi(const string& s) {
    string out;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\x1b') { while (i < s.size() && s[i] != 'm') ++i; continue; }
        out.push_back(s[i]);
    }
    return out;
}

TEST(color_table_has_identical_layout_to_plain) {
    ScanReport r = report_with({{"10.0.0.1", 22}, {"10.0.0.1", 8080}});
    r.drift = Drift{"base.json", {{"10.0.0.1", "tcp", 8080, "http"}}, {{"10.0.0.1", "tcp", 80, "http"}}};
    std::ostringstream plain, color;
    write_table(plain, r, TableStyle{false});
    write_table(color, r, TableStyle{true});
    CHECK(color.str().find("\x1b[32m") != string::npos);
    CHECK(plain.str().find('\x1b') == string::npos);
    CHECK_EQ(strip_ansi(color.str()), plain.str());
    CHECK(plain.str().find("+ NEW OPEN") != string::npos && plain.str().find("- NO LONGER") != string::npos);
}

TEST(json_node_limit_bounds_memory_amplification) {
    // A tiny-valued array is the worst case for memory: ~2 bytes of input become one Value object.
    string many = "[";
    for (int i = 0; i < 1000; ++i) many += "1,";
    many += "1]";  // 1001 elements + the array itself = 1002 values
    CHECK(json::parse(many, 64, 2000).value.has_value());
    auto r = json::parse(many, 64, 1000);
    CHECK(!r.value.has_value());
    CHECK(r.error.find("too many values") != string::npos);
    // The limit counts values at every depth, not just the top level.
    string nested = "[";
    for (int i = 0; i < 40; ++i) nested += "[1,2,3],";
    nested += "[]]";
    CHECK(!json::parse(nested, 64, 100).value.has_value());
    CHECK(json::parse(nested, 64, 1000).value.has_value());
    // The default limit is generous enough for a real report with tens of thousands of ports.
    CHECK(json::parse("{\"a\":[1,2,3]}").value.has_value());
}
