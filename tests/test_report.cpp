#include <sstream>

#include "recon/report.hpp"
#include "testing.hpp"

using namespace recon;
using std::string;

TEST(json_escape_basics) {
    CHECK_EQ(json_escape("a\"b\\c\n\t\r"), string("a\\\"b\\\\c\\n\\t\\r"));
    CHECK_EQ(json_escape(string("\x01\x1f\x7f", 3)), string("\\u0001\\u001f\\u007f"));
    CHECK_EQ(json_escape("plain"), string("plain"));
}

TEST(json_escape_utf8_validation) {
    CHECK_EQ(json_escape("caf\xc3\xa9"), string("caf\xc3\xa9"));                 // valid 2-byte kept
    CHECK_EQ(json_escape("\xe2\x82\xac"), string("\xe2\x82\xac"));               // euro sign
    CHECK_EQ(json_escape("\xf0\x9f\x98\x80"), string("\xf0\x9f\x98\x80"));       // emoji
    CHECK_EQ(json_escape("\xff"), string("\\ufffd"));                            // invalid lead
    CHECK_EQ(json_escape("\xc3"), string("\\ufffd"));                            // truncated
    CHECK_EQ(json_escape("\xc0\xaf"), string("\\ufffd\\ufffd"));                 // overlong '/'
    CHECK_EQ(json_escape("\xed\xa0\x80"), string("\\ufffd\\ufffd\\ufffd"));      // surrogate
    CHECK_EQ(json_escape("\xf4\x90\x80\x80"), string("\\ufffd\\ufffd\\ufffd\\ufffd"));  // > U+10FFFF
    CHECK_EQ(json_escape("a\x80z"), string("a\\ufffdz"));                        // stray continuation
}

TEST(csv_quoting_and_formula_injection) {
    CHECK_EQ(csv_field("plain"), string("plain"));
    CHECK_EQ(csv_field("a,b"), string("\"a,b\""));
    CHECK_EQ(csv_field("say \"hi\""), string("\"say \"\"hi\"\"\""));
    CHECK_EQ(csv_field("=cmd|' /C calc'!A0"), string("'=cmd|' /C calc'!A0"));
    CHECK_EQ(csv_field("+1"), string("'+1"));
    CHECK_EQ(csv_field("@SUM(A1)"), string("'@SUM(A1)"));
    CHECK_EQ(csv_field("line\nbreak"), string("\"line\nbreak\""));
}

static ScanReport sample() {
    ScanReport r;
    r.started_utc = "2030-01-01T00:00:00Z";
    r.summary.hosts = 1;
    r.summary.open = 1;
    HostRecord h;
    h.address = "127.0.0.1";
    PortRecord p;
    p.port = 22;
    Detection d;
    d.service = "ssh";
    d.product = "Open\"SSH";
    d.version = "9.6";
    d.banner = "SSH-2.0-x,y";
    d.confidence = 98;
    d.version_quality = VersionQuality::Reported;
    p.detection = d;
    h.ports.push_back(p);
    r.hosts.push_back(h);
    return r;
}

TEST(json_report_structure) {
    std::ostringstream os;
    write_json(os, sample());
    const string j = os.str();
    CHECK(j.find("\"schema_version\": 1") != string::npos);
    CHECK(j.find("\"version_quality\": \"reported\"") != string::npos);
    CHECK(j.find("\"product\": \"Open\\\"SSH\"") != string::npos);
    CHECK(j.find("\"summary\"") != string::npos);
    int depth = 0;  // braces/brackets balance outside of strings
    bool in_str = false;
    for (std::size_t i = 0; i < j.size(); ++i) {
        const char c = j[i];
        if (in_str) { if (c == '\\') ++i; else if (c == '"') in_str = false; continue; }
        if (c == '"') in_str = true;
        else if (c == '{' || c == '[') ++depth;
        else if (c == '}' || c == ']') --depth;
        CHECK(depth >= 0);
    }
    CHECK_EQ(depth, 0);
}

TEST(csv_report_rows) {
    std::ostringstream os;
    write_csv(os, sample());
    const string c = os.str();
    CHECK(c.rfind("host,hostname,port,protocol,state,service", 0) == 0);
    CHECK(c.find("\"Open\"\"SSH\"") != string::npos);
    CHECK(c.find("\"SSH-2.0-x,y\"") != string::npos);
}

TEST(table_marks_guesses) {
    ScanReport r = sample();
    Detection g;
    g.service = "http";
    g.confidence = 25;
    g.method = "port-guess";
    PortRecord p;
    p.port = 80;
    p.detection = g;
    r.hosts[0].ports.push_back(p);
    std::ostringstream os;
    write_table(os, r);
    CHECK(os.str().find("http?") != string::npos);
}

TEST(table_does_not_double_wrap_parenthesised_extra) {
    ScanReport r = sample();
    Detection d;
    d.service = "http"; d.product = "Apache"; d.version = "2.4.58"; d.extra = "(Ubuntu)"; d.confidence = 95; d.version_quality = VersionQuality::Reported;
    PortRecord p; p.port = 80; p.detection = d;
    r.hosts[0].ports.push_back(p);
    std::ostringstream os;
    write_table(os, r);
    CHECK(os.str().find("Apache 2.4.58 (Ubuntu)") != std::string::npos);
    CHECK(os.str().find("((Ubuntu))") == std::string::npos);
}
