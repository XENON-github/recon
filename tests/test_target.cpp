#include "recon/options.hpp"
#include "recon/target.hpp"
#include "testing.hpp"

using namespace recon;

TEST(ports_valid) {
    std::vector<std::uint16_t> p;
    std::string e;
    CHECK(parse_port_spec("443,22,80-82,22", p, e));
    CHECK_EQ(p, (std::vector<std::uint16_t>{22, 80, 81, 82, 443}));  // sorted, de-duplicated
}

TEST(ports_reject_garbage) {
    for (const char* bad : {"80abc", "0", "65536", "80-", "-80", "443-80", "80,,443", "", "1e3", "0x50", "80 90", "99999999999999999999"}) {
        std::vector<std::uint16_t> p;
        std::string e;
        CHECK(!parse_port_spec(bad, p, e));
        CHECK(!e.empty());
    }
}

TEST(ports_full_range) {
    std::vector<std::uint16_t> p;
    std::string e;
    CHECK(parse_port_spec("1-65535", p, e));
    CHECK_EQ(p.size(), std::size_t(65535));
}

TEST(ip_parse) {
    CHECK(net::IpAddress::parse("127.0.0.1").has_value());
    CHECK(net::IpAddress::parse("::1").has_value());
    CHECK(net::IpAddress::parse("2001:db8::ff").has_value());
    CHECK_EQ(net::IpAddress::parse("2001:db8::ff")->to_string(), std::string("2001:db8::ff"));
    CHECK(!net::IpAddress::parse("256.1.1.1").has_value());
    CHECK(!net::IpAddress::parse("1.2.3").has_value());
    CHECK(!net::IpAddress::parse("[::1]").has_value());
    CHECK(!net::IpAddress::parse("").has_value());
    CHECK(net::IpAddress::parse("::1")->is_loopback());
    CHECK(net::IpAddress::parse("127.9.9.9")->is_loopback());
    CHECK(!net::IpAddress::parse("10.0.0.1")->is_loopback());
}

TEST(endpoint_formats) {
    CHECK_EQ(net::Endpoint(*net::IpAddress::parse("10.1.2.3"), 80).to_string(), std::string("10.1.2.3:80"));
    CHECK_EQ(net::Endpoint(*net::IpAddress::parse("::1"), 443).to_string(), std::string("[::1]:443"));
    CHECK_EQ(net::Endpoint(*net::IpAddress::parse("::1"), 443).family(), AF_INET6);
}

TEST(cidr_v4) {
    std::vector<net::IpAddress> v;
    std::string e;
    CHECK(expand_cidr("192.168.1.0/30", 1024, v, e));
    CHECK_EQ(v.size(), std::size_t(4));
    CHECK_EQ(v.front().to_string(), std::string("192.168.1.0"));
    CHECK_EQ(v.back().to_string(), std::string("192.168.1.3"));
    v.clear();
    CHECK(expand_cidr("10.0.0.77/32", 1024, v, e));
    CHECK_EQ(v.size(), std::size_t(1));
    v.clear();  // host bits set in the base address are masked off
    CHECK(expand_cidr("10.0.0.77/24", 1024, v, e));
    CHECK_EQ(v.size(), std::size_t(256));
    CHECK_EQ(v.front().to_string(), std::string("10.0.0.0"));
    CHECK_EQ(v.back().to_string(), std::string("10.0.0.255"));
}

TEST(cidr_carry_across_octets) {
    std::vector<net::IpAddress> v;
    std::string e;
    CHECK(expand_cidr("10.0.0.254/31", 8, v, e));
    CHECK(expand_cidr("10.0.1.0/31", 8, v, e));
    CHECK_EQ(v[1].to_string(), std::string("10.0.0.255"));
    CHECK_EQ(v[2].to_string(), std::string("10.0.1.0"));
    std::vector<net::IpAddress> w;
    CHECK(expand_cidr("10.0.0.255/31", 8, w, e));  // masked to .254/31
    CHECK_EQ(w.front().to_string(), std::string("10.0.0.254"));
}

TEST(cidr_v6) {
    std::vector<net::IpAddress> v;
    std::string e;
    CHECK(expand_cidr("fd00::/126", 16, v, e));
    CHECK_EQ(v.size(), std::size_t(4));
    CHECK_EQ(v[3].to_string(), std::string("fd00::3"));
}

TEST(cidr_limits_and_errors) {
    std::vector<net::IpAddress> v;
    std::string e;
    CHECK(!expand_cidr("10.0.0.0/8", 1024, v, e));   // too many hosts
    CHECK(e.find("max-hosts") != std::string::npos);
    CHECK(!expand_cidr("2001:db8::/32", 1024, v, e));
    CHECK(!expand_cidr("::/0", 1024, v, e));          // 2^128 must not overflow the shift
    CHECK(!expand_cidr("10.0.0.0/33", 1024, v, e));
    CHECK(!expand_cidr("10.0.0.0/", 1024, v, e));
    CHECK(!expand_cidr("10.0.0.0/2x", 1024, v, e));
    CHECK(!expand_cidr("nonsense/24", 1024, v, e));
    CHECK(v.empty());
}

TEST(resolve_aliases_literals_and_dedupe) {
    std::vector<Target> t;
    std::string e;
    CHECK(resolve_targets({"localhost", "127.0.0.1", "::1", "10.0.0.0/31"}, {}, t, e));
    CHECK_EQ(t.size(), std::size_t(4));  // 127.0.0.1 de-duplicated against the alias
    CHECK_EQ(t[0].label, std::string("localhost"));
    std::vector<Target> bad;
    CHECK(!resolve_targets({"definitely-not-a-real-host.invalid"}, {}, bad, e));
    CHECK(!e.empty());
}

TEST(options_parse) {
    Options o;
    std::string e;
    CHECK(parse_args({"127.0.0.1", "-p", "22,80", "--json", "--rate=250", "--timeout", "800", "--fail-on-open"}, o, e) == ParseStatus::Ok);
    CHECK(o.format == OutputFormat::Json);
    CHECK_EQ(o.rate, 250.0);
    CHECK_EQ(o.timeout_ms, 800);
    CHECK(o.fail_on_open);
    CHECK_EQ(o.tcp_ports(), (std::vector<std::uint16_t>{22, 80}));
}

TEST(options_reject) {
    auto status = [](std::vector<std::string> a) {
        Options o;
        std::string e;
        return parse_args(a, o, e);
    };
    CHECK(status({"-pCT"}) == ParseStatus::Error);                         // no target
    CHECK(status({"127.0.0.1"}) == ParseStatus::Error);                    // no action
    CHECK(status({"127.0.0.1", "-pCT", "--bogus"}) == ParseStatus::Error);
    CHECK(status({"127.0.0.1", "-p"}) == ParseStatus::Error);              // missing value
    CHECK(status({"127.0.0.1", "-pCT", "--timeout", "abc"}) == ParseStatus::Error);
    CHECK(status({"127.0.0.1", "-pCT", "--retries", "-1"}) == ParseStatus::Error);
    CHECK(status({"127.0.0.1", "-pCT", "--rate", "nan"}) == ParseStatus::Error);
    CHECK(status({"127.0.0.1", "-pCT", "-4", "-6"}) == ParseStatus::Error);
    CHECK(status({"-h"}) == ParseStatus::Help);
    CHECK(status({"--version"}) == ParseStatus::Version);
}

TEST(options_all_flag_and_legacy) {
    Options o;
    std::string e;
    CHECK(parse_args({"localhost", "-A"}, o, e) == ParseStatus::Ok);
    CHECK(o.tcp_common && o.os_detect && o.detect_services);
    Options o2;
    CHECK(parse_args({"-ip", "1.2.3.4", "-pAU", "--no-sV"}, o2, e) == ParseStatus::Ok);
    CHECK(o2.udp_all && !o2.detect_services);
    CHECK_EQ(o2.udp_ports().size(), std::size_t(65535));
}
