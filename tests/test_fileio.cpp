#include <sys/stat.h>
#include <unistd.h>

#include <fstream>
#include <sstream>

#include "recon/fileio.hpp"
#include "testing.hpp"

using namespace recon;

namespace {
std::string tmpdir() {
    char t[] = "/tmp/recon_fio_XXXXXX";
    return ::mkdtemp(t) != nullptr ? std::string(t) : std::string();
}
unsigned mode_of(const std::string& p) {
    struct stat st {};
    return ::stat(p.c_str(), &st) == 0 ? (st.st_mode & 0777U) : 0U;
}
std::string slurp(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}
}  // namespace

TEST(fileio_creates_private_files_and_roundtrips) {
    const std::string d = tmpdir(), p = d + "/out.json";
    std::string err;
    const std::string big(300000, 'x');  // larger than a pipe/socket buffer: exercises the write loop
    CHECK(write_file_private(p, big, err));
    CHECK_EQ(mode_of(p), 0600u);
    CHECK_EQ(slurp(p), big);
    // Overwriting truncates, and an existing file keeps its (possibly looser) mode: we never widen or silently narrow it.
    ::chmod(p.c_str(), 0640);
    CHECK(write_file_private(p, "short", err));
    CHECK_EQ(slurp(p), std::string("short"));
    CHECK_EQ(mode_of(p), 0640u);
    ::unlink(p.c_str());
    ::rmdir(d.c_str());
}

TEST(fileio_refuses_symlinks_and_bad_paths) {
    const std::string d = tmpdir(), victim = d + "/victim", link = d + "/link";
    { std::ofstream f(victim); f << "precious"; }
    CHECK(::symlink(victim.c_str(), link.c_str()) == 0);
    std::string err;
    CHECK(!write_file_private(link, "attacker data", err));
    CHECK(err.find("symbolic link") != std::string::npos);
    CHECK_EQ(slurp(victim), std::string("precious"));  // the target was NOT overwritten
    CHECK(!write_file_private(d + "/no/such/dir/x", "d", err));
    CHECK(err.find("cannot open") != std::string::npos);
    CHECK(!write_file_private(d, "d", err));              // a directory
    CHECK(!write_file_private("/proc/nonexistent/x", "d", err));
    ::unlink(link.c_str()); ::unlink(victim.c_str()); ::rmdir(d.c_str());
}
