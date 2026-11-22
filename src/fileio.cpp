#include "recon/fileio.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "recon/net.hpp"

namespace recon {

bool write_file_private(const std::string& path, std::string_view data, std::string& error) {
    net::UniqueFd fd(::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600));
    if (!fd) {
        error = errno == ELOOP ? "refusing to write through a symbolic link: '" + path + "'"
                               : "cannot open '" + path + "' for writing";
        return false;
    }
    struct stat st {};
    if (::fstat(fd.get(), &st) == 0 && S_ISDIR(st.st_mode)) {  // defensive: O_WRONLY already fails on dirs
        error = "'" + path + "' is a directory";
        return false;
    }
    std::size_t off = 0;
    while (off < data.size()) {
        const ssize_t n = ::write(fd.get(), data.data() + off, data.size() - off);
        if (n > 0) {
            off += static_cast<std::size_t>(n);
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            error = "failed writing '" + path + "': " + std::strerror(errno);
            return false;
        }
    }
    return true;
}

}  // namespace recon
