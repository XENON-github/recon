// Safe report output. Reports map infrastructure, so they are written private by default and
// never through a symbolic link planted at the destination.
#pragma once

#include <string>
#include <string_view>

namespace recon {

// Writes `data` to `path`:
//  * a new file is created with mode 0600 (an existing file keeps its mode);
//  * the final path component is opened with O_NOFOLLOW, so a symlink is refused rather than followed
//    (protects predictable names in shared directories such as /tmp);
//  * the whole payload goes through one descriptor (no create-then-reopen race), with EINTR and
//    partial writes handled.
// On failure returns false and sets `error` to a one-line message.
bool write_file_private(const std::string& path, std::string_view data, std::string& error);

}  // namespace recon
