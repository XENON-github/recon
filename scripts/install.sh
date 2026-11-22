#!/usr/bin/env bash
# Build and install recon.  Needs only a C++17 compiler; uses CMake when it is available.
#
#   ./scripts/install.sh                     install for the current user (~/.local) - no sudo needed
#   sudo ./scripts/install.sh                install system-wide (/usr/local)
#   ./scripts/install.sh --prefix /opt/recon
#   ./scripts/install.sh --install-deps      install missing build dependencies first (asks before using sudo)
#   ./scripts/install.sh --test              run the test suite before installing
#   ./scripts/install.sh --uninstall         remove what a previous install put under the prefix
#
# Options: --prefix DIR  --system  --no-openssl  --std 17|20  --no-cmake  --build-only  --test
#          --install-deps  --yes  --uninstall  --deps  --no-hardening  -h|--help
#
# Safe by construction: builds only inside ./build, installs only under the prefix, and never runs a
# recursive delete.  Uninstall removes an explicit list of files, then empty directories.
set -euo pipefail

PREFIX=""; OPENSSL=AUTO; STD=17; USE_CMAKE=auto; BUILD_ONLY=0; RUN_TESTS=0; DEPS_ONLY=0
INSTALL_DEPS=0; ASSUME_YES=0; UNINSTALL=0; SYSTEM=0; HARDEN=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) [[ $# -ge 2 ]] || { echo "--prefix needs a directory" >&2; exit 2; }; PREFIX="$2"; shift 2 ;;
    --system) SYSTEM=1; shift ;;
    --no-openssl) OPENSSL=OFF; shift ;;
    --std) [[ $# -ge 2 ]] || { echo "--std needs 17 or 20" >&2; exit 2; }; STD="$2"; shift 2 ;;
    --no-cmake) USE_CMAKE=no; shift ;;
    --build-only) BUILD_ONLY=1; shift ;;
    --test) RUN_TESTS=1; shift ;;
    --install-deps) INSTALL_DEPS=1; shift ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --deps) DEPS_ONLY=1; shift ;;
    --no-hardening) HARDEN=0; shift ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
done
[[ "$STD" == 17 || "$STD" == 20 ]] || { echo "--std must be 17 or 20" >&2; exit 2; }

say()  { printf '\033[1m[*]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

[[ "$(uname -s)" == Linux ]] || die "recon supports Linux only (it uses epoll)"
cd "$(dirname "$0")/.."

# ---- prefix: per-user by default, system-wide when root or --system ------------------------------
if [[ -z "$PREFIX" ]]; then
  if [[ $SYSTEM == 1 || $EUID -eq 0 ]]; then PREFIX=/usr/local; else PREFIX="$HOME/.local"; fi
fi

# ---- distro-specific dependency command ------------------------------------------------------------
if [[ -r /etc/os-release ]]; then . /etc/os-release; fi
case "${ID:-}:${ID_LIKE:-}" in
  *debian*|*ubuntu*) DEPS_CMD="apt-get install -y build-essential cmake libssl-dev python3" ;;
  *fedora*|*rhel*|*centos*) DEPS_CMD="dnf install -y gcc-c++ cmake openssl-devel python3" ;;
  *arch*) DEPS_CMD="pacman -S --needed --noconfirm base-devel cmake openssl python" ;;
  *suse*) DEPS_CMD="zypper install -y gcc-c++ cmake libopenssl-devel python3" ;;
  *alpine*) DEPS_CMD="apk add build-base cmake openssl-dev python3" ;;
  *) DEPS_CMD="" ;;
esac
if [[ $DEPS_ONLY == 1 ]]; then
  echo "${DEPS_CMD:+sudo }${DEPS_CMD:-(install a C++17 compiler; optionally CMake >= 3.16 and the OpenSSL development headers)}"
  exit 0
fi

# ---- uninstall (explicit file list; no recursive deletes) ------------------------------------------
if [[ $UNINSTALL == 1 ]]; then
  say "removing recon from $PREFIX"
  files=("$PREFIX/bin/recon" "$PREFIX/share/man/man1/recon.1"
         "$PREFIX/share/bash-completion/completions/recon" "$PREFIX/share/zsh/site-functions/_recon"
         "$PREFIX/share/doc/recon/README.md" "$PREFIX/share/doc/recon/LICENSE" "$PREFIX/share/doc/recon/MANUAL.md"
         "$PREFIX/share/doc/recon/ARCHITECTURE.md" "$PREFIX/share/recon/scripts/cert_expiry.py"
         "$PREFIX/share/recon/scripts/drift_cron.sh")
  removed=0
  for f in "${files[@]}"; do
    if [[ -e "$f" || -L "$f" ]]; then rm -f -- "$f" && removed=$((removed + 1)); fi
  done
  rmdir "$PREFIX/share/recon/scripts" "$PREFIX/share/recon" "$PREFIX/share/doc/recon" 2>/dev/null || true
  say "removed $removed file(s). recon keeps no configuration or state, so nothing else remains."
  exit 0
fi

# ---- dependencies ----------------------------------------------------------------------------------
CXX_BIN="${CXX:-}"
if [[ -z "$CXX_BIN" ]]; then for c in g++ c++ clang++; do command -v "$c" >/dev/null 2>&1 && { CXX_BIN="$c"; break; }; done; fi
if [[ -z "$CXX_BIN" ]] && [[ $INSTALL_DEPS == 1 ]]; then
  [[ -n "$DEPS_CMD" ]] || die "cannot install dependencies automatically on this distribution; install a C++17 compiler manually"
  say "will run: sudo $DEPS_CMD"
  if [[ $ASSUME_YES != 1 ]]; then read -r -p "Proceed? [y/N] " ans; [[ "$ans" == [yY]* ]] || die "aborted"; fi
  # shellcheck disable=SC2086
  sudo $DEPS_CMD
  for c in g++ c++ clang++; do command -v "$c" >/dev/null 2>&1 && { CXX_BIN="$c"; break; }; done
fi
if [[ -z "$CXX_BIN" ]]; then
  warn "no C++ compiler found."
  [[ -n "$DEPS_CMD" ]] && warn "install the dependencies with:  sudo $DEPS_CMD   (or re-run with --install-deps)"
  exit 1
fi
CMAKE_OK=0
if [[ $USE_CMAKE != no ]] && command -v cmake >/dev/null 2>&1; then
  ver=$(cmake --version | head -1 | sed -E 's/[^0-9]*([0-9]+)\.([0-9]+).*/\1 \2/')
  read -r cmaj cmin <<<"$ver"
  if (( cmaj > 3 || (cmaj == 3 && cmin >= 16) )); then CMAKE_OK=1; fi
fi
say "compiler: $CXX_BIN ($("$CXX_BIN" --version | head -1)); build method: $([[ $CMAKE_OK == 1 ]] && echo CMake || echo 'direct compiler invocation (no CMake)')"
say "install prefix: $PREFIX"

mkdir -p build
JOBS=$(nproc 2>/dev/null || echo 2)

# ---- build ------------------------------------------------------------------------------------------
if [[ $CMAKE_OK == 1 ]]; then
  GEN=(); command -v ninja >/dev/null 2>&1 && GEN=(-G Ninja)
  cmake -S . -B build "${GEN[@]}" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" -DCMAKE_CXX_COMPILER="$CXX_BIN" \
        -DRECON_CXX_STANDARD="$STD" -DRECON_WITH_OPENSSL="$OPENSSL" -DRECON_HARDENING="$([[ $HARDEN == 1 ]] && echo ON || echo OFF)"
  cmake --build build -j"$JOBS"
  BIN=build/recon
  if [[ $RUN_TESTS == 1 ]]; then ctest --test-dir build --output-on-failure; fi
else
  # Sources are globbed so this path can never drift from the real file list.
  mapfile -t SRCS < <(ls src/*.cpp | grep -v tls_openssl.cpp)
  CXXFLAGS=(-std=c++$STD -O2 -Iinclude -Isrc -pthread -Wall -Wextra)
  LDFLAGS=(-pthread)
  HARD=()
  if [[ $HARDEN == 1 ]]; then
    HARD=(-D_GLIBCXX_ASSERTIONS -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE)
    for f in -fstack-clash-protection -fcf-protection=full; do
      echo 'int main(){}' | "$CXX_BIN" "$f" -x c++ - -o /dev/null 2>/dev/null && HARD+=("$f")
    done
    HLD=(-pie -Wl,-z,relro,-z,now,-z,noexecstack)
  else HLD=(); fi
  OSSL_FLAGS=(); OSSL_SRC=()
  if [[ $OPENSSL != OFF ]] && { command -v pkg-config >/dev/null 2>&1 && pkg-config --exists openssl 2>/dev/null || [[ -r /usr/include/openssl/ssl.h ]]; }; then
    OSSL_SRC=(src/tls_openssl.cpp); OSSL_FLAGS=(-DRECON_WITH_OPENSSL=1)
    if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists openssl 2>/dev/null; then
      read -r -a PK <<<"$(pkg-config --cflags --libs openssl)"; OSSL_FLAGS+=("${PK[@]}")
    else OSSL_FLAGS+=(-lssl -lcrypto); fi
  fi
  say "compiling ${#SRCS[@]} source files$([[ ${#OSSL_SRC[@]} -gt 0 ]] && echo ' (with OpenSSL TLS inspection)' || echo ' (without OpenSSL)')..."
  build_bin() { "$CXX_BIN" "${CXXFLAGS[@]}" "${HARD[@]}" "$@" "${SRCS[@]}" -o build/recon "${LDFLAGS[@]}" "${HLD[@]}"; }
  if [[ ${#OSSL_SRC[@]} -gt 0 ]]; then
    build_bin "${OSSL_FLAGS[@]}" "${OSSL_SRC[@]}" 2>build/openssl-build.log \
      || { warn "OpenSSL support failed to build (see build/openssl-build.log); continuing without it"; build_bin; }
  else build_bin; fi
  BIN=build/recon
  if [[ $RUN_TESTS == 1 ]]; then
    say "building and running the C++ test suite..."
    mapfile -t LIBSRC < <(ls src/*.cpp | grep -v -e main.cpp -e tls_openssl.cpp)
    mapfile -t TESTSRC < <(ls tests/test_*.cpp)
    "$CXX_BIN" -std=c++$STD -O1 -Iinclude -Isrc -Itests -pthread "${LIBSRC[@]}" "${TESTSRC[@]}" -o build/recon_tests
    ./build/recon_tests
    if command -v python3 >/dev/null 2>&1; then
      say "running end-to-end and documentation tests..."
      python3 tests/integration/test_cli.py "$BIN"
      python3 tests/doc_test.py "$BIN" docs/MANUAL.md man/recon.1
    fi
  fi
fi
"$BIN" --version >/dev/null || die "the built binary does not run"
say "built $(./$BIN --version)"
[[ $BUILD_ONLY == 1 ]] && { say "build only: binary is at ./$BIN"; exit 0; }

# ---- install ----------------------------------------------------------------------------------------
as_root=()
if [[ ! -w "$PREFIX" ]] && { [[ -e "$PREFIX" ]] || [[ ! -w "$(dirname "$PREFIX")" ]]; }; then
  command -v sudo >/dev/null 2>&1 || die "$PREFIX is not writable and sudo is unavailable; use --prefix ~/.local"
  warn "$PREFIX is not writable; using sudo for the install step only"; as_root=(sudo)
fi
if [[ $CMAKE_OK == 1 ]]; then
  "${as_root[@]}" cmake --install build
else
  inst() { "${as_root[@]}" install -D -m "$1" "$2" "$3"; }
  inst 755 "$BIN" "$PREFIX/bin/recon"
  inst 644 man/recon.1 "$PREFIX/share/man/man1/recon.1"
  inst 644 completions/recon.bash "$PREFIX/share/bash-completion/completions/recon"
  inst 644 completions/_recon "$PREFIX/share/zsh/site-functions/_recon"
  for d in README.md LICENSE docs/MANUAL.md docs/ARCHITECTURE.md; do inst 644 "$d" "$PREFIX/share/doc/recon/$(basename "$d")"; done
  inst 755 scripts/cert_expiry.py "$PREFIX/share/recon/scripts/cert_expiry.py"
  inst 755 scripts/drift_cron.sh "$PREFIX/share/recon/scripts/drift_cron.sh"
fi

echo
say "installed: $PREFIX/bin/recon"
"$PREFIX/bin/recon" --version
case ":$PATH:" in *":$PREFIX/bin:"*) ;; *) warn "$PREFIX/bin is not on your PATH. Add it:  export PATH=\"$PREFIX/bin:\$PATH\"" ;; esac
echo
echo "Try it:      recon localhost -pCT"
echo "Preview:     recon 192.168.1.0/24 -pCT --dry-run      (sends nothing)"
echo "Manual:      man recon     or     $PREFIX/share/doc/recon/MANUAL.md"
echo "SYN scans:   sudo setcap cap_net_raw+ep $PREFIX/bin/recon      (then: recon <host> -sS -pCT)"
echo "Uninstall:   ./scripts/install.sh --uninstall${PREFIX:+ --prefix $PREFIX}"
