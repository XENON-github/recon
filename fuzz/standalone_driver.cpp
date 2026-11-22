// Fallback main() for compilers without libFuzzer (e.g. GCC): replays files/directories given on
// the command line, then runs a bounded number of random + mutated inputs. Usage:
//   fuzz_x [corpus_file_or_dir ...] [-runs=N] [-seed=S]
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <random>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size);

int main(int argc, char** argv) {
    namespace fs = std::filesystem;
    long runs = 100000;
    unsigned seed = 1;
    std::vector<std::string> seeds;
    for (int i = 1; i < argc; ++i) {
        if (std::strncmp(argv[i], "-runs=", 6) == 0) { runs = std::atol(argv[i] + 6); continue; }
        if (std::strncmp(argv[i], "-seed=", 6) == 0) { seed = static_cast<unsigned>(std::atol(argv[i] + 6)); continue; }
        std::vector<fs::path> files;
        if (fs::is_directory(argv[i])) {
            for (auto& e : fs::directory_iterator(argv[i])) if (e.is_regular_file()) files.push_back(e.path());
        } else {
            files.emplace_back(argv[i]);
        }
        for (auto& f : files) {
            std::ifstream in(f, std::ios::binary);
            seeds.emplace_back((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        }
    }
    for (const auto& s : seeds) LLVMFuzzerTestOneInput(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
    std::mt19937 rng(seed);
    for (long i = 0; i < runs; ++i) {
        std::string d;
        if (seeds.empty() || rng() % 3 == 0) {
            d.resize(rng() % 256);
            for (auto& c : d) c = static_cast<char>(rng());
        } else {
            d = seeds[rng() % seeds.size()];
            for (unsigned m = 0, n = 1 + rng() % 6; m < n && !d.empty(); ++m) {
                switch (rng() % 3) {
                    case 0: d[rng() % d.size()] = static_cast<char>(rng()); break;
                    case 1: d.insert(d.begin() + static_cast<long>(rng() % (d.size() + 1)), static_cast<char>(rng())); break;
                    default: d.erase(d.begin() + static_cast<long>(rng() % d.size())); break;
                }
            }
            if (rng() % 5 == 0 && !d.empty()) d.resize(rng() % d.size());
        }
        LLVMFuzzerTestOneInput(reinterpret_cast<const std::uint8_t*>(d.data()), d.size());
    }
    std::printf("fuzz: %zu seeds + %ld generated inputs, no crashes\n", seeds.size(), runs);
    return 0;
}
