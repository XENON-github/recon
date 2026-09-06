<a id="readme-top"></a>

<!-- PROJECT SHIELDS -->
<div align="center">

[![License: GPL-3.0](https://img.shields.io/badge/License-GPLv3-blue.svg?style=for-the-badge)](LICENSE)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-00599C.svg?style=for-the-badge&logo=c%2B%2B&logoColor=white)](https://en.cppreference.com/w/cpp/17)
[![Platform](https://img.shields.io/badge/Platform-Linux-FCC624.svg?style=for-the-badge&logo=linux&logoColor=black)](https://www.kernel.org)
[![Repo](https://img.shields.io/badge/GitHub-XENON--github%2Frecon-181717.svg?style=for-the-badge&logo=github)](https://github.com/XENON-github/recon)

</div>

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <h1 align="center">Recon</h1>

  <p align="center">
    Fast, Lightweight Network Port, Service & OS Scanner in C++17
    <br />
    <br />
    <a href="#features">Features</a>
    &middot;
    <a href="#getting-started">Getting Started</a>
    &middot;
    <a href="#usage">Usage & Examples</a>
    &middot;
    <a href="#sample-output">Sample Output</a>
    &middot;
    <a href="#roadmap">Roadmap</a>
    &middot;
    <a href="#license">License</a>
  </p>
</div>

---

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#features">Features</a></li>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
        <li><a href="#uninstallation">Uninstallation</a></li>
      </ul>
    </li>
    <li>
      <a href="#usage">Usage</a>
      <ul>
        <li><a href="#command-syntax">Command Syntax</a></li>
        <li><a href="#cli-flags--options">CLI Flags & Options</a></li>
        <li><a href="#examples">Examples</a></li>
      </ul>
    </li>
    <li>
      <a href="#sample-output">Sample Output</a></li>
    <li><a href="#how-it-works">How It Works</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>

<!-- ABOUT THE PROJECT -->

## About The Project

**Recon** is a fast, multi-threaded command-line network reconnaissance utility engineered in modern C++17. It enables network administrators, security researchers, and enthusiasts to scan TCP and UDP ports, fingerprint active services and version banners, and heuristically infer the target operating system without requiring heavy third-party runtime frameworks.

### Features

- **Concurrent Port Scanning:**
  - **Common TCP Scan:** Scans ~70 of the most frequently used TCP ports concurrently.
  - **Full TCP Sweep:** Multi-threaded scan across all 65,535 TCP ports with high concurrency (up to 120 worker threads).
  - **UDP Port Scanning:** Probes common UDP service ports or sweeps the full 1-65,535 range.
  - **Custom Port Ranges:** Flexible port targeting supporting individual ports, comma-separated lists, and ranges (e.g. `22,80,8000-8080`).
- **Service & Version Fingerprinting:**
  - Active protocol probes for HTTP, HTTPS, SSH, FTP, SMTP, DNS, Redis, MySQL, PostgreSQL, MongoDB, Telnet, POP3, IMAP, and more.
  - Dynamic banner grabbing and application version extraction (enabled by default, can be toggled off with `--no-sV`).
- **Operating System Detection (`-os`, `-O`):**
  - **TTL Inspection:** Captures incoming packet Time-to-Live (TTL) over ICMP and TCP connection handshakes to estimate network hop distances and classify OS network stacks.
  - **Port Profiles:** Correlates typical exposed ports (e.g., SMB/RDP for Windows vs. SSH/RPC for Unix-like systems).
  - **Banner Correlation:** Inspects software banners (OpenSSH distribution signatures, web server headers, Samba versions) for precise OS identification.
  - **Localhost Acceleration:** Direct kernel system inspection (`uname`) when querying loopback targets.
- **Comprehensive Mode (`-A`):** Single-flag invocation combining common TCP scanning, active service/version detection, and full OS identification.
- **Convenient Target Aliases:** Resolves standard IPv4 addresses, DNS hostnames, and friendly aliases (`localhost`, `me`, `'my device'`).
- **Zero External Dependencies:** Built entirely with the C++ standard library and POSIX networking APIs.

### Built With

- **Language:** C++17
- **Compiler:** GNU Compiler Collection (GCC / `g++`) or Clang
- **Concurrency:** POSIX Threads (`pthread`)
- **Build System:** GNU Make

<!-- GETTING STARTED -->

## Getting Started

### Prerequisites

You will need a C++17-compatible compiler (`g++` or `clang++`) and `make`.

#### Arch Linux
```sh
sudo pacman -S gcc make
```

#### Debian / Ubuntu / Kali Linux
```sh
sudo apt update
sudo apt install build-essential
```

#### Fedora / RHEL
```sh
sudo dnf install gcc-c++ make
```

### Installation

#### Option 1: Using the Automated Installer

Clone the repository and run the provided `install.sh` script:

```sh
git clone https://github.com/XENON-github/recon.git
cd recon
chmod +x install.sh
./install.sh
```

#### Option 2: Manual Compilation & Installation

```sh
# 1. Clone the repository
git clone https://github.com/XENON-github/recon.git
cd recon

# 2. Compile the binary
make

# 3. Install to /usr/bin
sudo make install
```

Verify that Recon is installed and accessible in your PATH:

```sh
recon --help
```

### Uninstallation

To remove Recon from your system:

```sh
sudo make uninstall
```

<!-- USAGE -->

## Usage

### Command Syntax

```sh
recon <TARGET_IP> [FLAGS]
recon [FLAGS] <TARGET_IP>
```

> **Note:** Recon currently operates on one target host per scan execution.

### CLI Flags & Options

| Flag | Long Flag | Description |
| :--- | :--- | :--- |
| `<target>` | `-t`, `--target`, `-ip` | Target IPv4 address, hostname, or alias (`localhost`, `me`, `'my device'`). |
| `-pCT` | &mdash; | Scan common TCP ports (~70 popular services). |
| `-pAT` | &mdash; | Scan all TCP ports (`1-65535`) using high-concurrency worker threads. |
| `-pCU` | &mdash; | Scan common UDP ports with service-specific probe packets. |
| `-pAU` | &mdash; | Scan all UDP ports (`1-65535`). |
| `-p <ports>` | `--ports <ports>` | Scan custom ports (e.g. `-p 80,443`, `-p 8000-8080`, or `-p=22,3306`). |
| `-sV` | `--service-version` | Probe open ports for exact service name and version banner (**default: ON**). |
| &mdash; | `--no-sV` | Disable service/version probing for faster connection-only checks. |
| `-os`, `-O` | `--os` | Perform heuristic Operating System detection against the target host. |
| `-A` | `--all` | Comprehensive scan (combines `-pCT` + Service/Version detection + `-os`). |
| `-h` | `--help` | Display the help menu and exit. |

### Examples

**Scan common TCP ports on a target:**
```sh
recon 192.168.1.1 -pCT
```

**Run a common TCP scan and detect the operating system:**
```sh
recon 192.168.1.1 -pCT -os
```

**Perform an all-in-one comprehensive scan on local machine:**
```sh
recon localhost -A
```

**Scan specific ports and port ranges:**
```sh
recon 10.0.0.5 -p 22,80,443,8000-8080 -os
```

**Fast TCP scan without service/version probing:**
```sh
recon 192.168.1.50 -pCT --no-sV
```

**Scan all 65,535 TCP ports:**
```sh
recon 192.168.1.100 -pAT
```

**Probe common UDP ports:**
```sh
recon 192.168.1.1 -pCU
```

**Target a domain or hostname explicitly:**
```sh
recon --target scanme.example.com -p 80,443 -sV
```

<!-- SAMPLE OUTPUT -->

## Sample Output

Running a scan with service and OS detection (`recon 192.168.1.10 -pCT -os`):

```text
================================================================================
TARGET: 192.168.1.10
Scanning common TCP ports...
================================================================================
PORT        STATE   SERVICE        VERSION / BANNER DETAILS
--------------------------------------------------------------------------------
22/tcp      OPEN    ssh            OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
80/tcp      OPEN    http           nginx 1.18.0 (Ubuntu)
443/tcp     OPEN    https          nginx 1.18.0 (Ubuntu)
3306/tcp    OPEN    mysql          MySQL 8.0.36
================================================================================
Found 4 open port(s).

-----------------------------------------------------
  OPERATING SYSTEM DETECTION REPORT
-----------------------------------------------------
Target IP:      192.168.1.10
OS Detected:    Ubuntu Linux (Jammy Jellyfish / 22.04 LTS)
OS Family:      Linux
Confidence:     95%
Observed TTL:   64 (Estimated Hops: 0)

Detection Evidence:
  * OpenSSH banner indicates Ubuntu Linux (Ubuntu 3ubuntu0.6)
  * TCP initial TTL 64 strongly indicates Linux/Unix kernel
  * HTTP Server header indicates Ubuntu Linux (nginx 1.18.0)
-----------------------------------------------------
```

<!-- HOW IT WORKS -->

## How It Works

1. **Non-Blocking Concurrent Connects:** Recon leverages POSIX non-blocking sockets combined with `poll()` and a multi-threaded worker pool to rapidly scan ports without hanging on closed or filtered endpoints.
2. **Protocol Probing & Banner Grabbing:** For open ports, Recon issues protocol-appropriate requests (such as HTTP `HEAD /`, SSH identification exchanges, Redis `PING`, or database handshakes) to parse and sanitize software versions.
3. **Multi-Vector OS Fingerprinting:**
   - **ICMP / TCP TTL Analysis:** Evaluates default time-to-live values (e.g. 64 for Linux, 128 for Windows, 255 for network gear) to determine kernel family and network distance.
   - **Service & Banner Profiling:** Matches banners and OS distributions against built-in signatures.
   - **Confidence Scoring:** Combines all evidence into an overall confidence percentage and detailed detection rationale.

<!-- ROADMAP -->

## Roadmap

* [x] Multi-threaded TCP port scanning (Common ports and full 1-65535 range)
* [x] Multi-threaded UDP port scanning with protocol probes
* [x] Custom port lists and hyphenated range specifications
* [x] Protocol banner grabbing and service version detection
* [x] Operating system detection (TTL heuristics + banner analysis)
* [x] Comprehensive scan preset (`-A`)
* [x] Hostname resolution and target aliases (`localhost`, `me`)
* [ ] Expanded service fingerprinting signatures
* [ ] Subnet / CIDR range scanning (e.g. `192.168.1.0/24`)
* [ ] Output export formats (JSON, CSV, plain text)
* [ ] Timing templates and rate limiting (`-T1` to `-T5`)

<!-- CONTRIBUTING -->

## Contributing

Contributions are welcome! If you would like to help improve Recon:

1. Fork the Project (`https://github.com/XENON-github/recon`)
2. Create your Feature Branch:
   ```sh
   git checkout -b feature/AmazingFeature
   ```
3. Commit your Changes:
   ```sh
   git commit -m "Add AmazingFeature"
   ```
4. Push to the Branch:
   ```sh
   git push origin feature/AmazingFeature
   ```
5. Open a Pull Request

<!-- LICENSE -->

## License

Distributed under the **GNU General Public License v3.0**. See [`LICENSE`](LICENSE) for details.

<!-- ACKNOWLEDGMENTS -->

## Acknowledgments

* POSIX Socket API documentation
* GNU Compiler Collection (`g++`) & GNU Make
* Modern C++ community guidelines

<p align="right">(<a href="#readme-top">back to top</a>)</p>
