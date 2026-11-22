#!/usr/bin/env python3
"""Keeps docs/MANUAL.md honest.

  1. Every `recon ...` command line in a ```bash block is executed with --dry-run (nothing is sent) and
     must exit 0, so documented options and combinations are real.
  2. Every option printed by `recon --help` must appear in the manual (nothing undocumented).
  3. The sample `--dry-run` output shown in the manual must equal the real output exactly.
  4. docs/architecture.json must be consistent with the source tree, and docs/ARCHITECTURE.md must be up to date
     with it (scripts/gen_architecture.py --check).

Usage: doc_test.py <path-to-recon> <path-to-MANUAL.md> [path-to-recon.1]
"""
import os, re, shlex, subprocess, sys, tempfile

RECON, MANUAL = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
text = open(MANUAL, encoding="utf-8").read()
FILE_EXT = (".json", ".txt", ".csv", ".xml", ".yml", ".py", ".sh")
EMPTY_REPORT = '{"schema_version":1,"hosts":[]}'
failures = []


def bash_blocks(md):
    return re.findall(r"```bash\n(.*?)```", md, re.S)


def command_lines(block):
    block = re.sub(r"\\\n\s*", " ", block)  # join continuations
    for line in block.splitlines():
        line = line.strip()
        if not re.match(r"^(sudo )?recon( |$)", line):
            continue
        line = re.split(r"\s(?:\||>|&&|;)\s|\s+#\s", line)[0].strip()  # keep only the recon part
        if any(tok in line for tok in ("$(", "$?", "<", "...", "${{")):
            continue
        yield re.sub(r"^sudo ", "", line)


def prepare(args, cwd):
    """Replace placeholder hostnames with loopback and create referenced fixture files."""
    out = []
    for i, a in enumerate(args):
        prev = args[i - 1] if i else ""
        if prev in ("--baseline",):
            open(os.path.join(cwd, a), "w").write(EMPTY_REPORT)
        elif prev in ("-iL", "--input-list") and a != "-":
            open(os.path.join(cwd, a), "w").write("127.0.0.1\n")
        elif re.fullmatch(r"[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+", a) and not a.endswith(FILE_EXT) \
                and not re.fullmatch(r"\d+(\.\d+){3}", a) and prev not in ("-o", "--output", "-p", "--ports"):
            a = "127.0.0.1"
        out.append(a)
    return out


with tempfile.TemporaryDirectory() as cwd:
    n = 0
    for block in bash_blocks(text):
        for line in command_lines(block):
            args = prepare(shlex.split(line)[1:], cwd)
            if "--dry-run" not in args and "--version" not in args and "--help" not in args:
                args += ["--dry-run", "-q"]
            p = subprocess.run([RECON, *args], capture_output=True, text=True, cwd=cwd, timeout=30)
            n += 1
            if p.returncode != 0:
                failures.append(f"command failed (exit {p.returncode}): {line}\n    {p.stderr.strip()}")
    print(f"executed {n} documented command lines")

    # 2. every option in --help is in the manual
    helptext = subprocess.run([RECON, "--help"], capture_output=True, text=True).stdout
    options = set(re.findall(r"(?<![\w-])(--[A-Za-z][A-Za-z0-9-]+|-[A-Za-z]{1,3}\b|-p[ACTU]{2}\b)", helptext))
    options -= {"-4", "-6"}  # documented as a pair "-4 / -6"
    for opt in sorted(options):
        if not re.search(r"(?<![\w-])" + re.escape(opt) + r"(?![\w-])", text):
            failures.append(f"option {opt} appears in --help but not in the manual")
    for pair in ("-4", "-6"):
        if pair not in text:
            failures.append(f"option {pair} missing from the manual")

    # 2b. ... and in the man page (roff escapes hyphens as \\-)
    if len(sys.argv) > 3:
        man = open(sys.argv[3], encoding="utf-8").read().replace("\\-", "-")
        for opt in sorted(options | {"-4", "-6"}):
            if not re.search(r"(?<![\w-])" + re.escape(opt) + r"(?![\w-])", man):
                failures.append(f"option {opt} appears in --help but not in the man page")

    # 3. sample dry-run output must match the real one
    m = re.search(r"recon (192\.168\.1\.0/28 -pCT --dry-run)\n```\n\n```\n(Dry run:.*?)```", text, re.S)
    if not m:
        failures.append("could not find the sample --dry-run block in the manual")
    else:
        real = subprocess.run([RECON, *shlex.split(m.group(1))], capture_output=True, text=True).stdout
        if real.strip() != m.group(2).strip():
            failures.append("sample --dry-run output in the manual differs from the real output:\n--- manual\n"
                            + m.group(2) + "--- real\n" + real)

# 4. architecture map vs source tree, and generated section freshness
root = os.path.dirname(os.path.dirname(MANUAL))
gen = os.path.join(root, "scripts", "gen_architecture.py")
if os.path.exists(gen):
    r = subprocess.run([sys.executable, gen, "--check"], capture_output=True, text=True)
    if r.returncode != 0:
        failures.append("architecture check failed: " + (r.stderr.strip() or r.stdout.strip()))
else:
    failures.append("scripts/gen_architecture.py is missing")

if failures:
    print("\n".join(failures))
    sys.exit(1)
print("docs OK: examples run, all options documented, sample output matches, architecture map consistent")
