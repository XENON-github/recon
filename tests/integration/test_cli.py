#!/usr/bin/env python3
"""End-to-end tests: run the real `recon` binary against controlled local mock services.

Usage: test_cli.py <path-to-recon> [unittest args]
Everything binds to 127.0.0.1 on ephemeral ports; nothing leaves the machine.
"""
import csv
import io
import json
import os
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

RECON = None  # set in main()


class MockServer:
    """TCP server that runs `handler(conn)` for each connection on its own thread."""

    def __init__(self, handler):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        self.handler = handler
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._run, args=(conn,), daemon=True).start()

    def _run(self, conn):
        try:
            conn.settimeout(3)
            self.handler(conn)
        except (OSError, ssl.SSLError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self):
        self.stop.set()
        self.thread.join(timeout=2)
        self.sock.close()


def banner(data):
    def h(c):
        c.sendall(data)
        time.sleep(0.3)
    return h


def reply_after_request(data):
    def h(c):
        try:
            c.recv(4096)
        except OSError:
            return
        c.sendall(data)
    return h


def silent(c):
    time.sleep(3)


def mysql_handshake(version=b"8.0.36-0ubuntu0.22.04.1"):
    payload = b"\x0a" + version + b"\x00" + b"x" * 31
    return struct.pack("<I", len(payload))[:3] + b"\x00" + payload


def write_text(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def run(*args, expect=None, timeout=60):
    p = subprocess.run([RECON, *args], capture_output=True, timeout=timeout)
    if expect is not None:
        assert p.returncode == expect, f"exit {p.returncode} != {expect}\nstderr: {p.stderr.decode(errors='replace')}"
    return p


def closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def scan_json(*args):
    p = run(*args, "--json", "-q", expect=0)
    return json.loads(p.stdout.decode("utf-8"))  # strict: output must be valid UTF-8 JSON


def ports_by_number(doc, host=0):
    return {p["port"]: p for p in doc["hosts"][host]["ports"]}


class CliTests(unittest.TestCase):
    def test_mixed_services_json(self):
        servers = {
            "ssh": MockServer(banner(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n")),
            "http": MockServer(reply_after_request(
                b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 (Ubuntu)\r\nContent-Length: 0\r\n\r\n")),
            "mysql": MockServer(banner(mysql_handshake())),
            "redis": MockServer(reply_after_request(
                b"$60\r\n# Server\r\nredis_version:7.0.11\r\nredis_mode:standalone\r\n")),
            "silent": MockServer(silent),
        }
        closed = closed_port()
        try:
            ports = ",".join(str(s.port) for s in servers.values()) + f",{closed}"
            doc = scan_json("127.0.0.1", "-p", ports, "--intensity", "6", "--timeout", "800")
        finally:
            for s in servers.values():
                s.close()
        by = ports_by_number(doc)
        self.assertEqual(doc["schema_version"], 1)
        self.assertEqual(doc["scan"]["status"], "completed")
        self.assertNotIn(closed, by)  # only open ports are listed
        ssh = by[servers["ssh"].port]["service"]
        self.assertEqual((ssh["name"], ssh["product"], ssh["version"]), ("ssh", "OpenSSH", "9.6p1"))
        self.assertEqual(ssh["version_quality"], "reported")
        http = by[servers["http"].port]["service"]
        self.assertEqual((http["name"], http["product"], http["version"]), ("http", "nginx", "1.24.0"))
        mysql = by[servers["mysql"].port]["service"]
        self.assertEqual((mysql["name"], mysql["product"]), ("mysql", "MySQL"))
        self.assertTrue(mysql["version"].startswith("8.0.36"))
        redis = by[servers["redis"].port]["service"]
        self.assertEqual((redis["name"], redis["version"]), ("redis", "7.0.11"))
        quiet = by[servers["silent"].port]["service"]
        self.assertLess(quiet["confidence"], 50)  # a silent port must not be presented as a fact
        self.assertNotEqual(quiet["version_quality"], "reported")
        s = doc["summary"]
        self.assertEqual((s["open"], s["closed"], s["probes"]), (5, 1, 6))
        self.assertGreaterEqual(s["duration_ms"], 0)
        self.assertGreater(s["resources"]["max_rss_kb"], 0)

    def test_hostile_banner_yields_valid_json_and_safe_csv(self):
        evil = b"=HYPERLINK(\"http://evil\",\"x\")\xff\xfe\x1b[31m\x00\x07 not a real protocol\r\n"
        srv = MockServer(banner(evil))
        try:
            doc = scan_json("127.0.0.1", "-p", str(srv.port), "--timeout", "800")
            b = ports_by_number(doc)[srv.port]["service"]["banner"]
            self.assertTrue(all(32 <= ord(c) < 127 for c in b), repr(b))
            p = run("127.0.0.1", "-p", str(srv.port), "--csv", "-q", "--timeout", "800", expect=0)
            rows = list(csv.DictReader(io.StringIO(p.stdout.decode("utf-8"))))
            self.assertEqual(len(rows), 1)
            for v in rows[0].values():
                self.assertFalse(v[:1] in ("=", "+", "@"), f"formula injection: {v!r}")
        finally:
            srv.close()

    def test_exit_codes(self):
        srv = MockServer(banner(b"SSH-2.0-test_1.0\r\n"))
        try:
            run(expect=2)                                                  # no arguments
            run("127.0.0.1", expect=2)                                     # no scan action
            run("127.0.0.1", "-p", "80abc", expect=2)                      # strict port parsing
            run("127.0.0.1", "-p", "0", expect=2)
            run("127.0.0.1", "-p", "22", "--timeout", "x", expect=2)
            run("no-such-host.invalid", "-p", "22", "-q", expect=3)
            run("10.0.0.0/8", "-p", "22", "-q", expect=3)                  # refuses huge expansions
            run("127.0.0.1", "-p", str(srv.port), "-q", "--json", expect=0)
            run("127.0.0.1", "-p", str(srv.port), "-q", "--json", "--fail-on-open", expect=1)
            run("127.0.0.1", "-p", str(closed_port()), "-q", "--fail-on-open", expect=0)
            run("127.0.0.1", "-p", "22", "-q", "-o", "/nonexistent-dir/out.json", expect=4)
            self.assertEqual(run("--version", expect=0).stdout.split()[0], b"recon")
            self.assertIn(b"EXIT CODES", run("--help", expect=0).stdout)
        finally:
            srv.close()

    def test_output_file(self):
        srv = MockServer(banner(b"SSH-2.0-test_1.0\r\n"))
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "r.json")
            try:
                p = run("127.0.0.1", "-p", str(srv.port), "--json", "-q", "-o", out, expect=0)
            finally:
                srv.close()
            self.assertEqual(p.stdout, b"")
            with open(out, encoding="utf-8") as f:
                self.assertEqual(json.load(f)["summary"]["open"], 1)

    def test_cidr_and_host_indexing(self):
        srv = MockServer(banner(b"SSH-2.0-test_1.0\r\n"))
        try:
            doc = scan_json("127.0.0.0/30", "-p", str(srv.port), "--timeout", "800")
        finally:
            srv.close()
        self.assertEqual([h["address"] for h in doc["hosts"]],
                         ["127.0.0.0", "127.0.0.1", "127.0.0.2", "127.0.0.3"])
        open_hosts = [h["address"] for h in doc["hosts"] if h["ports"]]
        self.assertEqual(open_hosts, ["127.0.0.1"])  # server is bound to .1 only
        self.assertEqual(doc["summary"]["probes"], 4)

    def test_reset_connections_do_not_kill_the_scan(self):
        def rst(c):
            c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        srv = MockServer(rst)
        ssh = MockServer(banner(b"SSH-2.0-test_1.0\r\n"))
        try:
            p = run("127.0.0.1", "-p", f"{srv.port},{ssh.port}", "--json", "-q", expect=0)  # was exit 141
            self.assertEqual(json.loads(p.stdout)["summary"]["probes"], 2)
        finally:
            srv.close()
            ssh.close()

    def test_sigint_returns_partial_valid_json(self):
        p = subprocess.Popen([RECON, "127.0.0.1", "-p", "20000-22000", "--rate", "20", "--json", "-q"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(0.8)
        p.send_signal(signal.SIGINT)
        out, _ = p.communicate(timeout=10)
        self.assertEqual(p.returncode, 130)
        doc = json.loads(out)
        self.assertEqual(doc["scan"]["status"], "cancelled")
        self.assertLess(doc["summary"]["closed"], 2001)

    def test_conservative_rate_limit_is_enforced(self):
        t0 = time.time()
        run("127.0.0.1", "-p", "40000-40059", "--rate", "100", "-q", "--json", expect=0)
        self.assertGreaterEqual(time.time() - t0, 0.45)  # (60 - burst 5) / 100 per second

    def test_table_output_mentions_authorization_notice_on_stderr(self):
        srv = MockServer(banner(b"SSH-2.0-test_1.0\r\n"))
        try:
            p = run("127.0.0.1", "-p", str(srv.port), expect=0)
        finally:
            srv.close()
        self.assertIn(b"authorization", p.stderr)
        self.assertIn(b"ssh", p.stdout)
        self.assertNotIn(b"authorization", p.stdout)  # notices never pollute stdout


class WorkflowTests(unittest.TestCase):
    def test_baseline_drift_end_to_end(self):
        a = MockServer(banner(b"SSH-2.0-OpenSSH_9.6p1\r\n"))
        b = MockServer(banner(b"220 (vsFTPd 3.0.5)\r\n"))
        with tempfile.TemporaryDirectory() as d:
            base = os.path.join(d, "base.json")
            try:
                run("127.0.0.1", "-p", f"{a.port},{b.port}", "--json", "-q", "-o", base, expect=0)
                # Same state => exit 0, no drift entries.
                p = run("127.0.0.1", "-p", f"{a.port},{b.port}", "--json", "-q", "--baseline", base, expect=0)
                doc = json.loads(p.stdout)
                self.assertEqual(doc["drift"]["new_open"], [])
                self.assertEqual(doc["drift"]["no_longer_open"], [])
                # A service appears: exit 5, reported with its detected service name.
                c = MockServer(banner(b"+OK Dovecot ready.\r\n"))
                try:
                    p = run("127.0.0.1", "-p", f"{a.port},{b.port},{c.port}", "--json", "-q", "--baseline", base, expect=5)
                    drift = json.loads(p.stdout)["drift"]
                    self.assertEqual([(e["port"], e["service"]) for e in drift["new_open"]], [(c.port, "pop3")])
                finally:
                    c.close()
                # A service disappears: reported as no_longer_open but is not a failure.
                b.close()
                p = run("127.0.0.1", "-p", f"{a.port},{b.port}", "--json", "-q", "--baseline", base, expect=0)
                self.assertEqual([e["port"] for e in json.loads(p.stdout)["drift"]["no_longer_open"]], [b.port])
                # Scanning only a subset must NOT claim the others closed.
                p = run("127.0.0.1", "-p", str(a.port), "--json", "-q", "--baseline", base, expect=0)
                self.assertEqual(json.loads(p.stdout)["drift"]["no_longer_open"], [])
                # Bad baselines are usage errors, not crashes.
                bad = os.path.join(d, "bad.json")
                write_text(bad, "{not json")
                run("127.0.0.1", "-p", str(a.port), "-q", "--baseline", bad, expect=2)
                run("127.0.0.1", "-p", str(a.port), "-q", "--baseline", os.path.join(d, "missing.json"), expect=2)
            finally:
                a.close()
                b.close()

    def test_baseline_in_table_mode_shows_drift(self):
        a = MockServer(banner(b"SSH-2.0-OpenSSH_9.6p1\r\n"))
        with tempfile.TemporaryDirectory() as d:
            base = os.path.join(d, "empty.json")
            write_text(base, '{"schema_version":1,"hosts":[]}')
            try:
                p = run("127.0.0.1", "-p", str(a.port), "-q", "--baseline", base, "--color", "never", expect=5)
            finally:
                a.close()
        self.assertIn(b"NEW OPEN", p.stdout)
        self.assertNotIn(b"\x1b[", p.stdout)

    def test_target_file_and_profile(self):
        srv = MockServer(banner(b"SSH-2.0-test_1.0\r\n"))
        with tempfile.TemporaryDirectory() as d:
            lst = os.path.join(d, "t.txt")
            write_text(lst, "# lab hosts\n127.0.0.1   # loopback\n\n")
            try:
                doc = scan_json("-iL", lst, "-p", str(srv.port))
                self.assertEqual([h["address"] for h in doc["hosts"]], ["127.0.0.1"])
                self.assertEqual(doc["summary"]["open"], 1)
                # Profile supplies the port set (common ports) and its pacing; explicit --rate overrides it.
                doc = scan_json("127.0.0.1", "--profile", "quick", "--rate", "0")
                self.assertGreater(doc["scan"]["options"]["tcp_ports"], 30)
                self.assertEqual(doc["scan"]["options"]["intensity"], 3)
                self.assertEqual(doc["scan"]["options"]["rate_per_sec"], 0)
                doc = scan_json("127.0.0.1", "--profile", "stealth")
                self.assertEqual(doc["scan"]["options"]["max_inflight"], 8)
            finally:
                srv.close()
        run("127.0.0.1", "--profile", "bogus", expect=2)
        run("-iL", "/nonexistent", expect=2)

    def test_dry_run_sends_nothing(self):
        srv = MockServer(banner(b"SSH-2.0-test_1.0\r\n"))
        accepted = []
        srv.handler = lambda c: accepted.append(1)
        try:
            p = run("127.0.0.1", "-p", f"{srv.port},1-9", "--dry-run", "--rate", "100", expect=0)
        finally:
            time.sleep(0.2)
            srv.close()
        self.assertEqual(accepted, [])                    # no connection was ever made
        self.assertIn(b"Dry run: nothing was sent", p.stdout)
        self.assertIn(b"10 probes", p.stdout)
        self.assertIn(b">= 0.1 s", p.stdout)
        run("10.0.0.0/30", "-pCT", "--dry-run", "-q", expect=0)
        run("127.0.0.1", "-p", "22", "--dry-run", "-q", "--json", expect=0)
        run("no-such-host.invalid", "-p", "22", "--dry-run", "-q", expect=3)   # resolution still validated
        run("127.0.0.1", "--dry-run", "-q", expect=2)                          # still needs a scan action

    def test_output_files_are_private_and_never_follow_symlinks(self):
        srv = MockServer(banner(b"SSH-2.0-test_1.0\r\n"))
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "report.json")
            victim, link = os.path.join(d, "victim"), os.path.join(d, "link.json")
            write_text(victim, "precious")
            os.symlink(victim, link)
            try:
                run("127.0.0.1", "-p", str(srv.port), "--json", "-q", "-o", out, expect=0)
                self.assertEqual(os.stat(out).st_mode & 0o777, 0o600)          # reports are created private
                os.chmod(out, 0o640)
                run("127.0.0.1", "-p", str(srv.port), "--json", "-q", "-o", out, expect=0)
                self.assertEqual(os.stat(out).st_mode & 0o777, 0o640)          # an existing file's mode is respected
                p = run("127.0.0.1", "-p", str(srv.port), "--json", "-q", "-o", link, expect=4)
                self.assertIn(b"symbolic link", p.stderr)
                with open(victim) as f:
                    self.assertEqual(f.read(), "precious")                       # the symlink target was not touched
                p = run("127.0.0.1", "-p", str(srv.port), "--json", "-q", "-o", "-", expect=0)
                self.assertEqual(json.loads(p.stdout)["summary"]["open"], 1)     # '-o -' means stdout
                run("127.0.0.1", "-p", str(srv.port), "-q", "-o", d, expect=4)   # a directory is not a file
            finally:
                srv.close()

    def test_adaptive_timeouts_keep_silent_ports_cheap(self):
        silent_srv = MockServer(silent)
        try:
            t0 = time.time()
            doc = scan_json("127.0.0.1", "-p", str(silent_srv.port), "--intensity", "6")
            took = time.time() - t0
        finally:
            silent_srv.close()
        svc = ports_by_number(doc)[silent_srv.port]["service"]
        self.assertLess(svc["confidence"], 50)
        self.assertLess(took, 4.0)  # fixed 1.5 s timeouts would cost ~7 s for the same result


SCRIPTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "scripts")


class ScriptTests(unittest.TestCase):
    def sh(self, *args, env=None):
        e = dict(os.environ, RECON=RECON, **(env or {}))
        return subprocess.run(["bash", os.path.join(SCRIPTS, "drift_cron.sh"), *args], capture_output=True, env=e, timeout=60)

    def test_drift_cron_lifecycle(self):
        a = MockServer(banner(b"SSH-2.0-test_1.0\r\n"))
        with tempfile.TemporaryDirectory() as d:
            state = os.path.join(d, "state")
            args = ["127.0.0.1", "-p"]
            try:
                p = self.sh(state, *args, str(a.port))                       # first run records the baseline
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertTrue(os.path.exists(os.path.join(state, "baseline.json")))
                self.assertEqual(self.sh(state, *args, str(a.port)).returncode, 0)   # unchanged
                b = MockServer(banner(b"220 (vsFTPd 3.0.5)\r\n"))
                try:
                    ports = f"{a.port},{b.port}"
                    p = self.sh(state, *args, ports)
                    self.assertEqual(p.returncode, 5)                          # new port => alert
                    self.assertIn(b"ALERT", p.stderr)
                    self.assertEqual(self.sh(state, *args, ports).returncode, 5)  # alert repeats until acknowledged
                    p = self.sh(state, *args, ports, env={"ACCEPT": "1"})
                    self.assertEqual(p.returncode, 5)
                    self.assertIn(b"baseline updated", p.stderr)
                    self.assertEqual(self.sh(state, *args, ports).returncode, 0)  # accepted: quiet again
                finally:
                    b.close()
                self.assertGreaterEqual(len(os.listdir(os.path.join(state, "history"))), 4)
                mode = os.stat(os.path.join(state, "baseline.json")).st_mode & 0o777
                self.assertEqual(mode, 0o600)                                   # reports are created private
            finally:
                a.close()
        self.assertEqual(self.sh().returncode, 2)                              # usage

    def test_cert_expiry_script(self):
        def report(not_after, cert=True):
            tls = {"protocol": "TLSv1.3", "cipher": "x", "certificate": {"subject": "CN=a", "issuer": "CN=a", "not_before": "Jan  1 00:00:00 2020 GMT",
                   "not_after": not_after, "sha256": "0" * 64, "san": [], "self_signed": True, "expired": False} if cert else False}
            return {"hosts": [{"address": "10.0.0.1", "ports": [{"port": 443, "service": {"tls": tls}}]}]}
        def run_script(doc, *extra):
            with tempfile.TemporaryDirectory() as d:
                path = os.path.join(d, "r.json")
                write_text(path, json.dumps(doc))
                return subprocess.run([sys.executable, os.path.join(SCRIPTS, "cert_expiry.py"), path, *extra], capture_output=True)
        far = (__import__("datetime").datetime.now() + __import__("datetime").timedelta(days=400)).strftime("%b %e %H:%M:%S %Y GMT")
        soon = (__import__("datetime").datetime.now() + __import__("datetime").timedelta(days=5)).strftime("%b %e %H:%M:%S %Y GMT")
        self.assertEqual(run_script(report(far)).returncode, 0)
        p = run_script(report(soon))
        self.assertEqual(p.returncode, 1)
        self.assertIn(b"EXPIRING", p.stdout)
        self.assertEqual(run_script(report(soon), "--days", "2").returncode, 0)
        p = run_script(report("Jan  1 00:00:00 2001 GMT"))
        self.assertEqual((p.returncode, b"EXPIRED" in p.stdout), (1, True))
        self.assertEqual(run_script(report(far, cert=False)).returncode, 2)      # no certificate data
        self.assertEqual(run_script({"nothing": 1}).returncode, 2)


@unittest.skipUnless(os.geteuid() == 0, "SYN scan needs root / CAP_NET_RAW")
class SynTests(unittest.TestCase):
    def test_syn_matches_connect_and_is_labelled(self):
        servers = [MockServer(silent) for _ in range(5)]
        closed = [closed_port() for _ in range(5)]
        ports = ",".join(str(p) for p in [s.port for s in servers] + closed)
        try:
            syn = scan_json("127.0.0.1", "-sS", "-p", ports, "--no-sV", "--timeout", "500")
            conn = scan_json("127.0.0.1", "-sT", "-p", ports, "--no-sV", "--timeout", "500")
        finally:
            for s in servers:
                s.close()
        self.assertEqual(syn["scan"]["options"]["scan_type"], "syn")
        self.assertEqual(conn["scan"]["options"]["scan_type"], "connect")
        self.assertEqual(sorted(ports_by_number(syn)), sorted(ports_by_number(conn)))
        self.assertEqual((syn["summary"]["open"], syn["summary"]["closed"]), (5, 5))

    def test_syn_rejects_ipv6_with_usage_error(self):
        run("::1", "-sS", "-p", "22", "-q", expect=2)


@unittest.skipUnless(shutil.which("openssl"), "openssl CLI required to mint a test certificate")
class TlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.key, cls.crt = os.path.join(cls.tmp, "k.pem"), os.path.join(cls.tmp, "c.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                        "-subj", "/CN=recon-test.local", "-addext", "subjectAltName=DNS:recon-test.local",
                        "-keyout", cls.key, "-out", cls.crt], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _tls_server(self, version_max):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.crt, self.key)
        ctx.maximum_version = version_max

        def h(c):
            with ctx.wrap_socket(c, server_side=True) as t:
                t.recv(4096)
                t.sendall(b"HTTP/1.1 200 OK\r\nServer: recon-test/1.0\r\nContent-Length: 0\r\n\r\n")
        return MockServer(h)

    def _check(self, version_max, expect_proto):
        srv = self._tls_server(version_max)
        try:
            doc = scan_json("127.0.0.1", "-p", str(srv.port), "--timeout", "2000")
        finally:
            srv.close()
        svc = ports_by_number(doc)[srv.port]["service"]
        self.assertIn(svc["name"], ("ssl/tls", "https"))
        self.assertGreaterEqual(svc["confidence"], 80)
        tls = svc["tls"]
        self.assertIsInstance(tls, dict, "TLS must be recognised (ClientHello vs a real TLS stack)")
        self.assertEqual(tls["protocol"], expect_proto)
        cert = tls.get("certificate")
        if isinstance(cert, dict):  # only present in builds linked against OpenSSL
            self.assertIn("recon-test.local", cert["subject"])
            self.assertTrue(cert["self_signed"])
            self.assertFalse(cert["expired"])
            self.assertEqual(len(cert["sha256"]), 64)
            self.assertIn("recon-test.local", cert["san"])
            self.assertEqual((svc["name"], svc["product"]), ("https", "recon-test"))

    def test_tls13(self):
        self._check(ssl.TLSVersion.TLSv1_3, "TLSv1.3")

    def test_tls12(self):
        self._check(ssl.TLSVersion.TLSv1_2, "TLSv1.2")


if __name__ == "__main__":
    RECON = os.path.abspath(sys.argv.pop(1))
    unittest.main(verbosity=2)
