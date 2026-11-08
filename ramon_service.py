"""
ramon_service.py - runs RAMON silently in the background.

Every cycle (default 2 minutes) it:
  1. captures this PC's own traffic with tshark (no broadcast/multicast)
  2. keeps only what RAMON needs (pings, connection starts, DNS, website names, unusual ports)
  3. drops the CSV into 'incoming', which Splunk loads automatically (index=network)
  4. runs ramon.py on any NEW alerts, so verdicts appear in Splunk (index=ramon)

Control it with RAMON.bat. Activity is written to service.log, current state to status.json.
"""
import csv
import io
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parent
STOP = BASE / "STOP"
STATUS = BASE / "status.json"
LOCK = BASE / "ramon.lock"
NO_WINDOW = 0x08000000 if os.name == "nt" else 0

FIELDS = ["frame.time_epoch", "ip.src", "ip.dst", "frame.protocols", "tcp.srcport", "tcp.dstport",
          "udp.dstport", "dns.qry.name", "http.host", "tls.handshake.extensions_server_name", "frame.len",
          "tcp.flags.syn", "tcp.flags.ack", "dns.a"]
KEEP = ('ip && (icmp || tcp.flags.syn==1 || dns || tls.handshake.type==1 || http.request '
        '|| (tcp && !(tcp.port==80 || tcp.port==443)) || (udp && !(udp.port==443)))')
state = {}


def settings():
    """Re-read config.json every cycle, so edits apply without a restart."""
    cfg = json.loads((BASE / "config.json").read_text(encoding="utf-8"))
    svc = cfg.get("service", {})
    return {
        "tshark": svc.get("tshark", r"C:\Program Files\Wireshark\tshark.exe"),
        "cycle": int(svc.get("cycle_seconds", 120)),
        "interface": svc.get("interface", ""),
        "keep_days": int(svc.get("keep_csv_days", 1)),
        "model": cfg.get("model", {}).get("name", ""),
    }


def log(msg):
    with open(BASE / "service.log", "a", encoding="utf-8") as f:
        f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} {msg}\n")


def save_status(**kw):
    state.update(kw, updated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    STATUS.write_text(json.dumps(state, indent=2), encoding="utf-8")


def run(cmd, **kw):
    return subprocess.run(cmd, creationflags=NO_WINDOW, capture_output=True, text=True, **kw)


def acquire_lock():
    """Only one copy of RAMON may run. Returns the open lock file, or None if already running."""
    f = open(LOCK, "a+")
    try:
        if os.name == "nt":
            import msvcrt
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return f
    except OSError:
        f.close()
        return None


def pick_interface(cfg):
    if cfg["interface"]:
        return cfg["interface"]
    # the adapter carrying the default route is the one your internet traffic uses
    ps = ("Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object {$_.RouteMetric + $_.InterfaceMetric} | "
          "Select-Object -First 1 -ExpandProperty InterfaceAlias")
    return run(["powershell", "-NoProfile", "-Command", ps]).stdout.strip() or "Ethernet 2"


def wait_or_stop(seconds):
    """Sleep, but return True straight away if a stop was requested."""
    end = time.time() + seconds
    while time.time() < end:
        if STOP.exists():
            return True
        time.sleep(1)
    return STOP.exists()


def capture(cfg, iface, pcap):
    """Run tshark for one cycle; can be interrupted by a stop request."""
    proc = subprocess.Popen([cfg["tshark"], "-i", iface, "-f", "not broadcast and not multicast",
                             "-a", f"duration:{cfg['cycle']}", "-w", str(pcap), "-q"],
                            creationflags=NO_WINDOW, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    while proc.poll() is None:
        if STOP.exists():
            proc.terminate()
            proc.wait(timeout=10)
            return "stopped"
        time.sleep(1)
    return proc.stderr.read().strip()


def export(cfg, pcap):
    """Convert the capture to CSV, adding a time_iso column Splunk can read as the event time."""
    cmd = [cfg["tshark"], "-r", str(pcap), "-Y", KEEP, "-T", "fields", "-E", "header=y",
           "-E", "separator=,", "-E", "quote=d", "-E", "occurrence=f"]
    for fld in FIELDS:
        cmd += ["-e", fld]
    res = run(cmd)
    rows = list(csv.reader(io.StringIO(res.stdout)))
    if len(rows) < 2:
        return None, 0, res.stderr.strip()
    out = io.StringIO()
    w = csv.writer(out, quoting=csv.QUOTE_ALL, lineterminator="\n")
    w.writerow(["time_iso"] + rows[0])
    for r in rows[1:]:
        try:
            iso = datetime.fromtimestamp(float(r[0])).strftime("%Y-%m-%d %H:%M:%S.%f")
        except (ValueError, IndexError):
            continue
        w.writerow([iso] + r)
    return out.getvalue(), len(rows) - 1, ""


def tidy(cfg):
    """Delete files Splunk has already loaded (older than keep_csv_days) and leftovers."""
    cutoff = time.time() - cfg["keep_days"] * 86400
    for f in (BASE / "incoming").glob("live_*.csv"):
        if f.stat().st_mtime < cutoff or f.stat().st_size == 0:
            f.unlink(missing_ok=True)
    for pattern in ("pcaps/live_*.pcapng", "exports/live_*.tmp"):
        for f in BASE.glob(pattern):
            if f.stat().st_mtime < time.time() - 3600:
                f.unlink(missing_ok=True)


def cycle(cfg, iface):
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap = BASE / "pcaps" / f"live_{stamp}.pcapng"
    tmp = BASE / "exports" / f"live_{stamp}.tmp"
    csv_out = BASE / "incoming" / f"live_{stamp}.csv"

    save_status(state_now="capturing", cycle_started=datetime.now().strftime("%H:%M:%S"))
    err = capture(cfg, iface, pcap)
    if err == "stopped":
        pcap.unlink(missing_ok=True)
        return
    if not pcap.exists():
        log(f"capture failed on '{iface}': {err[:300]}")
        save_status(last_error=f"capture failed: {err[:200]}")
        wait_or_stop(30)
        return

    text, rows, xerr = export(cfg, pcap)
    pcap.unlink(missing_ok=True)  # raw packets are never kept
    if rows:
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(csv_out)      # appears complete, so Splunk never reads half a file
        log(f"captured {rows} packets on '{iface}' -> {csv_out.name}")
    elif xerr:
        log(f"tshark export error: {xerr[:300]}")
    else:
        log(f"captured 0 packets on '{iface}' (quiet network, or wrong adapter - see README)")

    save_status(state_now="analysing", last_packets=rows)
    if rows and wait_or_stop(20):  # give Splunk time to index the file
        return
    tri = run([sys.executable, str(BASE / "ramon.py"), "--new-only", "--max", "20"], cwd=BASE)
    out = (tri.stdout + tri.stderr).strip()
    for line in out.splitlines():
        if line.strip():
            log("ramon: " + line.strip())
    m = re.search(r"(\d+) alert\(s\)", out)
    save_status(state_now="waiting", last_cycle_end=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                last_alerts=int(m.group(1)) if m else 0,
                last_error="" if tri.returncode == 0 else out.splitlines()[-1][:200] if out else "ramon.py failed")
    tidy(cfg)


def main():
    lock = acquire_lock()
    if lock is None:
        log("start ignored: RAMON is already running")
        return
    for d in ("pcaps", "exports", "incoming"):
        (BASE / d).mkdir(exist_ok=True)
    STOP.unlink(missing_ok=True)
    cfg = settings()
    iface = pick_interface(cfg)
    state.clear()
    save_status(state_now="starting", running=True, pid=os.getpid(), interface=iface,
                started=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), last_error="")
    log(f"RAMON started (interface '{iface}', cycle {cfg['cycle']}s, model {cfg['model']})")
    tidy(cfg)
    while not STOP.exists():
        try:
            cfg = settings()
            save_status(model=cfg["model"])
            cycle(cfg, iface)
        except Exception as err:  # keep running whatever happens; record the problem
            log(f"error: {err}")
            save_status(last_error=str(err)[:200])
            wait_or_stop(30)
    STOP.unlink(missing_ok=True)
    save_status(state_now="stopped", running=False)
    log("RAMON stopped")
    lock.close()


if __name__ == "__main__":
    main()
