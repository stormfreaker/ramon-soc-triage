"""ramon_status.py - status, health check and stop for RAMON (used by RAMON.bat)."""
import json
import os
import sys
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent
STARTUP = Path(os.environ.get("APPDATA", "")) / "Microsoft/Windows/Start Menu/Programs/Startup/Ramon.vbs"


def running():
    """RAMON holds a lock on ramon.lock while it runs; if we can take it, RAMON is not running."""
    lock = BASE / "ramon.lock"
    if not lock.exists():
        return False
    try:
        f = open(lock, "a+")
    except OSError:
        return True
    try:
        if os.name == "nt":
            import msvcrt
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(f, fcntl.LOCK_UN)
        return False
    except OSError:
        return True
    finally:
        f.close()


def status_file():
    try:
        return json.loads((BASE / "status.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def short():
    st = status_file()
    on = running()
    print(f"  RAMON is {'RUNNING' if on else 'STOPPED'}" + (f"  ({st.get('state_now', '')})" if on else ""))
    if st.get("last_cycle_end"):
        print(f"  Last cycle: {st['last_cycle_end']}  -  {st.get('last_packets', 0)} packets, "
              f"{st.get('last_alerts', 0)} new alert(s)")
    if on and st.get("last_error"):
        print(f"  Last problem: {st['last_error']}")
    print(f"  Autostart at login: {'ON' if STARTUP.exists() else 'OFF'}")


def check(name, fn):
    try:
        print(f"  [ OK ] {name}: {fn()}")
        return True
    except Exception as err:
        print(f"  [FAIL] {name}: {err}")
        return False


def health():
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    cfg = json.loads((BASE / "config.json").read_text(encoding="utf-8"))
    m, sp, hec = cfg["model"], cfg["splunk"], cfg["hec"]

    def model():
        names = [x["name"] for x in requests.get(f'{m["url"]}/api/tags', timeout=10).json()["models"]]
        if m["name"] not in names:
            raise RuntimeError(f'"{m["name"]}" not installed in Ollama')
        return m["name"].split("/")[-1]

    def splunk():
        r = requests.get(f'{sp["rest_url"]}/services/server/info?output_mode=json', verify=False, timeout=10,
                         headers={"Authorization": f'Bearer {sp["token"]}'} if sp.get("token") else {})
        r.raise_for_status()
        return "logged in with token, version " + r.json()["generator"]["version"]

    def collector():
        r = requests.get(f'{hec["url"]}/services/collector/health', verify=False, timeout=10)
        r.raise_for_status()
        return "ready to receive verdicts"

    def tshark():
        path = Path(cfg.get("service", {}).get("tshark", r"C:\Program Files\Wireshark\tshark.exe"))
        if not path.exists():
            raise RuntimeError(f"not found at {path}")
        return "installed"

    print("\n  Health check")
    ok = all([check("AI model (Ollama)", model), check("Splunk search (8089)", splunk),
              check("Splunk collector (8088)", collector), check("Wireshark tshark", tshark)])
    print()
    short()
    print("\n  " + ("Everything is ready." if ok else "Fix the [FAIL] items above (see README.txt)."))


def stop():
    if not running():
        print("  RAMON is not running.")
        return
    (BASE / "STOP").touch()
    print("  Stopping RAMON...", end="", flush=True)
    for _ in range(30):
        time.sleep(1)
        if not running():
            print(" stopped.")
            return
        print(".", end="", flush=True)
    print(" still finishing; it will stop within a minute.")


if __name__ == "__main__":
    {"--short": short, "--health": health, "--stop": stop}.get(sys.argv[1] if len(sys.argv) > 1 else "--short", short)()
