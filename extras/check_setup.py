"""check_setup.py - checks that Ollama, Splunk REST and Splunk HEC are all reachable for Ramon."""
import json
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
cfg = json.loads((Path(__file__).resolve().parent.parent / "config.json").read_text(encoding="utf-8"))

# Ask for the Splunk password at run time instead of storing it in config.json.
if cfg["splunk"].get("password") in (None, "", "CHANGE_ME"):
    import getpass
    import os
    cfg["splunk"]["password"] = os.environ.get("SPLUNK_PASSWORD") or getpass.getpass("Splunk password: ")


def check(name, fn):
    try:
        print(f"[ OK ] {name}: {fn()}")
    except Exception as err:
        print(f"[FAIL] {name}: {err}")


def model():
    tags = requests.get(f'{cfg["model"]["url"]}/api/tags', timeout=10).json()
    names = [m["name"] for m in tags.get("models", [])]
    if cfg["model"]["name"] not in names:
        raise RuntimeError(f"model not found. Installed: {names}")
    return cfg["model"]["name"] + " found"


def splunk_rest():
    sp = cfg["splunk"]
    r = requests.get(f'{sp["rest_url"]}/services/server/info?output_mode=json',
                     auth=(sp["username"], sp["password"]), verify=False, timeout=10)
    r.raise_for_status()
    return "version " + r.json()["generator"]["version"]


def splunk_hec():
    h = cfg["hec"]
    r = requests.post(f'{h["url"]}/services/collector/event',
                      headers={"Authorization": f'Splunk {h["token"]}'},
                      json={"event": "ramon setup check", "index": h["index"]}, verify=False, timeout=10)
    r.raise_for_status()
    return r.text


check("Ollama model", model)
check("Splunk REST (8089)", splunk_rest)
check("Splunk HEC (8088)", splunk_hec)
