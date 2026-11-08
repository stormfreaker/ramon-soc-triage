"""
ramon.py - RAMON: a locally deployed LLM framework for automated Tier-1 SOC alert triage.

For every enabled detection rule in config.json:
  1. run the rule's Splunk search to find alerts (REST API, port 8089)
  2. add context about the source host and the destination
  3. ask the local model (Ollama) for a JSON verdict, using the system prompt in config.json
  4. send the verdict back to Splunk (HTTP Event Collector, index=ramon)
  5. record one row per alert in results.csv and the full prompt/answer in ramon.log

Usage:
  python ramon.py --new-only                    # what the background service runs every cycle
  python ramon.py --list-rules                  # show the detection rules
  python ramon.py --rule beacon --dry-run       # run one rule, do not write to Splunk
  python ramon.py --index ramon_test --dry-run  # run all rules against the test index
  python ramon.py --test-alert extras/sample_alert.json --dry-run
"""
import argparse
import csv
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # Splunk uses a self-signed cert

BASE = Path(__file__).resolve().parent
CONFIG = json.loads((BASE / "config.json").read_text(encoding="utf-8"))
SYSTEM_PROMPT = (BASE / CONFIG["prompt_file"]).read_text(encoding="utf-8")

logging.basicConfig(filename=BASE / "ramon.log", level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")

REQUIRED_KEYS = ["verdict", "severity", "confidence", "mitre_technique",
                 "key_evidence", "reasoning", "recommended_action"]
CSV_FIELDS = ["run_id", "alert_id", "timestamp_utc", "rule", "model", "prompt_version", "enriched",
              "src_ip", "dest_ip", "dest_port", "indicator", "verdict", "severity", "confidence",
              "likely_explanation", "mitre_technique", "valid_json", "latency_s", "tokens_per_s", "ground_truth"]


# ---------------------------------------------------------------- Splunk ----
def splunk_search(spl, earliest=None):
    """Run a Splunk search through the REST export endpoint and return the result rows."""
    sp = CONFIG["splunk"]
    headers, auth = {}, None
    if sp.get("token"):
        headers["Authorization"] = f'Bearer {sp["token"]}'
    elif sp.get("username"):
        auth = (sp["username"], sp.get("password", ""))
    response = requests.post(
        f'{sp["rest_url"]}/services/search/jobs/export',
        auth=auth, headers=headers,
        data={"search": spl, "output_mode": "json", "earliest_time": earliest or sp.get("earliest", "-60m")},
        verify=sp.get("verify_ssl", False), timeout=180, stream=True,
    )
    response.raise_for_status()
    rows = []
    for line in response.iter_lines():
        if line:
            obj = json.loads(line)
            if "result" in obj and obj.get("preview") is not True:
                rows.append(obj["result"])
    return rows


def fill(template, **values):
    """Insert values into a search template, escaping quotes so data cannot break the search."""
    safe = {k: str(v).replace("\\", "\\\\").replace('"', '\\"') for k, v in values.items()}
    return template.format(**safe)


def context_for(alert, index):
    """What else the source host did, and what is known about the destination."""
    ctx = {}
    if alert.get("src_ip"):
        rows = splunk_search(fill(CONFIG["context_search"], index=index, src_ip=alert["src_ip"]))
        if rows:
            ctx["source_host_activity"] = rows[0]
    if alert.get("dest_ip") and CONFIG.get("dest_context_search"):
        rows = splunk_search(fill(CONFIG["dest_context_search"], index=index, dest_ip=alert["dest_ip"]))
        if rows:
            ctx["destination_info"] = rows[0]
    return ctx


def send_to_splunk(event):
    """Write the verdict into the separate 'ramon' index via HEC (original evidence is never changed)."""
    hec = CONFIG["hec"]
    response = requests.post(
        f'{hec["url"]}/services/collector/event',
        headers={"Authorization": f'Splunk {hec["token"]}'},
        json={"event": event, "sourcetype": "ramon:verdict", "index": hec["index"]},
        verify=hec.get("verify_ssl", False), timeout=30,
    )
    response.raise_for_status()


# ----------------------------------------------------------------- Model ----
def ask_model(rule, alert, context):
    """Send one alert to the local model and parse its JSON verdict."""
    m = CONFIG["model"]
    shown = {k: v for k, v in alert.items() if k not in ("alert_key",) and not k.startswith("_")}
    user_msg = (f"RULE: {rule['name']} - {rule['description']}\n\n"
                f"ALERT:\n{json.dumps(shown, indent=2)}\n\n"
                f"CONTEXT:\n{json.dumps(context, indent=2) if context else 'none provided'}")
    payload = {
        "model": m["name"],
        "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user_msg}],
        "stream": False, "format": "json",
        "options": {"temperature": m["temperature"], "num_ctx": m["num_ctx"]},
    }
    if "think" in m:  # e.g. Qwen3: switch its slow 'thinking' mode off
        payload["think"] = m["think"]
    start = time.perf_counter()
    response = requests.post(f'{m["url"]}/api/chat', json=payload, timeout=m.get("timeout", 300))
    latency = time.perf_counter() - start
    response.raise_for_status()
    data = response.json()
    raw = data.get("message", {}).get("content", "")
    try:
        verdict = json.loads(raw)
        valid = isinstance(verdict, dict) and all(k in verdict for k in REQUIRED_KEYS)
    except json.JSONDecodeError:
        verdict, valid = {}, False
    if not isinstance(verdict, dict):
        verdict, valid = {}, False
    tokens, dur = data.get("eval_count", 0), data.get("eval_duration", 0)
    return verdict, raw, user_msg, latency, (tokens / (dur / 1e9) if dur else 0.0), valid


# ------------------------------------------------------------ Preflight ----
def preflight(need_splunk):
    """Check the model (and Splunk) are reachable, with a clear message if not."""
    m = CONFIG["model"]
    try:
        names = [x["name"] for x in requests.get(f'{m["url"]}/api/tags', timeout=10).json().get("models", [])]
    except requests.RequestException:
        return f'PROBLEM: the AI model server (Ollama) is not reachable at {m["url"]}. Is Ollama running?'
    if m["name"] not in names:
        return f'PROBLEM: model "{m["name"]}" is not installed in Ollama.'
    if need_splunk:
        try:
            splunk_search("| makeresults")
        except requests.HTTPError as err:
            code = err.response.status_code if err.response is not None else "?"
            return f"PROBLEM: Splunk refused the login (HTTP {code}). Check the token in config.json."
        except requests.RequestException:
            return "PROBLEM: Splunk is not reachable on port 8089. Is Splunk running?"
    return None


# ----------------------------------------------------------------- State ----
SEEN_PATH = BASE / "seen_alerts.json"


def load_seen():
    """Alerts already judged: {key: unix time first judged}. Entries older than 2 days are forgotten."""
    try:
        data = json.loads(SEEN_PATH.read_text())
    except (OSError, ValueError):
        return {}
    if isinstance(data, list):  # older format
        data = {k: time.time() for k in data}
    cutoff = time.time() - 2 * 86400
    return {k: t for k, t in data.items() if t > cutoff}


def open_results():
    """results.csv, starting a new file if the columns changed (old one kept as results_<date>.csv)."""
    path = BASE / "results.csv"
    if path.exists():
        with path.open(encoding="utf-8") as f:
            header = f.readline().strip().split(",")
        if header != CSV_FIELDS:
            path.rename(BASE / f"results_until_{datetime.now():%Y%m%d_%H%M}.csv")
    new = not path.exists()
    f = path.open("a", newline="", encoding="utf-8")
    w = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
    if new:
        w.writeheader()
    return f, w


# ------------------------------------------------------------------ Main ----
def main():
    p = argparse.ArgumentParser(description="RAMON - local LLM SOC alert triage")
    p.add_argument("--new-only", action="store_true", help="skip alerts already judged")
    p.add_argument("--rule", help="run only this rule")
    p.add_argument("--index", default=CONFIG.get("network_index", "network"), help="index holding traffic")
    p.add_argument("--dry-run", action="store_true", help="do not send verdicts to Splunk")
    p.add_argument("--no-enrich", action="store_true", help="no context (baseline experiment)")
    p.add_argument("--max", type=int, default=CONFIG.get("max_alerts", 20), help="maximum alerts per run")
    p.add_argument("--list-rules", action="store_true", help="list detection rules and exit")
    p.add_argument("--test-alert", help="JSON file with one alert (skips Splunk)")
    args = p.parse_args()

    rules = [r for r in CONFIG["rules"] if r.get("enabled", True) and (not args.rule or r["name"] == args.rule)]
    if args.list_rules:
        for r in CONFIG["rules"]:
            print(f'{r["name"]:<18} {"on " if r.get("enabled", True) else "off"}  {r["description"]}')
        return 0

    problem = preflight(need_splunk=not args.test_alert)
    if problem:
        print(problem)
        logging.error(problem)
        return 1

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    seen = load_seen()
    work = []  # (rule, alert)
    if args.test_alert:
        alert = json.loads(Path(args.test_alert).read_text(encoding="utf-8"))
        work.append(({"name": alert.get("rule", "test"), "description": "manual test alert"}, alert))
    else:
        for rule in rules:
            try:
                found = splunk_search(fill(rule["search"], index=args.index), rule.get("earliest"))
            except requests.RequestException as err:
                print(f"rule {rule['name']}: search failed ({err})")
                continue
            for a in found[: rule.get("max_alerts", 10)]:
                a.setdefault("alert_key", f'{a.get("src_ip")}|{a.get("dest_ip")}|{a.get("dest_port")}|{a.get("first_seen")}')
                key = f'{rule["name"]}|{a["alert_key"]}'
                if args.new_only and key in seen:
                    continue
                work.append((rule, a))
    work = work[: args.max]
    by_rule = {}
    for r, _ in work:
        by_rule[r["name"]] = by_rule.get(r["name"], 0) + 1
    print(f"Run {run_id}: {len(work)} alert(s) {by_rule or ''} prompt {CONFIG.get('prompt_version', '?')}")

    f, writer = open_results()
    with f:
        for i, (rule, alert) in enumerate(work, 1):
            alert_id = f"{run_id}-{i:04d}"
            try:
                ctx = {} if (args.no_enrich or args.test_alert) else context_for(alert, args.index)
                verdict, raw, user_msg, latency, tps, valid = ask_model(rule, alert, ctx)
            except requests.RequestException as err:
                logging.error("alert %s failed: %s", alert_id, err)
                print(f"[{i}/{len(work)}] ERROR: {err}")
                continue
            logging.info(json.dumps({"alert_id": alert_id, "rule": rule["name"], "prompt": user_msg, "response": raw}))
            row = {
                "run_id": run_id, "alert_id": alert_id,
                "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "rule": rule["name"], "model": CONFIG["model"]["name"],
                "prompt_version": CONFIG.get("prompt_version", "?"), "enriched": not args.no_enrich,
                "src_ip": alert.get("src_ip", ""), "dest_ip": alert.get("dest_ip", ""),
                "dest_port": alert.get("dest_port", ""), "indicator": alert.get("indicator", ""),
                "verdict": verdict.get("verdict", ""), "severity": verdict.get("severity", ""),
                "confidence": verdict.get("confidence", ""), "likely_explanation": verdict.get("likely_explanation", ""),
                "mitre_technique": verdict.get("mitre_technique", ""), "valid_json": valid,
                "latency_s": round(latency, 2), "tokens_per_s": round(tps, 1), "ground_truth": "",
            }
            if not args.dry_run:
                try:
                    send_to_splunk({**row, **verdict, "rule_description": rule["description"],
                                    "alert_details": {k: v for k, v in alert.items() if k != "alert_key"}})
                except requests.RequestException as err:
                    logging.error("HEC send failed for %s: %s", alert_id, err)
                    print(f"  warning: could not send to Splunk ({err})")
            writer.writerow(row)
            f.flush()
            if not args.test_alert:
                seen[f'{rule["name"]}|{alert["alert_key"]}'] = time.time()
                SEEN_PATH.write_text(json.dumps(seen))
            target = f'{row["dest_ip"]}:{row["dest_port"]}' if row["dest_ip"] else row["indicator"]
            print(f'[{i}/{len(work)}] {rule["name"]:<17} {row["src_ip"]} -> {target}  '
                  f'{row["verdict"] or "INVALID"} / {row["severity"]} / {row["confidence"]}  ({row["latency_s"]}s)')
            if args.test_alert:
                print(json.dumps(verdict, indent=2))
    print("Done. Results appended to results.csv")
    return 0


if __name__ == "__main__":
    sys.exit(main())
