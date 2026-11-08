# RAMON: local LLM triage for SOC alerts

RAMON is a home-lab Tier-1 SOC assistant that runs on one Windows PC. Every 2 minutes it captures the PC's own network traffic, loads it into Splunk, runs five detection rules, and asks a locally hosted LLM (through Ollama) to judge each new alert. The verdict, with reasoning, a MITRE ATT&CK technique and a recommended action, goes back into Splunk and into a CSV for evaluation. No log data leaves the machine.

The project set out to answer one question: can a small LLM running on ordinary hardware reliably help with Tier-1 alert triage? On a first labelled set of 14 alerts, Qwen3 14B with prompt v2 reached an F1 score of 0.86. Two security-specialised 8B models flagged every benign alert as suspicious (F1 0.67). See [Evaluation](#evaluation).

RAMON stands for Real-time Alert Monitoring and Orchestration Network. It recommends; a human decides. It never blocks or changes traffic.

## How it works

```
 tshark (120 s capture)
   │  keep only pings, connection starts, DNS, TLS SNI, unusual ports (~95% smaller)
   ▼
 incoming\live_*.csv ──► Splunk monitor input ──► index=network
                                                     │
                         5 detection rules (Splunk REST, port 8089)
                                                     │
                         ramon.py adds context about source and destination
                                                     │
                         Ollama (local model) ──► JSON verdict
                                                     │
              Splunk HEC (port 8088) ──► index=ramon      results.csv + ramon.log
```

1. **Capture.** `ramon_service.py` runs tshark for one cycle (default 120 s). Broadcast and multicast are excluded.
2. **Reduce.** Only the fields triage needs are exported to CSV. The raw pcap is deleted straight away.
3. **Load.** The CSV lands in `incoming\`, which Splunk monitors (`index=network`).
4. **Detect.** `ramon.py` runs each enabled rule from `config.json` as a Splunk search. Alerts already judged are skipped (`seen_alerts.json`).
5. **Enrich.** For each alert it adds what else the source host did and what is known about the destination (DNS names, website names, internal or external).
6. **Triage.** The rule, alert and context go to the model with the system prompt. The model returns JSON: verdict, severity, confidence, likely explanation, MITRE technique, key evidence, reasoning and recommended action.
7. **Record.** Verdicts go to a separate Splunk index (`ramon`) through the HTTP Event Collector, so the original evidence is never modified. Every prompt and answer is logged in `ramon.log`, and one row per alert is appended to `results.csv`.

### Detection rules

| Rule | Looks for | Window |
|---|---|---|
| `unusual_port` | TCP conversations on ports other than 80, 443 and 53 with more than 5 packets | 60 min |
| `new_website` | Websites (TLS SNI or HTTP host) seen for the first time, minus an allowlist of common services | 7-day baseline |
| `suspicious_domain` | Dynamic-DNS and tunnelling services, high-risk TLDs, long random-looking names | 60 min |
| `scan` | One host probing 15+ ports, 10+ internal hosts, or pinging 10+ hosts | 5-min buckets |
| `beacon` | 6+ new connections to the same destination at very regular intervals (jitter ≤ 0.15) | 60 min |

Each rule is a Splunk search in `config.json` and can be switched off with `"enabled": false`. `new_website` needs about a day of normal browsing before it knows what "normal" is.

## Requirements

- Windows 10 or 11 (the service and control panel use Windows tools; the Python code mostly runs elsewhere too)
- Python 3.10+ with the `py` / `pyw` launcher
- [Wireshark](https://www.wireshark.org/) with TShark and Npcap
- [Splunk Enterprise](https://www.splunk.com/) (the free trial or Splunk Free)
- [Ollama](https://ollama.com/) and a model, for example `qwen3:14b`
- A GPU helps. About 5 seconds per alert on an RTX 5060 Ti with Qwen3 14B.

## Setup

### 1. Get the code

```bash
git clone https://github.com/<your-user>/<this-repo>.git
```

```bash
cd <this-repo>
```

```bash
py -m pip install -r requirements.txt
```

### 2. Install a model

```bash
ollama pull qwen3:14b
```

Any Ollama model works. Set its name in `config.json` under `model.name`. The evaluation also used `hf.co/fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF:Q8_0`.

### 3. Configure Splunk

1. Create three indexes: `network` (traffic), `ramon` (verdicts) and, if you forward laptop logs, `endpoint`.
2. Add a monitor input on the `incoming\` folder with sourcetype `tshark_csv`. Examples are in [`splunk/inputs.conf.example`](splunk/inputs.conf.example) and [`splunk/props.conf.example`](splunk/props.conf.example). Field names such as `ip.src` must arrive as `ip_src`, because the rules search for those.
3. Turn on the HTTP Event Collector (Settings > Data inputs > HTTP Event Collector), create a token, and allow it to write to the `ramon` index.
4. Create an authentication token for the REST API (Settings > Tokens). Tokens expire; the default here was 180 days.

Splunk Free has no logins or tokens. After a trial converts to Free, leave `splunk.token`, `username` and `password` empty and RAMON calls the REST API without authentication.

### 4. Create your config

```bash
copy config.example.json config.json
```

Then edit `config.json`:

| Setting | What to put there |
|---|---|
| `splunk.token` | Your Splunk REST API token (or leave empty and use `username` / `password`) |
| `hec.token` | Your HTTP Event Collector token |
| `model.name` | The Ollama model to use |
| `service.interface` | Your network adapter, e.g. `"Ethernet 2"`, or `""` to pick the adapter with the default route |
| `service.tshark` | Path to `tshark.exe` if it is not in the default location |
| `rules[].search` | The `new_website` allowlist is a starting point; add the services you use |

`config.json` is in `.gitignore`. Never commit it.

### 5. Check and start

Double-click `RAMON.bat`:

```
1 Start   2 Stop   3 Health check   4 Open dashboard   5 Open log
6 Autostart ON     7 Autostart OFF
```

Run **3 Health check** first. Every line should say `[ OK ]`:

| Failure | Fix |
|---|---|
| AI model | Start Ollama, or `ollama pull` the model named in `config.json` |
| Splunk search (8089) | Start Splunk, or replace an expired token |
| Splunk collector (8088) | Turn on HEC and check the token |
| Wireshark tshark | Reinstall Wireshark with TShark and Npcap |

If `service.log` keeps saying `captured 0 packets`, set `service.interface` to the right adapter.

**Autostart ON** writes a small launcher into your Windows Startup folder so RAMON starts at login.

## Running by hand

```bash
py ramon.py --list-rules
```

```bash
py ramon.py --test-alert extras/sample_alert.json --dry-run
```

```bash
py ramon.py --rule beacon --dry-run
```

```bash
py ramon.py --no-enrich --dry-run
```

`--dry-run` skips writing to Splunk. `--no-enrich` sends alerts without context, for the baseline experiment. `--max N` limits how many alerts one run judges.

## Synthetic test data

`extras/selftest/make_selftest.py` builds a synthetic, labelled capture using lab (`192.168.56.x`) and documentation (RFC 5737) addresses only. It contains a beacon, a port scan, a ping sweep, a dynamic-DNS lookup, a random `.top` domain, and benign look-alikes (an irregular chat app, a printer, a new website).

```bash
py extras/selftest/make_selftest.py
```

Load `selftest.csv` into an index called `ramon_test` (same sourcetype), then:

```bash
py ramon.py --index ramon_test --dry-run
```

Compare the verdicts in `results.csv` with `selftest_labels.csv`.

## Evaluation

14 labelled alerts: 8 from the synthetic capture, 4 from an earlier synthetic demo and 2 from real home-network traffic. Each alert was sent with the same context to each model and prompt. "Malicious" or "suspicious" counts as escalated, "benign" as cleared.

| Model | Prompt | Attacks caught (of 7) | Benign cleared (of 7) | Precision | Recall | F1 | Median s/alert |
|---|---|---|---|---|---|---|---|
| Foundation-Sec 8B | v1 | 7 | 0 | 0.50 | 1.00 | 0.67 | 3.5 |
| Foundation-Sec 8B | v2 | 7 | 0 | 0.50 | 1.00 | 0.67 | 5.0 |
| WhiteRabbitNeo 7B | v1 | 7 | 0 | 0.50 | 1.00 | 0.67 | 3.2 |
| WhiteRabbitNeo 7B | v2 | 6 | 1 | 0.50 | 0.86 | 0.63 | 3.8 |
| Qwen3 14B | v2 | 6 | 6 | 0.86 | 0.86 | 0.86 | 5.4 |

Raw results are in [`evaluation/`](evaluation/).

**Findings**

- Prompt v1 (`system_prompt_v1.txt`) told the model that missing an attack is worse than a false alarm. Every model then escalated almost everything, often with the same confidence of 60 to 70.
- Prompt v2 (`system_prompt_v2.txt`) asks the model to name the normal use first, require specific indicators of malice, and calibrate confidence. That alone did not fix the small models.
- Model size mattered more than security specialisation on this task.
- The most important error: Qwen3 called an internal SMB sweep on port 445 "legitimate file sharing". That case needs more work.

**Limitations.** 14 alerts is far too few for firm conclusions, 12 are synthetic, and the ground truth was set by the author. The next step is a large public labelled dataset.

## Files

| File | Purpose |
|---|---|
| `RAMON.bat` | Control panel |
| `ramon_service.py` | Background loop: capture, export, triage, tidy up |
| `ramon.py` | Triage: Splunk alerts, context, model, verdict, Splunk |
| `ramon_status.py` | Status, health check and stop (used by `RAMON.bat`) |
| `start_ramon.vbs` | Starts the service without a window |
| `config.example.json` | Settings template with placeholder tokens |
| `system_prompt_v1.txt`, `system_prompt_v2.txt` | System prompts (v2 in use) |
| `splunk/` | Example Splunk input and parsing config |
| `evaluation/` | Model and prompt comparison results |
| `extras/` | Setup check, debug launchers, sample alert, synthetic test data |

Created at runtime and ignored by git: `config.json`, `ramon.log`, `service.log`, `results.csv`, `status.json`, `seen_alerts.json`, `incoming\`, `pcaps\`, `exports\`.

## Privacy and safety

- The model runs locally in Ollama. Alerts and context are never sent to a cloud service.
- Only metadata is stored (addresses, ports, DNS names, TLS SNI), never packet contents. Raw captures are deleted after each cycle.
- Only traffic to and from this PC is captured. Capture only networks you own or are allowed to monitor.
- The model writes only to its own index. Everything inside the alert is treated as data, not instructions, to reduce prompt-injection risk from crafted domain names.
