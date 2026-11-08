"""Builds a SYNTHETIC, labelled test capture for RAMON's rules. No real traffic is generated.
Uses lab (192.168.56.x) and documentation (RFC 5737) addresses only."""
import csv, random, time
from datetime import datetime
from pathlib import Path
random.seed(42)
now = time.time()
start = now - 40 * 60
rows, labels = [], []
HDR = ["time_iso","frame.time_epoch","ip.src","ip.dst","frame.protocols","tcp.srcport","tcp.dstport","udp.dstport",
       "dns.qry.name","http.host","tls.handshake.extensions_server_name","frame.len","tcp.flags.syn","tcp.flags.ack","dns.a"]
def add(t, src, dst, proto, sport="", dport="", udp="", dns="", host="", sni="", ln=60, syn="", ack="", a=""):
    rows.append([datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S.%f"), f"{t:.9f}", src, dst, proto,
                 sport, dport, udp, dns, host, sni, ln, syn, ack, a])
def connect(t, src, dst, dport, sni=""):
    sp = random.randint(49152, 65535)
    add(t, src, dst, "eth:ethertype:ip:tcp", sp, dport, ln=66, syn="True", ack="False")
    add(t+0.02, dst, src, "eth:ethertype:ip:tcp", dport, sp, ln=66, syn="True", ack="True")
    for k in range(6):
        add(t+0.05+k*0.01, src, dst, "eth:ethertype:ip:tcp" + (":tls" if sni and k == 0 else ""), sp, dport,
            sni=sni if k == 0 else "", ln=random.randint(60, 900), syn="False", ack="True")

WS, ATT, VIC = "192.168.56.10", "192.168.56.20", "192.168.56.30"
# 1 MALICIOUS beacon: workstation -> 203.0.113.50:8443 every 60s (+/-0.5s), after a duckdns lookup
add(start+5, WS, "192.168.56.1", "eth:ethertype:ip:udp:dns", udp="53", dns="upd8-k3x9q.duckdns.org", ln=80)
add(start+5.1, "192.168.56.1", WS, "eth:ethertype:ip:udp:dns", udp="54111", dns="upd8-k3x9q.duckdns.org", ln=96, a="203.0.113.50")
for i in range(30):
    connect(start + 10 + i*60 + random.uniform(-0.5, 0.5), WS, "203.0.113.50", 8443)
labels += [("beacon","203.0.113.50:8443","malicious"), ("unusual_port","203.0.113.50:8443","malicious"),
           ("suspicious_domain","upd8-k3x9q.duckdns.org","malicious")]
# 2 BENIGN irregular repeat: chat app reconnecting at random intervals (should NOT be a beacon)
t = start + 20
while t < now - 60:
    connect(t, WS, "198.51.100.20", 5222); t += random.uniform(20, 140)
labels += [("unusual_port","198.51.100.20:5222","benign")]
# 3 MALICIOUS port scan (synthetic rows only): attacker -> victim, 40 ports in ~20s
scan_t = now - 8*60
for i, port in enumerate([21,22,23,25,53,80,110,111,135,139,143,389,443,445,465,587,636,993,995,1433,1521,1723,2049,
                          3306,3389,5432,5900,5985,6379,8000,8080,8081,8443,8888,9000,9200,10000,11211,27017,50000]):
    add(scan_t + i*0.5, ATT, VIC, "eth:ethertype:ip:tcp", 40000+i, port, ln=60, syn="True", ack="False")
labels += [("scan","port scan by "+ATT,"malicious")]
# 4 MALICIOUS ping sweep: attacker pings 25 lab hosts
for i in range(25):
    add(now - 6*60 + i*0.3, ATT, f"192.168.56.{100+i}", "eth:ethertype:ip:icmp:data", ln=74)
labels += [("scan","ping sweep by "+ATT,"malicious")]
# 5 SUSPICIOUS random-looking domain on a risky TLD
add(now - 15*60, WS, "192.168.56.1", "eth:ethertype:ip:udp:dns", udp="53", dns="qx7v2k9d4m8z1w5r.top", ln=80)
labels += [("suspicious_domain","qx7v2k9d4m8z1w5r.top","suspicious")]
# 6 new website (benign) on 443
connect(now - 12*60, WS, "198.51.100.77", 443, sni="www.python.org")
labels += [("new_website","python.org","benign")]
# 7 BENIGN internal printer and normal web noise
for i in range(12):
    add(now - 20*60 + i, WS, "192.168.56.240", "eth:ethertype:ip:tcp", 51000, 9100, ln=900, syn="False", ack="True")
labels += [("unusual_port","192.168.56.240:9100","benign")]
for i in range(60):
    connect(start + random.uniform(0, 2300), WS, "142.250.187.196", 443, sni="www.google.com")

rows.sort(key=lambda r: float(r[1]))
out = Path(__file__).with_name("selftest.csv")
with out.open("w", newline="") as f:
    w = csv.writer(f, quoting=csv.QUOTE_ALL); w.writerow(HDR); w.writerows(rows)
with out.with_name("selftest_labels.csv").open("w", newline="") as f:
    w = csv.writer(f); w.writerow(["rule","target","ground_truth"]); w.writerows(labels)
print(len(rows), "rows,", len(labels), "labelled cases")
