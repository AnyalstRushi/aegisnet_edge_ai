"""Explainable AI + Guardian Agent (bounded autonomy) + Drift Watchdog."""
from collections import Counter
import numpy as np
from .data import FEATURES

PRETTY = {"cpu_pct": "CPU %", "mem_pct": "Memory %", "disk_io_mbps": "Disk I/O MB/s",
          "net_in_mbps": "Inbound Mbps", "net_out_mbps": "Outbound Mbps", "connections": "Open connections",
          "failed_logins": "Failed logins/min", "unique_dst_ports": "Unique ports touched",
          "avg_pkt_bytes": "Avg packet bytes", "dns_queries": "DNS queries/min", "http_5xx_pct": "HTTP 5xx %",
          "processes": "Running processes", "file_writes": "File writes/min"}

# action = (text, needs_human_approval).  Safe actions run automatically, risky ones wait for a human.
PLAYBOOK = {
    "brute_force": dict(sev="HIGH", title="Credential brute-force attack", actions=[
        ("Turn on account lock-out + login rate-limit", False), ("Open ticket and notify on-call engineer", False),
        ("Block offending source IPs at the firewall", True), ("Force password reset for targeted accounts", True)]),
    "ddos": dict(sev="CRITICAL", title="Volumetric DDoS attack", actions=[
        ("Enable CDN / WAF rate-limiting profile", False), ("Page the on-call network engineer", False),
        ("Null-route top offending prefixes", True), ("Scale out replicas behind the load balancer", True)]),
    "port_scan": dict(sev="MEDIUM", title="Network reconnaissance / port scan", actions=[
        ("Raise logging level on the firewall", False), ("Add source to watch-list", False),
        ("Block scanning source IP", True)]),
    "exfiltration": dict(sev="CRITICAL", title="Possible data exfiltration / DNS tunnelling", actions=[
        ("Snapshot network flows for forensics", False), ("Alert security team", False),
        ("Cut outbound traffic for this host", True), ("Disable the affected service account", True)]),
    "cryptominer": dict(sev="HIGH", title="Cryptojacking (unauthorised mining process)", actions=[
        ("Capture process list for forensics", False), ("Open ticket for host owner", False),
        ("Kill suspicious process tree", True), ("Isolate host from network", True)]),
    "ransomware": dict(sev="CRITICAL", title="Ransomware-like mass file encryption", actions=[
        ("Take immediate storage snapshot", False), ("Page incident-response team", False),
        ("Isolate host from network NOW", True), ("Suspend user sessions on the host", True)]),
    "unknown_anomaly": dict(sev="MEDIUM", title="Unknown anomaly (possible zero-day)", actions=[
        ("Increase telemetry resolution for this host", False), ("Send to analyst queue with explanation", False),
        ("Quarantine host for investigation", True)]),
}


def top_features(share_vec, observed, expected, k=3):
    out = []
    for n, j in enumerate(np.argsort(-share_vec)[:k]):
        if n > 0 and share_vec[j] < 0.05:      # hide metrics that contributed under 5%
            break
        out.append({"feature": FEATURES[j], "name": PRETTY[FEATURES[j]], "share": float(share_vec[j]),
                    "observed": float(observed[j]), "expected": float(expected[j])})
    return out


def build_incidents(res, gap=2):
    """Merge consecutive alert windows into incidents and explain each one."""
    p = res.pred
    idx = np.where(p["alert"].to_numpy())[0]
    if len(idx) == 0:
        return []
    groups, cur = [], [idx[0]]
    for i in idx[1:]:
        if i - cur[-1] > gap:
            groups.append(cur)
            cur = []
        cur.append(i)
    groups.append(cur)
    incs = []
    for g in groups:
        g = np.array(g)
        peak = g[np.argmax(p["risk"].to_numpy()[g])]
        kind = Counter(p["label"].to_numpy()[g]).most_common(1)[0][0]
        incs.append({"start": int(p["minute"].iloc[g[0]]), "end": int(p["minute"].iloc[g[-1]]),
                     "duration": int(len(g)), "type": kind, "peak_risk": float(p["risk"].iloc[peak]),
                     "peak_minute": int(p["minute"].iloc[peak]),
                     "why": top_features(res.share[g].mean(0), res.observed[peak], res.expected[peak])})
    return incs


class Guardian:
    """Agent with BOUNDED autonomy: runs only safe actions by itself, asks a human for risky ones.
    (Actions are simulated and written to an audit log - plug in your firewall/ticketing API here.)"""

    def __init__(self):
        self.audit = []

    def triage(self, inc, approved=False):
        pb = PLAYBOOK.get(inc["type"], PLAYBOOK["unknown_anomaly"])
        auto, pending = [], []
        for text, needs in pb["actions"]:
            if needs and not approved:
                pending.append(text)
            else:
                auto.append(text)
                self.audit.append({"minute": inc["end"], "incident": inc["type"], "action": text,
                                   "by": "human-approved" if needs else "guardian-auto"})
        why = "; ".join(f'{w["name"]} = {w["observed"]:.0f} (model expected ~{w["expected"]:.0f})' for w in inc["why"])
        text = (f'[{pb["sev"]}] {pb["title"]} | minutes {inc["start"]}-{inc["end"]} ({inc["duration"]} min) | '
                f'peak risk {inc["peak_risk"]:.0f}/100\nWHY: {why}')
        return {"severity": pb["sev"], "title": pb["title"], "narrative": text,
                "auto_executed": auto, "awaiting_human_approval": pending}


class DriftWatchdog:
    """Population Stability Index per metric: warns when live data no longer looks like training data."""

    def __init__(self, ref_df, bins=10):
        q = np.linspace(0, 1, bins + 1)[1:-1]
        self.edges = {f: np.unique(np.quantile(ref_df[f], q)) for f in FEATURES}
        self.ref = {f: self._hist(ref_df[f].to_numpy(), f) for f in FEATURES}

    def _hist(self, x, f):
        c = np.bincount(np.searchsorted(self.edges[f], x), minlength=len(self.edges[f]) + 1) / len(x)
        return np.clip(c, 1e-4, None)

    def check(self, cur_df):
        psi = {}
        for f in FEATURES:
            cur, ref = self._hist(cur_df[f].to_numpy(), f), self.ref[f]
            psi[f] = float(np.sum((cur - ref) * np.log(cur / ref)))
        worst = max(psi.values())
        status = "DRIFT - retrain model" if worst > 0.25 else ("WATCH" if worst > 0.1 else "STABLE")
        return {"psi": psi, "status": status, "worst_feature": max(psi, key=psi.get), "worst_psi": worst}
