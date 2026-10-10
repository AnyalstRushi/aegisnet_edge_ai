"""Realistic server-telemetry simulator + feature engineering.
13 metrics per minute, daily load cycle, benign 'flash crowds' (hard negatives) and 6 attack families.
Swap `simulate()` with a loader for CICIDS2017 / NSL-KDD / your own logs - the rest of the pipeline stays the same."""
import numpy as np
import pandas as pd

FEATURES = ["cpu_pct", "mem_pct", "disk_io_mbps", "net_in_mbps", "net_out_mbps", "connections",
            "failed_logins", "unique_dst_ports", "avg_pkt_bytes", "dns_queries", "http_5xx_pct",
            "processes", "file_writes"]
ATTACKS = ["brute_force", "ddos", "port_scan", "exfiltration", "cryptominer", "ransomware"]
_PCT = ["cpu_pct", "mem_pct", "http_5xx_pct"]


def _baseline(n, rng, start):
    t = np.arange(start, start + n)
    load = 0.35 + 0.65 * 0.5 * (1 + np.sin(2 * np.pi * ((t / 60.0) % 24 - 9) / 24))  # daily cycle
    b = rng.normal(0, 1, n)  # shared burst factor -> metrics are correlated like real servers
    N = lambda s: rng.normal(0, s, n)
    d = {
        "cpu_pct": 18 + 30 * load + 2 * b + N(3), "mem_pct": 50 + 10 * load + N(2),
        "disk_io_mbps": 6 + 8 * load + np.abs(N(2)), "net_in_mbps": 40 + 120 * load + 12 * b + N(8),
        "net_out_mbps": 25 + 70 * load + 7 * b + N(6), "connections": 200 + 600 * load + 50 * b + N(30),
        "failed_logins": rng.poisson(1 + 0.5 * load).astype(float),
        "unique_dst_ports": rng.poisson(6 + 3 * load).astype(float),
        "avg_pkt_bytes": 700 - 80 * load + N(50), "dns_queries": rng.poisson(40 + 60 * load).astype(float),
        "http_5xx_pct": 0.4 + np.abs(N(0.25)), "processes": 120 + 10 * load + N(4),
        "file_writes": rng.poisson(30 + 40 * load).astype(float),
    }
    return pd.DataFrame(d)


def _inject(A, ci, kind, s, dur, rng):
    inten = rng.uniform(0.4, 1.0)          # attack strength (weak attacks overlap with normal -> hard task)
    p = rng.uniform(0, 1, 4)
    lerp = lambda a, b, u: a + (b - a) * u
    for k in range(dur):
        i = s + k
        if i >= len(A):
            break
        r = inten * min(1.0, (k + 1) / 3.0) * rng.uniform(0.85, 1.15)  # ramp-up + jitter
        row = A[i]
        c = lambda name: ci[name]
        if kind == "brute_force":
            row[c("failed_logins")] += r * lerp(80, 250, p[0]); row[c("connections")] += r * lerp(150, 400, p[1])
            row[c("cpu_pct")] += r * lerp(5, 12, p[2])
        elif kind == "ddos":
            row[c("net_in_mbps")] *= 1 + r * lerp(3, 8, p[0]); row[c("connections")] *= 1 + r * lerp(4, 11, p[1])
            row[c("http_5xx_pct")] += r * lerp(8, 35, p[2]); row[c("cpu_pct")] += r * lerp(25, 45, p[3])
            row[c("avg_pkt_bytes")] *= 1 - 0.6 * r
        elif kind == "port_scan":
            row[c("unique_dst_ports")] += r * lerp(400, 2000, p[0]); row[c("avg_pkt_bytes")] *= 1 - 0.85 * r
            row[c("connections")] += r * lerp(300, 900, p[1])
        elif kind == "exfiltration":
            row[c("net_out_mbps")] = row[c("net_out_mbps")] * (1 + r * lerp(2, 4, p[0])) + r * lerp(60, 200, p[1])
            row[c("dns_queries")] += r * lerp(300, 800, p[2]); row[c("disk_io_mbps")] += r * lerp(15, 35, p[3])
        elif kind == "cryptominer":
            row[c("cpu_pct")] += r * lerp(40, 55, p[0]); row[c("processes")] += r * lerp(15, 40, p[1])
            row[c("mem_pct")] += r * lerp(8, 15, p[2]); row[c("net_out_mbps")] += r * lerp(5, 15, p[3])
        elif kind == "ransomware":
            row[c("file_writes")] = row[c("file_writes")] * (1 + r * lerp(8, 20, p[0])) + r * lerp(1500, 4000, p[1])
            row[c("disk_io_mbps")] += r * lerp(60, 120, p[2]); row[c("cpu_pct")] += r * lerp(20, 35, p[3])
            row[c("processes")] += r * lerp(20, 60, p[0]); row[c("mem_pct")] += r * lerp(8, 15, p[1])
        elif kind == "flash_crowd":        # BENIGN traffic surge: looks like DDoS but is harmless
            row[c("net_in_mbps")] *= 1 + r * lerp(1.2, 2.0, p[0]); row[c("connections")] *= 1 + r * lerp(1.0, 1.8, p[1])
            row[c("cpu_pct")] += r * lerp(8, 18, p[2]); row[c("http_5xx_pct")] += r * lerp(0.2, 1.0, p[3])
            row[c("net_out_mbps")] *= 1 + 0.5 * r


def simulate(n_minutes, seed=0, attacks=tuple(ATTACKS), flash=True, start_minute=0, rate=1.0, drift=None):
    """Returns DataFrame[minute, 13 metrics, label]. label = 'normal' or the attack family."""
    rng = np.random.default_rng(seed)
    df = _baseline(n_minutes, rng, start_minute)
    A = df[FEATURES].to_numpy(float).copy()
    ci = {f: i for i, f in enumerate(FEATURES)}
    labels = np.array(["normal"] * n_minutes, dtype=object)
    kinds = list(attacks) + (["flash_crowd"] * max(1, len(attacks) // 2) if flash else [])
    cursor = 120
    while kinds and cursor < n_minutes - 60:
        cursor += int(rng.integers(90, 360) / rate)
        dur = int(rng.integers(8, 30))
        if cursor + dur >= n_minutes:
            break
        kind = kinds[int(rng.integers(len(kinds)))]
        _inject(A, ci, kind, cursor, dur, rng)
        if kind != "flash_crowd":
            labels[cursor:cursor + dur] = kind
        cursor += dur
    if drift:                                   # simulate concept drift (e.g. new traffic baseline)
        for f, m in drift.items():
            A[:, ci[f]] *= m
    A = np.maximum(A, 0.0)
    for f in _PCT:
        A[:, ci[f]] = np.minimum(A[:, ci[f]], 100.0)
    out = pd.DataFrame(A, columns=FEATURES)
    out.insert(0, "minute", np.arange(start_minute, start_minute + n_minutes))
    out["label"] = labels
    return out


def build_features(df):
    """26 inputs = log-scaled level of each metric + its change vs the previous 5-minute average."""
    X0 = np.log1p(df[FEATURES].to_numpy(float))
    roll = np.array(pd.DataFrame(X0).rolling(5, min_periods=1).mean().shift(1))
    roll[0] = X0[0]
    return np.hstack([X0, X0 - roll])
