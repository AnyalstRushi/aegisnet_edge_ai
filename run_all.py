"""AegisNet by Rushi.
ONE-CLICK PIPELINE:  python run_all.py   (add --quick for a 1-minute smoke run)
simulate data -> train both brains -> evaluate -> zero-day test -> drift test -> incident reports -> HTML report."""
import json
import pathlib
import sys
import time
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score, roc_curve

from aegisnet.data import simulate, build_features, ATTACKS
from aegisnet.models import AegisNet
from aegisnet.explain import build_incidents, Guardian, DriftWatchdog
from aegisnet import report

ZERO_DAY = "ransomware"


def episodes(labels):
    """Contiguous attack runs -> list of (start_idx, end_idx, type)."""
    out, i, n = [], 0, len(labels)
    while i < n:
        if labels[i] != "normal":
            j = i
            while j + 1 < n and labels[j + 1] == labels[i]:
                j += 1
            out.append((i, j, labels[i]))
            i = j + 1
        else:
            i += 1
    return out


def prf(flag, y):
    tp, fp, fn = int((flag & y).sum()), int((flag & ~y).sum()), int((~flag & y).sum())
    return {"precision": tp / max(tp + fp, 1), "recall": tp / max(tp + fn, 1), "fpr": fp / max((~y).sum(), 1),
            "f1": 2 * tp / max(2 * tp + fp + fn, 1)}


def main(quick=False):
    t0 = time.time()
    out = pathlib.Path("outputs")
    fig = out / "figures"
    fig.mkdir(parents=True, exist_ok=True)
    days, tdays = (8, 4) if quick else (20, 10)
    ea, ec = (25, 20) if quick else (60, 40)

    print("[1/7] simulating telemetry ...")
    normal = simulate(days * 1440, seed=1, attacks=(), flash=True)
    labeled = simulate(days * 1440, seed=2)
    test = simulate(tdays * 1440, seed=3, start_minute=60 * 1440)
    y = (test["label"] != "normal").to_numpy()
    lab = test["label"].to_numpy()

    print("[2/7] training Dual-Brain model ...")
    model = AegisNet().fit(normal, labeled, epochs_ae=ea, epochs_clf=ec)
    model.save(out / "aegisnet_model.npz")
    if not quick:                                   # keep the shipped pretrained model in sync
        pathlib.Path("models").mkdir(exist_ok=True)
        model.save(pathlib.Path("models") / "aegisnet_model.npz")
    res = model.analyze(test)
    p = res.pred

    print("[3/7] evaluating ...")
    iso = IsolationForest(n_estimators=150, random_state=0).fit(model._std(build_features(normal)))
    iso_score = -iso.score_samples(model._std(build_features(test)))
    scores = {"AegisNet fused risk": p["risk"].to_numpy(), "Autoencoder only": p["ae_score"].to_numpy(),
              "Classifier only": p["p_attack"].to_numpy(), "Isolation Forest (baseline)": iso_score}
    curves, aucs = {}, {}
    for k, s in scores.items():
        fpr, tpr, _ = roc_curve(y, s)
        aucs[k] = float(roc_auc_score(y, s))
        curves[k] = (fpr, tpr, aucs[k])
    m_raw, m_alert = prf(p["raw_alert"].to_numpy(), y), prf(p["alert"].to_numpy(), y)

    # per-family results + decision matrix
    per_class = {}
    for c in ATTACKS:
        mk = lab == c
        per_class[c] = {"minutes": int(mk.sum()), "alert_recall": float(p["alert"][mk].mean()) if mk.any() else None,
                        "typed_correctly": float((p["label"][mk] == c).mean()) if mk.any() else None}
    rows = ["normal"] + ATTACKS
    cols = ["normal"] + ATTACKS + ["unknown_anomaly"]
    cm = np.zeros((len(rows), len(cols)), int)
    for t_, d_ in zip(lab, p["label"].to_numpy()):
        cm[rows.index(t_), cols.index(d_)] += 1

    # incident-level (what a SOC analyst feels): detection + time-to-detect + false incidents
    eps = episodes(lab)
    alert = p["alert"].to_numpy()
    ttd, found = [], 0
    for s, e, _ in eps:
        hit = np.where(alert[s:e + 3])[0]
        if len(hit):
            found += 1
            ttd.append(int(hit[0]))
    incs = build_incidents(res)
    false_inc = sum(1 for i in incs if not y[(test["minute"] >= i["start"]) & (test["minute"] <= i["end"])].any())

    # latency / size
    day = test.iloc[:1440]
    t1 = time.perf_counter()
    for _ in range(5):
        model.analyze(day)
    ms = (time.perf_counter() - t1) / 5 / 1440 * 1000
    size_kb = (out / "aegisnet_model.npz").stat().st_size / 1024

    print("[4/7] zero-day experiment (ransomware hidden from the classifier) ...")
    known = [a for a in ATTACKS if a != ZERO_DAY]
    lab_zd = simulate(days * 1440, seed=2, attacks=known)
    mz = AegisNet().fit(normal, lab_zd, known=known, epochs_ae=ea, epochs_clf=ec)
    rz = mz.analyze(test).pred
    zm = lab == ZERO_DAY
    zero = {"Classifier only": float(rz["clf_flag"][zm].mean()), "Autoencoder only": float(rz["ae_flag"][zm].mean()),
            "AegisNet fused": float(rz["raw_alert"][zm].mean()),
            "AegisNet flagged as NEW pattern": float((rz["label"][zm] == "unknown_anomaly").mean())}
    zero["Mislabelled as a known attack"] = float(rz["label"][zm].isin(known).mean())

    print("[5/7] drift test ...")
    wd = DriftWatchdog(normal)
    stable = wd.check(simulate(2 * 1440, seed=11, attacks=(), flash=True, start_minute=0))
    drifted = wd.check(simulate(2 * 1440, seed=12, attacks=(), flash=True, drift={"net_in_mbps": 1.6, "connections": 1.5}))

    print("[6/7] incident reports + figures ...")
    guard = Guardian()
    samples, chosen = [], {}
    for inc in sorted(incs, key=lambda i: -i["peak_risk"]):
        if inc["type"] not in chosen and inc["type"] in ("ddos", "ransomware", "exfiltration", "unknown_anomaly", "brute_force"):
            chosen[inc["type"]] = inc
    for inc in chosen.values():
        t = guard.triage(inc)
        samples.append(t["narrative"] + "\nAUTO-EXECUTED : " + " | ".join(t["auto_executed"]) +
                       "\nNEEDS HUMAN OK : " + " | ".join(t["awaiting_human_approval"]))
    (out / "sample_incidents.txt").write_text("\n\n".join(samples), encoding="utf-8")
    pick = [(k.upper(), chosen[k]) for k in ("ddos", "ransomware") if k in chosen][:2] or [("INCIDENT", incs[0])]
    report.fig_training(model, fig / "training.png")
    report.fig_roc(curves, fig / "roc.png")
    report.fig_confusion(cm, rows, cols, fig / "confusion.png")
    report.fig_timeline(test, p, fig / "timeline.png")
    report.fig_explain(pick, fig / "explain.png")
    report.fig_zeroday(zero, fig / "zeroday.png")
    report.fig_drift(stable, drifted, fig / "drift.png")

    headline = {"ROC-AUC (fused)": f'{aucs["AegisNet fused risk"]:.3f}', "Attack recall": f'{m_alert["recall"]*100:.1f}%',
                "False-alarm rate": f'{m_alert["fpr"]*100:.2f}%', "Attacks found": f"{found}/{len(eps)}",
                "Mean time-to-detect": f"{np.mean(ttd):.1f} min" if ttd else "n/a",
                "Model size": f"{size_kb:.0f} KB", "Latency": f"{ms:.3f} ms/min", "Parameters": f"{model.n_params():,}"}
    results = {"headline": headline, "auc": aucs, "raw_alert": m_raw, "smoothed_alert": m_alert, "per_class": per_class,
               "incidents": {"true_attacks": len(eps), "detected": found, "mean_ttd_min": float(np.mean(ttd)) if ttd else None,
                             "max_ttd_min": max(ttd) if ttd else None, "predicted_incidents": len(incs), "false_incidents": false_inc},
               "zero_day": zero, "drift": {"stable": stable["status"], "stable_worst_psi": stable["worst_psi"],
                                           "drifted": drifted["status"], "drifted_worst_psi": drifted["worst_psi"],
                                           "drifted_worst_feature": drifted["worst_feature"]},
               "perf": {"ms_per_window": ms, "model_kb": size_kb, "params": model.n_params(),
                        "ae_params": model.ae.n_params(), "clf_params": model.clf.n_params()},
               "data": {"train_normal_min": len(normal), "train_labeled_min": len(labeled), "test_min": len(test),
                        "test_attack_min": int(y.sum()), "test_episodes": len(eps)},
               "confusion": {"rows": rows, "cols": cols, "matrix": cm.tolist()}, "quick": quick}
    (out / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print("[7/7] building HTML report ...")
    report.build_html(results, str(fig), samples, out / "report.html")
    print(f"\nDONE in {time.time() - t0:.0f}s  ->  open outputs/report.html")
    for k, v in headline.items():
        print(f"  {k:22s} {v}")
    return results


if __name__ == "__main__":
    main(quick="--quick" in sys.argv)
