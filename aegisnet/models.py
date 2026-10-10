"""AegisNet = Dual-Brain detector.
Brain 1  Autoencoder (trained on NORMAL data only)  -> catches unknown / zero-day behaviour.
Brain 2  MLP classifier (trained on labelled attacks) -> names known attack families.
Fusion   risk score 0-100 + 2-of-3 persistence + 'signature consistency' check that sends
         never-seen patterns to `unknown_anomaly` instead of mislabelling them."""
import json
import numpy as np
import pandas as pd
from .nn import MLP
from .data import FEATURES, ATTACKS, build_features


class Result:
    """Everything produced by analyze(): predictions + per-feature explanation data."""
    def __init__(self, pred, share, expected, observed):
        self.pred, self.share, self.expected, self.observed = pred, share, expected, observed


class AegisNet:
    def __init__(self, seed=7, ae_hidden=18, ae_code=6):
        self.seed, self.h, self.c = seed, ae_hidden, ae_code

    # ---------------------------------------------------------------- helpers
    def _std(self, Z):
        return np.clip((Z - self.mu) / self.sd, -20, 20)

    def _share(self, X, R):
        """Share of reconstruction error contributed by each of the 13 metrics (level + change)."""
        e2 = (X - R) ** 2
        d = X.shape[1] // 2
        a = e2[:, :d] + e2[:, d:]
        return a / (a.sum(1, keepdims=True) + 1e-12)

    @staticmethod
    def _cos(a, b):
        return (a * b).sum(1) / (np.linalg.norm(a, axis=1) * np.linalg.norm(b, axis=1) + 1e-12)

    def n_params(self):
        return self.ae.n_params() + self.clf.n_params()

    # ---------------------------------------------------------------- training
    def fit(self, normal_df, labeled_df, known=tuple(ATTACKS), epochs_ae=60, epochs_clf=40):
        Zn = build_features(normal_df)
        self.mu, self.sd = Zn.mean(0), Zn.std(0) + 1e-6
        Xn = self._std(Zn)
        rng = np.random.default_rng(self.seed)
        idx = rng.permutation(len(Xn))
        k = int(0.85 * len(Xn))
        tr, va = Xn[idx[:k]], Xn[idx[k:]]
        d = Xn.shape[1]
        # ---- Brain 1: autoencoder  26 -> 18 -> 6 -> 18 -> 26
        self.ae = MLP([d, self.h, self.c, self.h, d], ["tanh", "tanh", "tanh", "linear"], "mse", self.seed)
        self.hist_ae = self.ae.fit(tr, tr, epochs=epochs_ae, X_val=va, Y_val=va, lr=3e-3, seed=self.seed)
        err_va = np.mean((va - self.ae.forward(va)) ** 2, axis=1)
        self.thr = float(np.quantile(err_va, 0.995))      # target false-alarm rate ~0.5 % on normal data
        # ---- Brain 2: classifier  26 -> 48 -> 24 -> K
        self.classes = ["normal"] + list(known)
        Xl = self._std(build_features(labeled_df))
        lab = labeled_df["label"].to_numpy()
        keep = np.isin(lab, self.classes)
        X = Xl[keep]
        y = np.array([self.classes.index(l) for l in lab[keep]])
        cnt = np.bincount(y, minlength=len(self.classes))
        cw = (len(y) / (len(self.classes) * np.maximum(cnt, 1))) ** 0.5
        p = rng.permutation(len(X))
        kk = int(0.85 * len(X))
        self.clf = MLP([d, 48, 24, len(self.classes)], ["relu", "relu", "linear"], "ce", self.seed + 1)
        self.hist_clf = self.clf.fit(X[p[:kk]], y[p[:kk]], epochs=epochs_clf, class_w=cw, lr=3e-3,
                                     X_val=X[p[kk:]], Y_val=y[p[kk:]], seed=self.seed)
        # ---- error-signature prototypes (used to spot never-seen attack patterns)
        R = self.ae.forward(X)
        sc = np.mean((X - R) ** 2, axis=1) / self.thr
        sh = self._share(X, R)
        self.proto = np.zeros((len(known), len(FEATURES)))
        self.sig_thr = np.full(len(known), 0.5)
        for j in range(len(known)):
            m = (y == j + 1) & (sc > 1.0)
            if m.sum() < 5:
                self.proto[j] = 1.0 / len(FEATURES)
                continue
            self.proto[j] = sh[m].mean(0)
            cos = self._cos(sh[m], np.tile(self.proto[j], (m.sum(), 1)))
            self.sig_thr[j] = max(0.5, float(np.quantile(cos, 0.05)))
        return self

    # ---------------------------------------------------------------- inference
    def analyze(self, df):
        Z = build_features(df)
        X = self._std(Z)
        R = self.ae.forward(X)
        score = np.mean((X - R) ** 2, axis=1) / self.thr          # >1 means "unusual"
        P = self.clf.proba(X)
        p_att = 1.0 - P[:, 0]
        share = self._share(X, R)
        att_idx = P[:, 1:].argmax(1)                              # most likely attack family
        cos = self._cos(share, self.proto[att_idx])
        ae_flag, clf_flag = score > 1.0, p_att > 0.5
        raw = ae_flag | clf_flag
        risk = np.clip(np.maximum(100 / (1 + np.exp(-3 * (score - 1))), 100 * p_att), 0, 100)
        roll = pd.Series(raw.astype(int)).rolling(3, min_periods=1).sum().to_numpy()
        alert = raw & ((roll >= 2) | (risk >= 90))
        label = np.full(len(df), "normal", dtype=object)
        for i in np.where(alert)[0]:
            j = att_idx[i]
            sure = clf_flag[i] and ((ae_flag[i] and cos[i] >= self.sig_thr[j]) or (not ae_flag[i] and p_att[i] > 0.9))
            label[i] = self.classes[j + 1] if sure else "unknown_anomaly"
        pred = pd.DataFrame({"minute": df["minute"].to_numpy(), "ae_score": score, "p_attack": p_att,
                             "risk": risk, "raw_alert": raw, "alert": alert, "label": label,
                             "ae_flag": ae_flag, "clf_flag": clf_flag})
        expected = np.expm1(R[:, :len(FEATURES)] * self.sd[:len(FEATURES)] + self.mu[:len(FEATURES)])
        return Result(pred, share, expected, df[FEATURES].to_numpy(float))

    def predict(self, df):
        return self.analyze(df).pred

    # ---------------------------------------------------------------- persistence
    def save(self, path):
        meta = dict(seed=self.seed, h=self.h, c=self.c, classes=self.classes, thr=self.thr,
                    ae=self.ae.sizes, clf=self.clf.sizes)
        arr = {f"ae_{i}": a for i, a in enumerate(self.ae.get_params())}
        arr.update({f"clf_{i}": a for i, a in enumerate(self.clf.get_params())})
        np.savez_compressed(path, mu=self.mu, sd=self.sd, proto=self.proto, sig_thr=self.sig_thr,
                            meta=json.dumps(meta), **arr)

    @classmethod
    def load(cls, path):
        z = np.load(path, allow_pickle=False)
        meta = json.loads(str(z["meta"]))
        m = cls(meta["seed"], meta["h"], meta["c"])
        m.mu, m.sd, m.proto, m.sig_thr = z["mu"], z["sd"], z["proto"], z["sig_thr"]
        m.classes, m.thr = meta["classes"], meta["thr"]
        m.ae = MLP(meta["ae"], ["tanh", "tanh", "tanh", "linear"], "mse")
        m.clf = MLP(meta["clf"], ["relu", "relu", "linear"], "ce")
        m.ae.set_params([z[f"ae_{i}"] for i in range(2 * len(m.ae.layers))])
        m.clf.set_params([z[f"clf_{i}"] for i in range(2 * len(m.clf.layers))])
        return m
