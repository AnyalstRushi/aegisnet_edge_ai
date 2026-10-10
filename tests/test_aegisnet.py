"""Run:  python -m unittest discover -s tests -v      (takes ~30-40 s)"""
import os, sys, tempfile, time, unittest
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sklearn.metrics import roc_auc_score
from aegisnet.nn import MLP
from aegisnet.data import simulate, build_features, FEATURES, ATTACKS
from aegisnet.models import AegisNet
from aegisnet.explain import build_incidents, Guardian, DriftWatchdog


class TestNeuralEngine(unittest.TestCase):
    def test_gradient_check(self):
        """Backprop must match numerical gradients (proves the from-scratch maths is right)."""
        rng = np.random.default_rng(0)
        for loss in ("mse", "ce"):
            net = MLP([5, 7, 4, 3], ["tanh", "tanh", "linear"], loss, seed=1)
            X = rng.normal(size=(12, 5)); Y = X[:, :3] if loss == "mse" else rng.integers(0, 3, 12)
            if loss == "mse":
                net = MLP([5, 7, 4, 3], ["tanh", "tanh", "linear"], loss, seed=1)
            net.loss_and_grad(X, Y)
            for layer in net.layers:
                for name in ("W", "b"):
                    P, G = getattr(layer, name), getattr(layer, "d" + name)
                    for _ in range(4):
                        idx = tuple(rng.integers(0, s) for s in P.shape)
                        old = P[idx]; eps = 1e-6
                        P[idx] = old + eps; lp = net.loss_and_grad(X, Y)
                        P[idx] = old - eps; lm = net.loss_and_grad(X, Y)
                        P[idx] = old; net.loss_and_grad(X, Y)
                        self.assertAlmostEqual(G[idx], (lp - lm) / (2 * eps), places=5)

    def test_learns_xor(self):
        X = np.array([[0, 0], [0, 1], [1, 0], [1, 1]] * 64, float); y = (X[:, 0] != X[:, 1]).astype(int)
        net = MLP([2, 8, 2], ["tanh", "linear"], "ce", seed=3)
        net.fit(X, y, epochs=150, batch=32, lr=1e-2)
        self.assertGreater((net.proba(X).argmax(1) == y).mean(), 0.99)


class TestData(unittest.TestCase):
    def test_simulator(self):
        a, b = simulate(3000, seed=5), simulate(3000, seed=5)
        self.assertTrue(a.equals(b))                                   # deterministic
        self.assertEqual(list(a.columns), ["minute"] + FEATURES + ["label"])
        self.assertTrue((a[FEATURES] >= 0).all().all())
        self.assertTrue(set(a.label) <= set(ATTACKS) | {"normal"})
        self.assertEqual(build_features(a).shape, (3000, 26))
        self.assertFalse(np.isnan(build_features(a)).any())


class TestPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.normal = simulate(8 * 1440, seed=1, attacks=(), flash=True)
        cls.labeled = simulate(8 * 1440, seed=2)
        cls.test = simulate(4 * 1440, seed=3, start_minute=30 * 1440)
        cls.model = AegisNet().fit(cls.normal, cls.labeled, epochs_ae=25, epochs_clf=20)
        cls.res = cls.model.analyze(cls.test)
        cls.y = (cls.test.label != "normal").to_numpy()

    def test_detection_quality(self):
        p = self.res.pred
        self.assertGreater(roc_auc_score(self.y, p.risk), 0.97)
        rec = (p.alert.to_numpy() & self.y).sum() / self.y.sum()
        fpr = (p.alert.to_numpy() & ~self.y).sum() / (~self.y).sum()
        self.assertGreater(rec, 0.90); self.assertLess(fpr, 0.03)

    def test_every_attack_family_is_detected(self):
        p, lab = self.res.pred, self.test.label.to_numpy()
        for c in ATTACKS:
            if (lab == c).sum() >= 10:
                self.assertGreater(p.alert[lab == c].mean(), 0.8, c)

    def test_save_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "m.npz"); self.model.save(path)
            m2 = AegisNet.load(path)
            a, b = self.res.pred, m2.predict(self.test)
            np.testing.assert_allclose(a.risk, b.risk); self.assertTrue((a.label == b.label).all())

    def test_explanation_points_to_right_metric(self):
        incs = build_incidents(self.res)
        self.assertGreater(len(incs), 0)
        expect = {"ddos": {"http_5xx_pct", "connections", "net_in_mbps", "avg_pkt_bytes", "cpu_pct"},
                  "brute_force": {"failed_logins", "connections"}, "port_scan": {"unique_dst_ports", "avg_pkt_bytes", "connections"},
                  "ransomware": {"file_writes", "disk_io_mbps"}, "exfiltration": {"dns_queries", "net_out_mbps", "disk_io_mbps"},
                  "cryptominer": {"cpu_pct", "processes", "mem_pct"}}
        checked = 0
        for inc in incs:
            if inc["type"] in expect:
                checked += 1
                self.assertIn(inc["why"][0]["feature"], expect[inc["type"]], inc["type"])
        self.assertGreater(checked, 0)

    def test_guardian_needs_human_for_risky_actions(self):
        inc = {"type": "ransomware", "start": 1, "end": 5, "duration": 5, "peak_risk": 99, "why": []}
        g = Guardian(); t = g.triage(inc)
        self.assertTrue(any("Isolate" in a for a in t["awaiting_human_approval"]))
        self.assertFalse(any("Isolate" in a for a in t["auto_executed"]))
        t2 = g.triage(inc, approved=True)
        self.assertEqual(t2["awaiting_human_approval"], [])
        self.assertTrue(any(a["by"] == "human-approved" for a in g.audit))

    def test_zero_day_is_caught_by_autoencoder(self):
        known = [a for a in ATTACKS if a != "ransomware"]
        m = AegisNet().fit(self.normal, simulate(8 * 1440, seed=2, attacks=known), known=known, epochs_ae=25, epochs_clf=20)
        r = m.analyze(self.test).pred; zm = (self.test.label == "ransomware").to_numpy()
        self.assertGreater(zm.sum(), 5)
        self.assertGreater(r.ae_flag[zm].mean(), 0.9)
        self.assertEqual(r.label[zm & r.alert.to_numpy()].isin(known).sum(), 0)    # never mislabelled

    def test_drift_watchdog(self):
        wd = DriftWatchdog(self.normal)
        self.assertEqual(wd.check(simulate(2 * 1440, seed=11, attacks=(), flash=True))["status"], "STABLE")
        d = wd.check(simulate(2 * 1440, seed=12, attacks=(), flash=True, drift={"net_in_mbps": 1.6}))
        self.assertTrue(d["status"].startswith("DRIFT")); self.assertEqual(d["worst_feature"], "net_in_mbps")

    def test_edge_speed(self):
        day = self.test.iloc[:1440]; t = time.perf_counter(); self.model.analyze(day)
        self.assertLess((time.perf_counter() - t) / 1440 * 1000, 1.0)              # < 1 ms per minute-window

    def test_rest_api(self):
        from api import create_app
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "m.npz"); self.model.save(path)
            c = create_app(path).test_client()
            self.assertEqual(c.get("/health").get_json()["status"], "ok")
            self.assertEqual(c.post("/predict", json={}).status_code, 400)
            self.assertEqual(c.post("/predict", json={"windows": [{"cpu_pct": 1}]}).status_code, 400)
            ddos = self.test[self.test.label == "ddos"]
            if len(ddos):
                i = ddos.index[8]; w = self.test.loc[i - 8:i, FEATURES].to_dict("records")
                out = c.post("/predict", json={"windows": w}).get_json()
                self.assertTrue(out["latest"]["alert"]); self.assertIn("incident", out)
            calm = self.test[self.test.label == "normal"].iloc[200:210][FEATURES].to_dict("records")
            self.assertFalse(c.post("/predict", json={"windows": calm}).get_json()["latest"]["alert"])


if __name__ == "__main__":
    unittest.main()
