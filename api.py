"""REST API (Flask): send the last few minutes of server metrics, get risk score + explanation + Guardian plan.
Run:  python api.py      then POST http://127.0.0.1:5000/predict   (see README for a curl example)"""
import os
import pandas as pd
from flask import Flask, jsonify, request
from aegisnet.models import AegisNet
from aegisnet.data import FEATURES
from aegisnet.explain import build_incidents, Guardian


def _default_model():
    for p in ("outputs/aegisnet_model.npz", "models/aegisnet_model.npz"):   # model from run_all.py first, auto-trained one second
        if os.path.exists(p):
            return p
    # first run after cloning: train once (about 5 s) so `python api.py` works immediately
    from aegisnet.data import simulate
    os.makedirs("models", exist_ok=True)
    m = AegisNet().fit(simulate(20 * 1440, seed=1, attacks=(), flash=True), simulate(20 * 1440, seed=2))
    m.save("models/aegisnet_model.npz")
    return "models/aegisnet_model.npz"


def create_app(model_path=None):
    model_path = model_path or _default_model()
    app = Flask(__name__)
    model, guard = AegisNet.load(model_path), Guardian()

    @app.get("/health")
    def health():
        return jsonify(status="ok", parameters=model.n_params(), classes=model.classes)

    @app.post("/predict")
    def predict():
        body = request.get_json(silent=True) or {}
        rows = body.get("windows")
        if not isinstance(rows, list) or not rows:
            return jsonify(error="send JSON like {'windows': [ {metric: value, ...}, ... ]} (oldest first, >=6 recommended)"), 400
        try:
            df = pd.DataFrame(rows)
            miss = [f for f in FEATURES if f not in df.columns]
            if miss:
                return jsonify(error=f"missing metrics: {miss}"), 400
            df = df[FEATURES].astype(float)
        except (ValueError, TypeError):
            return jsonify(error="all metric values must be numbers"), 400
        df.insert(0, "minute", range(len(df)))
        res = model.analyze(df)
        last = res.pred.iloc[-1]
        out = {"windows": len(df), "latest": {"risk": round(float(last["risk"]), 1), "alert": bool(last["alert"]),
                                              "label": str(last["label"])}}
        if last["alert"]:
            inc = build_incidents(res)[-1]
            out["incident"] = guard.triage(inc)
        return jsonify(out)

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000)
