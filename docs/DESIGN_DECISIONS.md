# Design decisions

Every choice below has a reason and a cost. Numbers come from `docs/results.json` (reproduced by `python run_all.py`).

## 1. A neural network engine from scratch in NumPy
**Why:** every step (forward pass, back-propagation, Adam) can be explained, tested and shipped without a heavy framework, and the model stays tiny.
**Cost:** no GPU, no automatic differentiation, so the architectures stay small. Correctness is protected by a numerical gradient check in the tests.

## 2. Two brains instead of one
A supervised classifier is excellent on attacks it has seen and blind to ones it has not. An autoencoder trained on normal data flags anything unusual but cannot name it. AegisNet uses both.
**Evidence:** in the zero-day experiment the classifier alone flagged 0% of unseen ransomware, while the autoencoder flagged 100%.
**Cost:** on known attacks the classifier alone ranks slightly better (ROC-AUC 0.9999 vs 0.995 fused).

## 3. The alert budget: the 99.5th percentile of validation error
The autoencoder threshold is the 99.5th percentile of reconstruction error on held-out normal data, which targets about 0.5% false alarms on normal behaviour.
**Cost:** weak attacks that look like normal bursts (for example a faint cryptominer) can slip under it. The percentile is a dial, not a law.

## 4. Features: log scale plus change versus the last five minutes
Log scaling tames heavy-tailed metrics; the change feature highlights the sudden jumps that open most attacks. Together they give 26 inputs from 13 metrics.

## 5. Persistence: two of the last three minutes, or risk of at least 90
**Measured effect:** false-alarm rate 1.33% to 0.98%, precision 78.7% to 83.3%, recall 99.0% to 98.5%.
**Cost:** a one-minute blip is never alerted unless it is extreme, and a real attack is confirmed about a minute later at worst (maximum time-to-detect measured: 1 minute).

## 6. A signature check instead of trusting classifier confidence
A softmax classifier is often confidently wrong on inputs unlike its training data. So a suggested attack name is accepted only if the autoencoder's per-metric error pattern resembles that attack's learned signature (cosine similarity above a threshold calibrated on training data). Otherwise the alert becomes `unknown_anomaly`.
**Evidence:** unseen ransomware was labelled `unknown_anomaly` 100% of the time and mislabelled as a known attack 0% of the time.
**Cost:** some genuine known attacks are also sent to `unknown_anomaly` (for example about a quarter of port-scan minutes). They are still alerted, only not named.

## 7. Benign flash crowds in the data
A traffic surge from a popular launch looks like a DDoS but is harmless. Including such events (labelled normal) makes the false-alarm number meaningful instead of flattering.

## 8. Bounded autonomy for the Guardian
Safe actions (snapshots, tickets, paging) run automatically; high-impact actions (blocking, isolating, quarantining) wait for a human, and everything is audit-logged. This mirrors the 2026 consensus that agents should act within limits with a human in the loop.
**Cost:** slower containment for the actions that need approval. That is the point.

## 9. Simulated data
Simulation makes the project offline, reproducible, fully labelled and free. **Cost:** the attack signatures are cleaner than real traffic, which is why the classifier reaches an AUC near 1.0. Real-world numbers will be lower; validating on CICIDS2017 or production logs is the first item on the roadmap.

## 10. The browser lab is deliberately lighter
`docs/lab.js` re-implements the simulator, the autoencoder and the signature naming in plain JavaScript so anyone can try the idea with one click. It omits the supervised classifier, so it catches roughly 85-88% of attack minutes (measured on unseen simulated days), against 98.5% for the full Python system. Its self-check panel reports its own numbers live, so nothing is hidden.

## What did not work as well as hoped
- **Port-scan naming:** 72.9% named correctly, the weakest family.
- **Weak cryptominers:** the autoencoder alone often misses faint ones; the classifier in the Python project recovers most of them.
- **Explanations are model-based:** the "expected" value is the autoencoder's reconstruction, which is pulled toward large anomalies, so it is a hint rather than a ground-truth baseline.
