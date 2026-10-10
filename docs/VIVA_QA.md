# Viva and interview questions with short answers

**1. What is this project in one sentence?**
A tiny neural network (34 KB, written from scratch in NumPy) that detects known and unknown cyber-attacks from server metrics, explains why, and asks a human before risky actions.

**2. Why write the network from scratch?**
It makes every step explainable and testable, needs no heavy framework, and keeps the model small enough for edge devices. A gradient-check test proves the back-propagation is correct.

**3. Why two neural networks?**
The autoencoder learns only normal behaviour, so it catches anything unusual, including attacks it never saw. The classifier learns labelled attacks, so it can name known ones. Fusing them gives both coverage and names.

**4. What exactly is an autoencoder?**
A network that compresses its input to a small code (6 numbers here) and rebuilds it. Trained on normal data only, it rebuilds normal data well and abnormal data badly, so a large reconstruction error signals an anomaly.

**5. What happens when a completely new attack appears?**
The autoencoder flags it. The signature check sees that the error pattern matches no known attack and labels it `unknown_anomaly` instead of guessing a wrong name. In the experiment, unseen ransomware was caught 100% and mislabelled 0%.

**6. Why is the classifier's AUC higher than the fused system?**
On attacks it has seen, a supervised model is very strong, and the simulated attacks are clean. Fusion adds the autoencoder so unseen attacks are still caught, at the cost of a little ranking quality.

**7. Why the 99.5th percentile threshold?**
It targets about 0.5% false alarms on normal validation data. It is a tunable alert budget: higher means fewer false alarms but more missed weak attacks.

**8. What is PSI and why use it?**
The Population Stability Index measures how far live data has moved from the training data. Above 0.25 is treated as significant drift, which is the signal to retrain. It addresses the 2026 gap between adopting AI and running it reliably in production.

**9. Why log transform and change features?**
Log scaling tames heavy-tailed metrics such as connections. Change features highlight sudden jumps, which is how most attacks begin.

**10. What does "bounded autonomy" mean?**
The agent may run low-risk actions on its own. High-impact actions (blocking IPs, isolating hosts) need a human approval, and every action is audit-logged.

**11. Is the data real? Is 98.5% realistic?**
No, the data is simulated so the project is offline, reproducible and fully labelled. Real traffic is messier, so real-world numbers will be lower. Testing on CICIDS2017 or production logs is the next step. Being upfront about this is a strength.

**12. How does this connect to current AI trends?**
It follows the 2026 shift toward small task-specific models, agents with human oversight, explainability, and monitoring to close the gap between adopting AI and running it in production.

**13. How would you improve it?**
Real datasets, a local LLM to write incident stories, real firewall integrations, ONNX export for edge devices, and federated training across servers.
