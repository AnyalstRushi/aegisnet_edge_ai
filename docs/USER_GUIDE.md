# User guide (step by step)

> Just want to see it work? Open the **[live lab](https://anyalstrushi.github.io/aegisnet-edge-ai/)**; it needs no installation.

This guide assumes you have never used Python projects before. Windows is shown first; macOS and Linux notes are at the end.

## 1. Install Python (one time)

1. Go to <https://www.python.org/downloads> and install the latest Python 3.
2. On the first installer screen tick **"Add python.exe to PATH"**. This is the most important click.
3. Open Command Prompt (Start menu, type `cmd`) and check:
   ```
   python --version
   ```
   You should see `Python 3.x.x`.

## 2. Get the project

**Option A, with Git:**
```
git clone https://github.com/AnyalstRushi/aegisnet-edge-ai.git
cd aegisnet-edge-ai
```
**Option B, without Git:** on the GitHub page click the green **Code** button, then **Download ZIP**, right-click the ZIP, **Extract All**, and open the extracted folder. Click the folder's address bar, type `cmd` and press Enter. A black window opens in the right folder.

## 3. Install the libraries

```
pip install -r requirements.txt
```
This downloads NumPy, pandas, Matplotlib, scikit-learn and Flask (all free). It can take 1 to 2 minutes.

## 4. Run the whole project

```
python run_all.py
```
After about 15 seconds you should see:
```
ROC-AUC (fused)        0.995
Attack recall          98.5%
False-alarm rate       0.98%
Attacks found          37/37
```
Now open the folder `outputs` and double-click **`report.html`**. It shows all charts, the metrics and the incident reports in your browser.

## 5. Run the tests

```
python -m unittest discover -s tests -v
```
At the end you should see `Ran 12 tests` and `OK`. That means everything works.

## 6. Try the live API (optional)

Terminal 1:
```
python api.py
```
The very first start trains the model once (about 5 seconds). Leave it running. Open a second Command Prompt in the same folder:
```
curl.exe -X POST http://127.0.0.1:5000/predict -H "Content-Type: application/json" -d @sample_request.json
```
The answer contains `"alert":true` and `"label":"ddos"`, plus the explanation and the Guardian plan. Press `Ctrl+C` in the first window to stop the server.

## 7. What each output means

| Output | Meaning |
|---|---|
| `risk` (0 to 100) | How suspicious this minute is. Above 50 is an alert level. |
| `label` | `normal`, a named attack (for example `ddos`), or `unknown_anomaly` (a pattern the model has never seen) |
| `WHY` line | The metrics that caused the alert, with observed and model-expected values |
| `AUTO-EXECUTED` | Safe actions the Guardian ran by itself |
| `NEEDS HUMAN OK` | Risky actions waiting for a person to approve |

## 8. Troubleshooting

| Problem | Fix |
|---|---|
| `'python' is not recognized` | Reinstall Python and tick "Add python.exe to PATH". Or try `py` instead of `python`. |
| `'pip' is not recognized` | Use `python -m pip install -r requirements.txt` |
| Permission error during install | Use `pip install --user -r requirements.txt` |
| Port 5000 already in use | Close the other program, or edit the port in the last line of `api.py` |

**macOS and Linux:** use `python3` instead of `python` and `pip3` instead of `pip`; use `curl` instead of `curl.exe`.

## 9. Quick smoke run

`python run_all.py --quick` runs a smaller version in about 3 seconds. Its numbers are lower than the full run, which is normal.
