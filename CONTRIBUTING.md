# Contributing to AegisNet

Thanks for your interest! Small, focused contributions are the easiest to review.

## Set up
```bash
git clone https://github.com/AnyalstRushi/aegisnet-edge-ai.git
cd aegisnet-edge-ai
pip install -r requirements.txt
python -m unittest discover -s tests -v     # all 12 tests must pass
```

## Guidelines
- Open an issue first for large changes.
- Keep the core engine dependency-light (NumPy and pandas only inside `aegisnet/`).
- Add or update a test for every behaviour change.
- Be honest in documentation: say clearly whether a result comes from simulated or real data.

## Pull requests
Fork, create a branch, make the change, run the tests, then open a pull request using the template.
