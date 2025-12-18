# bitirme_anomali_tespit

This repository contains a thesis project for anomaly detection. It includes a Python server, a React security dashboard frontend in the `security-dashboard` folder, and supporting files.

How to use:
- Python backend: `python server.py`
- Frontend: `cd security-dashboard && npm install && npm start`

To create and push this repo to GitHub, use the PowerShell script `create_github_repo.ps1` or GitHub CLI as described below.

# Machine Learning
We've used two machine learning models: One of them is RandomForest and the other one is XGBoost algorithm. First, we identify the package whether it is benign or anomaly with Random Forest model
If there is an anomaly situation, then our second model takes turn and identifies what kind of anomaly does the package have.
